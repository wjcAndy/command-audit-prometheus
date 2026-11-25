package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type eventMetricKey struct {
	Host, User, Command, Result string
}

type dangerMetricKey struct {
	Host, User, Command, Rule, Severity string
}

type suppressedMetricKey struct {
	Host, Reason string
}

type MetricStore struct {
	sync.Mutex
	MaxUsers    int
	MaxCommands int
	Events      map[eventMetricKey]int64
	Danger      map[dangerMetricKey]int64
	LastEvent   map[string]float64
	LastSeen    map[string]time.Time
	Dropped     map[string]int64
	ParseErrors map[string]int64
	Suppressed  map[suppressedMetricKey]int64
	Users       map[string]bool
	Commands    map[string]bool
}

func NewMetricStore(maxUsers, maxCommands int) *MetricStore {
	return &MetricStore{
		MaxUsers: maxUsers, MaxCommands: maxCommands,
		Events: make(map[eventMetricKey]int64), Danger: make(map[dangerMetricKey]int64),
		LastEvent: make(map[string]float64), LastSeen: make(map[string]time.Time),
		Dropped: make(map[string]int64), ParseErrors: make(map[string]int64), Suppressed: make(map[suppressedMetricKey]int64),
		Users: map[string]bool{"__other__": true}, Commands: map[string]bool{"__other__": true},
	}
}

func boundedLabel(value string, values map[string]bool, limit int) string {
	if value == "" {
		value = "unknown"
	}
	if len(value) > 128 {
		value = value[:128]
	}
	if values[value] {
		return value
	}
	if len(values) >= limit {
		return "__other__"
	}
	values[value] = true
	return value
}

func (m *MetricStore) Observe(event *Event, seenAt time.Time) {
	m.Lock()
	defer m.Unlock()
	user := boundedLabel(event.User, m.Users, m.MaxUsers)
	command := boundedLabel(event.Command, m.Commands, m.MaxCommands)
	result := "failed"
	if event.Success {
		result = "success"
	}
	m.Events[eventMetricKey{event.Hostname, user, command, result}]++
	for _, match := range event.Danger {
		m.Danger[dangerMetricKey{event.Hostname, user, command, match.Rule, match.Severity}]++
	}
	if event.Timestamp > m.LastEvent[event.Hostname] {
		m.LastEvent[event.Hostname] = event.Timestamp
	}
	m.LastSeen[event.Hostname] = seenAt
}

func (m *MetricStore) Touch(host string) {
	m.Lock()
	m.LastSeen[host] = time.Now()
	m.Unlock()
}

func (m *MetricStore) Drop(host string, count int64) {
	m.Lock()
	m.Dropped[host] += count
	m.Unlock()
}

func (m *MetricStore) ParseError(host string, count int64) {
	m.Lock()
	m.ParseErrors[host] += count
	m.Unlock()
}

func (m *MetricStore) Suppress(host, reason string) {
	m.Lock()
	m.Suppressed[suppressedMetricKey{host, reason}]++
	m.Unlock()
}

func labelEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func labels(pairs ...string) string {
	if len(pairs) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteByte('{')
	for index := 0; index < len(pairs); index += 2 {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(pairs[index])
		builder.WriteString("=\"")
		builder.WriteString(labelEscape(pairs[index+1]))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func number(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func (m *MetricStore) Render(localAgent string) string {
	m.Lock()
	defer m.Unlock()
	now := time.Now()
	if localAgent != "" {
		m.LastSeen[localAgent] = now
	}
	hosts := make(map[string]bool)
	for host := range m.LastSeen {
		hosts[host] = true
	}
	for host := range m.LastEvent {
		hosts[host] = true
	}
	for host := range m.Dropped {
		hosts[host] = true
	}
	for host := range m.ParseErrors {
		hosts[host] = true
	}
	for key := range m.Suppressed {
		hosts[key.Host] = true
	}
	var sortedHosts []string
	for host := range hosts {
		sortedHosts = append(sortedHosts, host)
	}
	sort.Strings(sortedHosts)
	var out strings.Builder
	out.WriteString("# HELP command_audit_events_total Executed commands observed by auditd.\n# TYPE command_audit_events_total counter\n")
	var eventKeys []eventMetricKey
	for key := range m.Events {
		eventKeys = append(eventKeys, key)
	}
	sort.Slice(eventKeys, func(i, j int) bool { return fmt.Sprint(eventKeys[i]) < fmt.Sprint(eventKeys[j]) })
	for _, key := range eventKeys {
		fmt.Fprintf(&out, "command_audit_events_total%s %d\n", labels("hostname", key.Host, "user", key.User, "command", key.Command, "result", key.Result), m.Events[key])
	}
	out.WriteString("# HELP command_audit_dangerous_events_total Commands matching dangerous-command rules.\n# TYPE command_audit_dangerous_events_total counter\n")
	var dangerKeys []dangerMetricKey
	for key := range m.Danger {
		dangerKeys = append(dangerKeys, key)
	}
	sort.Slice(dangerKeys, func(i, j int) bool { return fmt.Sprint(dangerKeys[i]) < fmt.Sprint(dangerKeys[j]) })
	for _, key := range dangerKeys {
		fmt.Fprintf(&out, "command_audit_dangerous_events_total%s %d\n", labels("hostname", key.Host, "user", key.User, "command", key.Command, "rule", key.Rule, "severity", key.Severity), m.Danger[key])
	}
	out.WriteString("# HELP command_audit_last_event_timestamp_seconds Unix timestamp of the latest audit event.\n# TYPE command_audit_last_event_timestamp_seconds gauge\n")
	for _, host := range sortedHosts {
		if value, ok := m.LastEvent[host]; ok {
			fmt.Fprintf(&out, "command_audit_last_event_timestamp_seconds%s %s\n", labels("hostname", host), number(value))
		}
	}
	out.WriteString("# HELP command_audit_agent_last_seen_timestamp_seconds Unix timestamp when an agent was last seen.\n# TYPE command_audit_agent_last_seen_timestamp_seconds gauge\n")
	for _, host := range sortedHosts {
		if value, ok := m.LastSeen[host]; ok {
			fmt.Fprintf(&out, "command_audit_agent_last_seen_timestamp_seconds%s %s\n", labels("hostname", host), number(float64(value.UnixNano())/1e9))
		}
	}
	out.WriteString("# HELP command_audit_agent_up Whether an agent is fresh (server) or running (local scrape).\n# TYPE command_audit_agent_up gauge\n")
	for _, host := range sortedHosts {
		up := 0
		if host == localAgent || now.Sub(m.LastSeen[host]) <= 90*time.Second {
			up = 1
		}
		fmt.Fprintf(&out, "command_audit_agent_up%s %d\n", labels("hostname", host), up)
	}
	writeHostCounter(&out, "command_audit_agent_events_dropped_total", "Events dropped by bounded buffers.", m.Dropped, sortedHosts)
	writeHostCounter(&out, "command_audit_parse_errors_total", "Malformed audit records observed.", m.ParseErrors, sortedHosts)
	out.WriteString("# HELP command_audit_events_suppressed_total Events intentionally excluded by collection policy.\n# TYPE command_audit_events_suppressed_total counter\n")
	var suppressedKeys []suppressedMetricKey
	for key := range m.Suppressed {
		suppressedKeys = append(suppressedKeys, key)
	}
	sort.Slice(suppressedKeys, func(i, j int) bool { return fmt.Sprint(suppressedKeys[i]) < fmt.Sprint(suppressedKeys[j]) })
	for _, key := range suppressedKeys {
		fmt.Fprintf(&out, "command_audit_events_suppressed_total%s %d\n", labels("hostname", key.Host, "reason", key.Reason), m.Suppressed[key])
	}
	return out.String()
}

func writeHostCounter(out *strings.Builder, name, help string, values map[string]int64, hosts []string) {
	fmt.Fprintf(out, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	for _, host := range hosts {
		fmt.Fprintf(out, "%s%s %d\n", name, labels("hostname", host), values[host])
	}
}
