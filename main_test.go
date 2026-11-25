package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func auditLines(command string, args ...string) []string {
	stamp := "1760000000.123:100"
	argv := append([]string{command}, args...)
	var execve strings.Builder
	for index, value := range argv {
		execve.WriteString(` a`)
		execve.WriteString(strconvItoa(index))
		execve.WriteString(`="`)
		execve.WriteString(value)
		execve.WriteString(`"`)
	}
	return []string{
		`type=SYSCALL msg=audit(` + stamp + `): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=1200 pid=1201 auid=1000 uid=1000 gid=1000 euid=0 egid=0 tty=pts0 ses=22 comm="` + command + `" exe="/usr/bin/` + command + `" key="command_audit"`,
		`type=EXECVE msg=audit(` + stamp + `): argc=` + strconvItoa(len(argv)) + execve.String(),
		`type=CWD msg=audit(` + stamp + `): cwd="/home/tester"`,
		`type=EOE msg=audit(` + stamp + `):`,
	}
}

func strconvItoa(value int) string {
	return fmt.Sprintf("%d", value)
}

func observedEvent(command string, args ...string) *Event {
	assembler := NewAuditAssembler("node-a", 100)
	var event *Event
	for _, line := range auditLines(command, args...) {
		if observed := assembler.Ingest(line); observed != nil {
			event = observed
		}
	}
	if event == nil {
		panic("test event was not assembled")
	}
	return event
}

func TestAuditParserIdentityArgumentsAndDanger(t *testing.T) {
	event := observedEvent("rm", "-rf", "/")
	if event.Command != "rm" || event.AUID != 1000 || event.EUID != 0 || event.PID != 1201 {
		t.Fatalf("unexpected identity or command: %+v", event)
	}
	if event.CWD != "/home/tester" || !event.Success || len(event.Args) != 3 {
		t.Fatalf("unexpected event fields: %+v", event)
	}
	if len(event.Danger) != 1 || event.Danger[0].Rule != "root_recursive_delete" {
		t.Fatalf("unexpected danger classification: %+v", event.Danger)
	}
}

func TestHexArgumentsDoNotCorruptNumericFields(t *testing.T) {
	lines := auditLines("ls", "/tmp")
	lines[1] = strings.ReplaceAll(lines[1], `a0="ls"`, "a0=6C73")
	lines[1] = strings.ReplaceAll(lines[1], `a1="/tmp"`, "a1=2F746D70")
	assembler := NewAuditAssembler("node-a", 100)
	var event *Event
	for _, line := range lines {
		if value := assembler.Ingest(line); value != nil {
			event = value
		}
	}
	if event == nil || strings.Join(event.Args, " ") != "ls /tmp" || event.PID != 1201 || event.AUID != 1000 {
		t.Fatalf("hex decoding failed: %+v", event)
	}
}

func TestRedactionAndRules(t *testing.T) {
	redacted := redactArguments([]string{"curl", "--token", "abc123", "--password=def456", "https://user:secret@example.test"})
	expected := "curl --token <redacted> --password=<redacted> https://user:<redacted>@example.test"
	if strings.Join(redacted, " ") != expected {
		t.Fatalf("unexpected redaction: %v", redacted)
	}
	if got := classifyCommand([]string{"reboot"}, ""); len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("reboot not detected: %+v", got)
	}
	if got := classifyCommand([]string{"systemctl", "poweroff"}, ""); len(got) != 1 || got[0].Rule != "system_power_state" {
		t.Fatalf("systemctl poweroff not detected: %+v", got)
	}
	if got := classifyCommand([]string{"rm", "file.txt"}, ""); got[0].Severity != "warning" {
		t.Fatalf("rm severity mismatch: %+v", got)
	}
	if got := classifyCommand([]string{"rm", "-r", "build"}, ""); got[0].Severity != "high" {
		t.Fatalf("recursive rm severity mismatch: %+v", got)
	}
}

func TestDangerousPoliciesAndArgumentSwitch(t *testing.T) {
	drop := NewAgentState("node-a", 10, "drop", true, 200, 300)
	drop.Observe(observedEvent("reboot"))
	if len(drop.Recent) != 0 || len(drop.Metrics.Events) != 0 || drop.Metrics.Suppressed[suppressedMetricKey{"node-a", "dangerous_command"}] != 1 {
		t.Fatalf("drop policy did not fully suppress event")
	}
	noAlert := NewAgentState("node-a", 10, "no-alert", true, 200, 300)
	noAlert.Observe(observedEvent("reboot"))
	if len(noAlert.Recent) != 1 || len(noAlert.Recent[0].Danger) != 0 || len(noAlert.Metrics.Events) != 1 || len(noAlert.Metrics.Danger) != 0 {
		t.Fatalf("no-alert policy mismatch: %+v", noAlert.Recent)
	}
	noArguments := NewAgentState("node-a", 10, "collect", false, 200, 300)
	noArguments.Observe(observedEvent("ls", "/tmp"))
	if len(noArguments.Recent) != 1 || len(noArguments.Recent[0].Args) != 0 {
		t.Fatalf("argument disable switch failed: %+v", noArguments.Recent)
	}
}

func TestMetricsExcludeArguments(t *testing.T) {
	state := NewAgentState("node-a", 10, "collect", true, 200, 300)
	state.Observe(observedEvent("rm", "-rf", "--password=supersecret", "/"))
	text := state.Metrics.Render("node-a")
	if strings.Contains(text, "supersecret") || strings.Contains(text, `"/"`) {
		t.Fatalf("metrics leaked arguments: %s", text)
	}
	if !strings.Contains(text, `rule="root_recursive_delete"`) || !strings.Contains(text, `command_audit_agent_up{hostname="node-a"} 1`) {
		t.Fatalf("expected metrics missing: %s", text)
	}
}

func TestRepositoryDedupeHeartbeatAndCentralDrop(t *testing.T) {
	repository := NewEventRepository(100, "collect")
	event := *observedEvent("ls", "/tmp")
	accepted, duplicates, _ := repository.Ingest(&PushPayload{Hostname: "node-a", Events: []Event{event}})
	if accepted != 1 || duplicates != 0 {
		t.Fatalf("first ingest mismatch: %d %d", accepted, duplicates)
	}
	accepted, duplicates, _ = repository.Ingest(&PushPayload{Hostname: "node-a", Events: []Event{event}})
	if accepted != 0 || duplicates != 1 {
		t.Fatalf("retry dedupe mismatch: %d %d", accepted, duplicates)
	}
	_, _, _ = repository.Ingest(&PushPayload{Hostname: "idle-node", Events: []Event{}})
	if !strings.Contains(repository.Metrics.Render(""), `command_audit_agent_up{hostname="idle-node"} 1`) {
		t.Fatal("heartbeat did not register idle agent")
	}
	centralDrop := NewEventRepository(100, "drop")
	accepted, _, _ = centralDrop.Ingest(&PushPayload{Hostname: "node-a", Events: []Event{*observedEvent("reboot")}})
	if accepted != 0 || len(centralDrop.Events) != 0 || len(centralDrop.Metrics.Suppressed) != 1 {
		t.Fatal("central drop policy failed")
	}
}

func TestAuthenticatedHTTPPushQueryAndScrape(t *testing.T) {
	repository := NewEventRepository(100, "collect")
	server := httptest.NewServer(serverHandler(repository, "test-token"))
	defer server.Close()
	response, err := http.Get(server.URL + "/metrics")
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("authentication not enforced: %v %v", response, err)
	}
	_ = response.Body.Close()
	body, _ := json.Marshal(PushPayload{Hostname: "node-a", Events: []Event{*observedEvent("reboot")}})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusAccepted {
		t.Fatalf("push failed: %v %v", response, err)
	}
	_ = response.Body.Close()
	query, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/events?dangerous=true", nil)
	query.Header.Set("Authorization", "Bearer test-token")
	response, err = http.DefaultClient.Do(query)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Events []Event `json:"events"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(result.Events) != 1 || result.Events[0].Command != "reboot" {
		t.Fatalf("query mismatch: %+v", result.Events)
	}
}

func TestEventPusherEndToEnd(t *testing.T) {
	repository := NewEventRepository(100, "collect")
	delivered := make(chan struct{}, 1)
	handler := serverHandler(repository, "")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(writer, request)
		if request.Method == http.MethodPost {
			select {
			case delivered <- struct{}{}:
			default:
			}
		}
	}))
	defer server.Close()
	state := NewAgentState("node-a", 10, "collect", true, 200, 300)
	state.Pusher = NewEventPusher(server.URL, "node-a", "", 100, 100, time.Second, 30*time.Second, func() {})
	state.Pusher.Start()
	defer state.Pusher.Close()
	state.Observe(observedEvent("ls", "/tmp"))
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("push was not delivered")
	}
	if len(repository.Query("node-a", false, 10)) != 1 {
		t.Fatal("pushed event not stored")
	}
}

func TestListenAddressParsing(t *testing.T) {
	address, err := resolveListen(":9101", "", -1, 9101)
	if err != nil || address != ":9101" {
		t.Fatalf("short listen address failed: %s %v", address, err)
	}
	address, err = resolveListen("127.0.0.1:0", "", -1, 9101)
	if err != nil || address != "127.0.0.1:0" {
		t.Fatalf("explicit listen address failed: %s %v", address, err)
	}
	address, err = resolveListen(":9101", "127.0.0.1", 9999, 9101)
	if err != nil || address != "127.0.0.1:9999" {
		t.Fatalf("legacy override failed: %s %v", address, err)
	}
}
