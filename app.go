package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxRequestBody = 2 * 1024 * 1024

type AgentState struct {
	Hostname      string
	DangerousMode string
	CollectArgs   bool
	MaxRecent     int
	Metrics       *MetricStore
	Pusher        *EventPusher
	mu            sync.Mutex
	Recent        []Event
}

func NewAgentState(hostname string, maxRecent int, dangerousMode string, collectArgs bool, maxUsers, maxCommands int) *AgentState {
	return &AgentState{Hostname: hostname, MaxRecent: maxRecent, DangerousMode: dangerousMode, CollectArgs: collectArgs, Metrics: NewMetricStore(maxUsers, maxCommands)}
}

func (s *AgentState) Observe(input *Event) {
	event := *input
	if len(event.Danger) > 0 && s.DangerousMode == "drop" {
		s.Metrics.Suppress(s.Hostname, "dangerous_command")
		return
	}
	if s.DangerousMode == "no-alert" {
		event.Danger = nil
	}
	if !s.CollectArgs {
		event.Args = nil
	}
	s.Metrics.Observe(&event, time.Now())
	s.mu.Lock()
	if s.MaxRecent > 0 {
		s.Recent = append(s.Recent, event)
		if len(s.Recent) > s.MaxRecent {
			s.Recent = append([]Event(nil), s.Recent[len(s.Recent)-s.MaxRecent:]...)
		}
	}
	s.mu.Unlock()
	if s.Pusher != nil {
		s.Pusher.Enqueue(event)
	}
}

func (s *AgentState) Query(dangerousOnly bool, limit int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Event, 0)
	for index := len(s.Recent) - 1; index >= 0 && len(result) < limit; index-- {
		if dangerousOnly && len(s.Recent[index].Danger) == 0 {
			continue
		}
		result = append(result, s.Recent[index])
	}
	return result
}

type EventRepository struct {
	Events        []Event
	Metrics       *MetricStore
	MaxEvents     int
	DangerousMode string
	mu            sync.Mutex
	seen          map[string]bool
	seenOrder     []string
}

func NewEventRepository(maxEvents int, dangerousMode string) *EventRepository {
	return &EventRepository{Metrics: NewMetricStore(200, 300), MaxEvents: maxEvents, DangerousMode: dangerousMode, seen: make(map[string]bool)}
}

func (r *EventRepository) Ingest(payload *PushPayload) (int, int, error) {
	if len(payload.Events) > 1000 {
		return 0, 0, fmt.Errorf("events must contain at most 1000 items")
	}
	defaultHost := payload.Hostname
	if defaultHost == "" {
		defaultHost = "unknown"
	}
	r.Metrics.Touch(defaultHost)
	accepted, duplicates := 0, 0
	for _, original := range payload.Events {
		event := original
		if event.Hostname == "" {
			event.Hostname = defaultHost
		}
		if event.Timestamp <= 0 || math.IsNaN(event.Timestamp) || math.IsInf(event.Timestamp, 0) {
			continue
		}
		if event.DedupeKey == "" {
			event.DedupeKey = fmt.Sprintf("%s:%s:%d", event.Hostname, event.EventID, event.PID)
		}
		r.mu.Lock()
		if r.seen[event.DedupeKey] {
			duplicates++
			r.mu.Unlock()
			continue
		}
		r.seen[event.DedupeKey] = true
		r.seenOrder = append(r.seenOrder, event.DedupeKey)
		if len(r.seenOrder) > 50000 {
			delete(r.seen, r.seenOrder[0])
			r.seenOrder = r.seenOrder[1:]
		}
		suppressed := r.DangerousMode == "drop" && len(event.Danger) > 0
		if !suppressed {
			if r.DangerousMode == "no-alert" {
				event.Danger = nil
			}
			if r.MaxEvents > 0 {
				r.Events = append(r.Events, event)
				if len(r.Events) > r.MaxEvents {
					r.Events = append([]Event(nil), r.Events[len(r.Events)-r.MaxEvents:]...)
				}
			}
		}
		r.mu.Unlock()
		if suppressed {
			r.Metrics.Suppress(event.Hostname, "dangerous_command")
			continue
		}
		r.Metrics.Observe(&event, time.Now())
		accepted++
	}
	return accepted, duplicates, nil
}

func (r *EventRepository) Query(hostname string, dangerousOnly bool, limit int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Event, 0)
	for index := len(r.Events) - 1; index >= 0 && len(result) < limit; index-- {
		event := r.Events[index]
		if hostname != "" && event.Hostname != hostname {
			continue
		}
		if dangerousOnly && len(event.Danger) == 0 {
			continue
		}
		result = append(result, event)
	}
	return result
}

type EventPusher struct {
	URL               string
	Hostname          string
	Token             string
	BatchSize         int
	HeartbeatInterval time.Duration
	Queue             chan Event
	OnDrop            func()
	Client            *http.Client
	stop              chan struct{}
	done              chan struct{}
}

func NewEventPusher(url, hostname, token string, batchSize, queueSize int, timeout, heartbeat time.Duration, onDrop func()) *EventPusher {
	url = strings.TrimRight(url, "/")
	if !strings.HasSuffix(url, "/api/v1/events") {
		url += "/api/v1/events"
	}
	return &EventPusher{URL: url, Hostname: hostname, Token: token, BatchSize: batchSize, HeartbeatInterval: heartbeat, Queue: make(chan Event, queueSize), OnDrop: onDrop, Client: &http.Client{Timeout: timeout}, stop: make(chan struct{}), done: make(chan struct{})}
}

func (p *EventPusher) Start() {
	go p.run()
}

func (p *EventPusher) Enqueue(event Event) {
	select {
	case p.Queue <- event:
	default:
		p.OnDrop()
	}
}

func (p *EventPusher) post(batch []Event) error {
	if batch == nil {
		batch = make([]Event, 0)
	}
	body, err := json.Marshal(PushPayload{Hostname: p.Hostname, Events: batch})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "command-audit-agent/0.2.0")
	if p.Token != "" {
		request.Header.Set("Authorization", "Bearer "+p.Token)
	}
	response, err := p.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected server status %s", response.Status)
	}
	return nil
}

func (p *EventPusher) run() {
	defer close(p.done)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var pending []Event
	lastHeartbeat := time.Time{}
	for {
		if len(pending) == 0 {
			select {
			case event := <-p.Queue:
				pending = append(pending, event)
			drainQueue:
				for len(pending) < p.BatchSize {
					select {
					case next := <-p.Queue:
						pending = append(pending, next)
					default:
						break drainQueue
					}
				}
			case now := <-ticker.C:
				if now.Sub(lastHeartbeat) >= p.HeartbeatInterval {
					if err := p.post(nil); err != nil {
						logAt(2, "heartbeat failed: %v", err)
					} else {
						lastHeartbeat = now
					}
				}
				continue
			case <-p.stop:
				return
			}
		}
		if err := p.post(pending); err != nil {
			logAt(2, "push failed; retaining %d events: %v", len(pending), err)
			select {
			case <-time.After(2 * time.Second):
			case <-p.stop:
				return
			}
		} else {
			pending = nil
			lastHeartbeat = time.Now()
		}
	}
}

func (p *EventPusher) Close() {
	close(p.stop)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}

func authorized(request *http.Request, token string) bool {
	if token == "" {
		return true
	}
	expected := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte(expected)) == 1
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	body, _ := json.Marshal(value)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func writeMetrics(writer http.ResponseWriter, body string) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(writer, body)
}

func queryLimit(request *http.Request) int {
	limit, err := strconv.Atoi(request.URL.Query().Get("limit"))
	if err != nil || limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return limit
}

func agentHandler(state *AgentState, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		queueSize := 0
		if state.Pusher != nil {
			queueSize = len(state.Pusher.Queue)
		}
		writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "hostname": state.Hostname, "push_queue": queueSize})
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, request *http.Request) {
		if !authorized(request, token) {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		writeMetrics(writer, state.Metrics.Render(state.Hostname))
	})
	mux.HandleFunc("/api/v1/events", func(writer http.ResponseWriter, request *http.Request) {
		if !authorized(request, token) {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		events := state.Query(request.URL.Query().Get("dangerous") == "true", queryLimit(request))
		writeJSON(writer, http.StatusOK, map[string]any{"events": events})
	})
	return mux
}

func serverHandler(repository *EventRepository, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "recent_events": len(repository.Events)})
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, request *http.Request) {
		if !authorized(request, token) {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		writeMetrics(writer, repository.Metrics.Render(""))
	})
	mux.HandleFunc("/api/v1/events", func(writer http.ResponseWriter, request *http.Request) {
		if !authorized(request, token) {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		switch request.Method {
		case http.MethodGet:
			events := repository.Query(request.URL.Query().Get("hostname"), request.URL.Query().Get("dangerous") == "true", queryLimit(request))
			writeJSON(writer, http.StatusOK, map[string]any{"events": events})
		case http.MethodPost:
			request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBody)
			var payload PushPayload
			decoder := json.NewDecoder(request.Body)
			if err := decoder.Decode(&payload); err != nil {
				writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			accepted, duplicates, err := repository.Ingest(&payload)
			if err != nil {
				writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(writer, http.StatusAccepted, map[string]int{"accepted": accepted, "duplicates": duplicates})
		default:
			writeJSON(writer, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})
	return mux
}
