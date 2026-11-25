package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.2.0"

var runtimeLogLevel = 1

func logAt(level int, format string, args ...any) {
	if level >= runtimeLogLevel {
		log.Printf(format, args...)
	}
}

func parseLogLevel(value string) error {
	switch strings.ToUpper(value) {
	case "DEBUG":
		runtimeLogLevel = 0
	case "INFO":
		runtimeLogLevel = 1
	case "WARNING":
		runtimeLogLevel = 2
	case "ERROR":
		runtimeLogLevel = 3
	case "CRITICAL":
		runtimeLogLevel = 4
	default:
		return fmt.Errorf("invalid log level %q", value)
	}
	return nil
}

func resolveListen(address, legacyHost string, legacyPort, defaultPort int) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("listen address cannot be empty")
	}
	host, portText := "", ""
	if strings.Contains(address, ":") {
		var err error
		host, portText, err = net.SplitHostPort(address)
		if err != nil {
			return "", fmt.Errorf("invalid listen address %q: %w", address, err)
		}
	} else {
		host = address
		portText = strconv.Itoa(defaultPort)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return "", fmt.Errorf("invalid listen port %q", portText)
	}
	if legacyHost != "" {
		host = legacyHost
	}
	if legacyPort >= 0 {
		if legacyPort > 65535 {
			return "", fmt.Errorf("invalid legacy listen port %d", legacyPort)
		}
		port = legacyPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

type AuditReader struct {
	State     *AgentState
	Source    string
	FromStart bool
	Assembler *AuditAssembler
	Stop      chan struct{}
	stopOnce  sync.Once
}

func NewAuditReader(state *AgentState, source string, fromStart bool, maxPending int) *AuditReader {
	return &AuditReader{State: state, Source: source, FromStart: fromStart, Assembler: NewAuditAssembler(state.Hostname, maxPending), Stop: make(chan struct{})}
}

func (r *AuditReader) Close() {
	r.stopOnce.Do(func() { close(r.Stop) })
}

func (r *AuditReader) wait(duration time.Duration) bool {
	select {
	case <-time.After(duration):
		return true
	case <-r.Stop:
		return false
	}
}

func (r *AuditReader) accountParser() {
	if r.Assembler.Dropped > 0 {
		r.State.Metrics.Drop(r.State.Hostname, r.Assembler.Dropped)
		r.Assembler.Dropped = 0
	}
	if r.Assembler.ParseErrors > 0 {
		r.State.Metrics.ParseError(r.State.Hostname, r.Assembler.ParseErrors)
		r.Assembler.ParseErrors = 0
	}
}

func (r *AuditReader) processLine(line string) {
	if event := r.Assembler.Ingest(line); event != nil {
		r.State.Observe(event)
	}
	r.accountParser()
}

func (r *AuditReader) expire() {
	for _, event := range r.Assembler.Expire() {
		r.State.Observe(event)
	}
	r.accountParser()
}

func (r *AuditReader) Run() error {
	r.State.Metrics.Touch(r.State.Hostname)
	if r.Source == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			r.processLine(scanner.Text())
		}
		r.expire()
		return scanner.Err()
	}
	firstOpen := true
	for {
		select {
		case <-r.Stop:
			r.expire()
			return nil
		default:
		}
		file, err := os.Open(r.Source)
		if err != nil {
			logAt(2, "cannot open audit log %s: %v", r.Source, err)
			if !r.wait(time.Second) {
				return nil
			}
			continue
		}
		if firstOpen && !r.FromStart {
			_, _ = file.Seek(0, io.SeekEnd)
		}
		firstOpen = false
		reader := bufio.NewReaderSize(file, 256*1024)
		rotated := false
		for {
			line, readErr := reader.ReadString('\n')
			if line != "" {
				r.processLine(line)
			}
			if readErr == nil {
				continue
			}
			if readErr != io.EOF {
				_ = file.Close()
				return readErr
			}
			r.expire()
			current, statErr := os.Stat(r.Source)
			open, openErr := file.Stat()
			if statErr == nil && openErr == nil && !os.SameFile(current, open) {
				rotated = true
				break
			}
			if !r.wait(250 * time.Millisecond) {
				_ = file.Close()
				r.expire()
				return nil
			}
		}
		_ = file.Close()
		if !rotated && !r.wait(100*time.Millisecond) {
			return nil
		}
	}
}

func runAgent(arguments []string) error {
	flags := flag.NewFlagSet("command-audit", flag.ContinueOnError)
	var listenAddress, legacyHost, input, hostname, serverURL, token, dangerousMode, logLevel string
	var legacyPort, maxPending, maxRecent, maxUsers, maxCommands, batchSize, queueSize int
	var fromStart, collectArgs, noArgs, showVersion bool
	var pushTimeout, heartbeatInterval float64
	flags.StringVar(&listenAddress, "web.listen-address", ":9101", "listen address, for example :9101 or 127.0.0.1:9101")
	flags.StringVar(&legacyHost, "listen", "", "legacy listen host")
	flags.IntVar(&legacyPort, "port", -1, "legacy listen port")
	flags.StringVar(&input, "audit.log-path", "/var/log/audit/audit.log", "audit log path, or - for stdin")
	flags.StringVar(&input, "input", "/var/log/audit/audit.log", "alias for audit.log-path")
	flags.BoolVar(&fromStart, "audit.from-start", false, "read existing audit log content")
	flags.BoolVar(&fromStart, "from-start", false, "alias for audit.from-start")
	flags.IntVar(&maxPending, "audit.max-pending", 10000, "maximum incomplete audit events")
	defaultHost, _ := os.Hostname()
	flags.StringVar(&hostname, "hostname", defaultHost, "hostname label")
	flags.StringVar(&serverURL, "server.url", os.Getenv("COMMAND_AUDIT_SERVER"), "optional aggregation server URL")
	flags.StringVar(&serverURL, "server-url", os.Getenv("COMMAND_AUDIT_SERVER"), "alias for server.url")
	flags.StringVar(&token, "auth.token", os.Getenv("COMMAND_AUDIT_TOKEN"), "bearer token; environment variable is preferred")
	flags.StringVar(&token, "token", os.Getenv("COMMAND_AUDIT_TOKEN"), "alias for auth.token")
	flags.StringVar(&dangerousMode, "dangerous.commands", "collect", "dangerous policy: collect, no-alert, or drop")
	flags.StringVar(&dangerousMode, "dangerous-commands", "collect", "alias for dangerous.commands")
	flags.BoolVar(&collectArgs, "collector.args", true, "collect redacted command arguments")
	flags.BoolVar(&collectArgs, "collect-args", true, "alias for collector.args")
	flags.BoolVar(&noArgs, "no-collector.args", false, "disable command argument collection")
	flags.BoolVar(&noArgs, "no-collect-args", false, "alias for no-collector.args")
	flags.IntVar(&maxRecent, "collector.max-recent", 200, "local recent event cache; 0 disables")
	flags.IntVar(&maxRecent, "max-recent", 200, "alias for collector.max-recent")
	flags.IntVar(&maxUsers, "metrics.max-users", 200, "maximum distinct user labels")
	flags.IntVar(&maxCommands, "metrics.max-commands", 300, "maximum distinct command labels")
	flags.IntVar(&batchSize, "push.batch-size", 100, "push batch size")
	flags.IntVar(&queueSize, "push.queue-size", 10000, "in-memory push queue size")
	flags.Float64Var(&pushTimeout, "push.timeout", 5, "push HTTP timeout in seconds")
	flags.Float64Var(&heartbeatInterval, "push.heartbeat-interval", 30, "idle heartbeat interval in seconds")
	flags.StringVar(&logLevel, "log.level", "INFO", "DEBUG, INFO, WARNING, ERROR, or CRITICAL")
	flags.StringVar(&logLevel, "log-level", "INFO", "alias for log.level")
	flags.BoolVar(&showVersion, "version", false, "print version")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if showVersion {
		fmt.Println("command-audit " + version)
		return nil
	}
	if noArgs {
		collectArgs = false
	}
	if dangerousMode != "collect" && dangerousMode != "no-alert" && dangerousMode != "drop" {
		return fmt.Errorf("dangerous.commands must be collect, no-alert, or drop")
	}
	if maxRecent < 0 || maxPending < 1 || batchSize < 1 || queueSize < 1 || maxUsers < 2 || maxCommands < 2 || pushTimeout <= 0 || heartbeatInterval <= 0 {
		return fmt.Errorf("invalid collector, metric, queue, or timeout limits")
	}
	if err := parseLogLevel(logLevel); err != nil {
		return err
	}
	address, err := resolveListen(listenAddress, legacyHost, legacyPort, 9101)
	if err != nil {
		return err
	}
	state := NewAgentState(hostname, maxRecent, dangerousMode, collectArgs, maxUsers, maxCommands)
	if serverURL != "" {
		state.Pusher = NewEventPusher(serverURL, hostname, token, batchSize, queueSize, time.Duration(pushTimeout*float64(time.Second)), time.Duration(heartbeatInterval*float64(time.Second)), func() { state.Metrics.Drop(hostname, 1) })
		state.Pusher.Start()
		defer state.Pusher.Close()
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: agentHandler(state, token), ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	reader := NewAuditReader(state, input, fromStart, maxPending)
	readerDone := make(chan error, 1)
	go func() { readerDone <- reader.Run() }()
	defer reader.Close()
	logAt(1, "agent listening on %s, reading %s, dangerous=%s, args=%t, push=%t", listener.Addr(), input, dangerousMode, collectArgs, serverURL != "")
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	select {
	case <-signalContext.Done():
	case err = <-readerDone:
	case err = <-serveDone:
	}
	reader.Close()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownContext)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runServer(arguments []string) error {
	flags := flag.NewFlagSet("command-audit server", flag.ContinueOnError)
	var listenAddress, legacyHost, token, dangerousMode, logLevel string
	var legacyPort, maxEvents int
	var showVersion bool
	flags.StringVar(&listenAddress, "web.listen-address", ":9100", "listen address")
	flags.StringVar(&legacyHost, "listen", "", "legacy listen host")
	flags.IntVar(&legacyPort, "port", -1, "legacy listen port")
	flags.IntVar(&maxEvents, "server.max-events", 10000, "recent event cache size; 0 disables")
	flags.IntVar(&maxEvents, "max-events", 10000, "alias for server.max-events")
	flags.StringVar(&dangerousMode, "dangerous.commands", "collect", "dangerous policy: collect, no-alert, or drop")
	flags.StringVar(&dangerousMode, "dangerous-commands", "collect", "alias for dangerous.commands")
	flags.StringVar(&token, "auth.token", os.Getenv("COMMAND_AUDIT_TOKEN"), "bearer token")
	flags.StringVar(&token, "token", os.Getenv("COMMAND_AUDIT_TOKEN"), "alias for auth.token")
	flags.StringVar(&logLevel, "log.level", "INFO", "log level")
	flags.StringVar(&logLevel, "log-level", "INFO", "alias for log.level")
	flags.BoolVar(&showVersion, "version", false, "print version")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if showVersion {
		fmt.Println("command-audit " + version)
		return nil
	}
	if maxEvents < 0 {
		return fmt.Errorf("server.max-events must be >=0")
	}
	if dangerousMode != "collect" && dangerousMode != "no-alert" && dangerousMode != "drop" {
		return fmt.Errorf("dangerous.commands must be collect, no-alert, or drop")
	}
	if err := parseLogLevel(logLevel); err != nil {
		return err
	}
	address, err := resolveListen(listenAddress, legacyHost, legacyPort, 9100)
	if err != nil {
		return err
	}
	repository := NewEventRepository(maxEvents, dangerousMode)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: serverHandler(repository, token), ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	logAt(1, "server listening on %s, dangerous=%s, authentication=%t", listener.Addr(), dangerousMode, token != "")
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	select {
	case <-signalContext.Done():
	case err = <-serveDone:
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	arguments := os.Args[1:]
	var err error
	if len(arguments) > 0 && arguments[0] == "server" {
		err = runServer(arguments[1:])
	} else {
		if len(arguments) > 0 && arguments[0] == "agent" {
			arguments = arguments[1:]
		}
		err = runAgent(arguments)
	}
	if errors.Is(err, flag.ErrHelp) || err == nil {
		return
	}
	logAt(3, "command-audit: %v", err)
	os.Exit(2)
}
