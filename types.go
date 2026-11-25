package main

import (
	"encoding/hex"
	"fmt"
	"os/user"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DangerRule struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type Event struct {
	Timestamp float64      `json:"timestamp"`
	EventID   string       `json:"event_id"`
	Hostname  string       `json:"hostname"`
	User      string       `json:"user"`
	AUID      int64        `json:"auid"`
	UID       int64        `json:"uid"`
	EUID      int64        `json:"euid"`
	Command   string       `json:"command"`
	Exe       string       `json:"exe"`
	Args      []string     `json:"args"`
	CWD       string       `json:"cwd"`
	PID       int64        `json:"pid"`
	PPID      int64        `json:"ppid"`
	Success   bool         `json:"success"`
	ExitCode  int64        `json:"exit_code"`
	Session   int64        `json:"session"`
	TTY       string       `json:"tty"`
	Danger    []DangerRule `json:"danger"`
	DedupeKey string       `json:"dedupe_key"`
}

type PushPayload struct {
	Hostname string  `json:"hostname"`
	Events   []Event `json:"events"`
}

var (
	msgIDPattern   = regexp.MustCompile(`msg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)`)
	typePattern    = regexp.MustCompile(`(?:^|\s)type=([A-Z0-9_]+)`)
	fieldPattern   = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S+)`)
	hexPattern     = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	argPattern     = regexp.MustCompile(`^a[0-9]+$`)
	sensitiveEnv   = regexp.MustCompile(`(?i)^([A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)=(.*)$`)
	uriCredentials = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://)([^/@:]+):([^/@]*)@(.+)$`)
)

func decodeAuditValue(value string, allowHex bool) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		if decoded, err := strconv.Unquote(value); err == nil {
			return decoded
		}
		return value[1 : len(value)-1]
	}
	if allowHex && len(value) >= 2 && len(value)%2 == 0 && hexPattern.MatchString(value) {
		if decoded, err := hex.DecodeString(value); err == nil {
			return strings.TrimRight(string(decoded), "\x00")
		}
	}
	return value
}

func parseFields(line string) map[string]string {
	fields := make(map[string]string)
	for _, match := range fieldPattern.FindAllStringSubmatch(line, -1) {
		key := match[1]
		allowHex := argPattern.MatchString(key) || key == "proctitle" || key == "name" || key == "exe" || key == "cwd" || key == "comm"
		fields[key] = decodeAuditValue(match[2], allowHex)
	}
	return fields
}

func parseInt(value string, fallback int64) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

var userCache = struct {
	sync.Mutex
	values map[int64]string
}{values: make(map[int64]string)}

func resolveUser(uid int64) string {
	if uid == 4294967295 || uid == -1 {
		return "unset"
	}
	userCache.Lock()
	cached, ok := userCache.values[uid]
	userCache.Unlock()
	if ok {
		return cached
	}
	name := fmt.Sprintf("uid:%d", uid)
	if account, err := user.LookupId(strconv.FormatInt(uid, 10)); err == nil && account.Username != "" {
		name = account.Username
	}
	userCache.Lock()
	userCache.values[uid] = name
	userCache.Unlock()
	return name
}

type partialEvent struct {
	Timestamp float64
	EventID   string
	Records   map[string]map[string]string
	Updated   time.Time
}

type AuditAssembler struct {
	Hostname    string
	MaxPending  int
	Timeout     time.Duration
	Pending     map[string]*partialEvent
	Order       []string
	Dropped     int64
	ParseErrors int64
}

func NewAuditAssembler(hostname string, maxPending int) *AuditAssembler {
	return &AuditAssembler{Hostname: hostname, MaxPending: maxPending, Timeout: 2 * time.Second, Pending: make(map[string]*partialEvent)}
}

func (a *AuditAssembler) Ingest(line string) *Event {
	match := msgIDPattern.FindStringSubmatch(line)
	if match == nil {
		if strings.TrimSpace(line) != "" {
			a.ParseErrors++
		}
		return nil
	}
	typeMatch := typePattern.FindStringSubmatch(line)
	if typeMatch == nil {
		return nil
	}
	eventType := typeMatch[1]
	eventID := match[1] + ":" + match[2]
	partial := a.Pending[eventID]
	if partial == nil {
		if len(a.Pending) >= a.MaxPending {
			oldest := a.Order[0]
			delete(a.Pending, oldest)
			a.Order = a.Order[1:]
			a.Dropped++
		}
		timestamp, _ := strconv.ParseFloat(match[1], 64)
		partial = &partialEvent{Timestamp: timestamp, EventID: eventID, Records: make(map[string]map[string]string)}
		a.Pending[eventID] = partial
		a.Order = append(a.Order, eventID)
	}
	partial.Updated = time.Now()
	if eventType != "EOE" {
		partial.Records[eventType] = parseFields(line)
	}
	if eventType != "EOE" {
		return nil
	}
	a.remove(eventID)
	return a.build(partial)
}

func (a *AuditAssembler) remove(eventID string) {
	delete(a.Pending, eventID)
	for index, value := range a.Order {
		if value == eventID {
			a.Order = append(a.Order[:index], a.Order[index+1:]...)
			break
		}
	}
}

func (a *AuditAssembler) Expire() []*Event {
	cutoff := time.Now().Add(-a.Timeout)
	var events []*Event
	var expired []string
	for id, partial := range a.Pending {
		if !partial.Updated.After(cutoff) {
			if event := a.build(partial); event != nil {
				events = append(events, event)
			}
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		a.remove(id)
	}
	return events
}

func (a *AuditAssembler) build(partial *partialEvent) *Event {
	syscall := partial.Records["SYSCALL"]
	execve := partial.Records["EXECVE"]
	if syscall == nil || execve == nil {
		return nil
	}
	argc := parseInt(execve["argc"], 0)
	var argv []string
	for index := int64(0); index < argc; index++ {
		argv = append(argv, execve[fmt.Sprintf("a%d", index)])
	}
	if len(argv) == 0 && execve["a0"] != "" {
		argv = append(argv, execve["a0"])
	}
	exe := syscall["exe"]
	fallback := syscall["comm"]
	if len(argv) > 0 {
		fallback = argv[0]
	}
	command := path.Base(exe)
	if exe == "" {
		command = path.Base(fallback)
	}
	if command == "" || command == "." {
		command = "unknown"
	}
	auid := parseInt(syscall["auid"], -1)
	uid := parseInt(syscall["uid"], -1)
	euid := parseInt(syscall["euid"], uid)
	identity := auid
	if identity < 0 || identity == 4294967295 {
		identity = euid
	}
	cwd := ""
	if partial.Records["CWD"] != nil {
		cwd = partial.Records["CWD"]["cwd"]
	}
	pid := parseInt(syscall["pid"], -1)
	return &Event{
		Timestamp: partial.Timestamp,
		EventID:   partial.EventID,
		Hostname:  a.Hostname,
		User:      resolveUser(identity),
		AUID:      auid,
		UID:       uid,
		EUID:      euid,
		Command:   command,
		Exe:       exe,
		Args:      redactArguments(argv),
		CWD:       cwd,
		PID:       pid,
		PPID:      parseInt(syscall["ppid"], -1),
		Success:   syscall["success"] == "yes",
		ExitCode:  parseInt(syscall["exit"], 0),
		Session:   parseInt(syscall["ses"], -1),
		TTY:       syscall["tty"],
		Danger:    classifyCommand(argv, exe),
		DedupeKey: fmt.Sprintf("%s:%s:%d", a.Hostname, partial.EventID, pid),
	}
}

var sensitiveFlags = map[string]bool{
	"--password": true, "--passwd": true, "--token": true, "--access-token": true,
	"--api-key": true, "--apikey": true, "--secret": true, "--client-secret": true,
	"--private-key": true, "--credential": true, "--credentials": true, "--authorization": true,
}

func redactArguments(argv []string) []string {
	redacted := make([]string, 0, len(argv))
	maskNext := false
	for index, value := range argv {
		if maskNext {
			redacted = append(redacted, "<redacted>")
			maskNext = false
			continue
		}
		lower := strings.ToLower(value)
		if index > 0 && sensitiveFlags[lower] {
			redacted = append(redacted, value)
			maskNext = true
			continue
		}
		matchedAssignment := false
		if index > 0 {
			for flag := range sensitiveFlags {
				if strings.HasPrefix(lower, flag+"=") {
					redacted = append(redacted, strings.SplitN(value, "=", 2)[0]+"=<redacted>")
					matchedAssignment = true
					break
				}
			}
		}
		if matchedAssignment {
			continue
		}
		if match := sensitiveEnv.FindStringSubmatch(value); match != nil {
			redacted = append(redacted, match[1]+"=<redacted>")
			continue
		}
		if index > 0 && len(argv) > 0 && strings.Contains(strings.ToLower(path.Base(argv[0])), "mysql") && strings.HasPrefix(lower, "-p") && len(value) > 2 {
			redacted = append(redacted, "-p<redacted>")
			continue
		}
		if match := uriCredentials.FindStringSubmatch(value); match != nil {
			value = match[1] + match[2] + ":<redacted>@" + match[4]
		}
		redacted = append(redacted, value)
	}
	return redacted
}

func dangerRule(rule, severity, description string) DangerRule {
	return DangerRule{Rule: rule, Severity: severity, Description: description}
}

func recursiveFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-r" || arg == "-R" || arg == "--recursive" {
			return true
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && (strings.Contains(arg[1:], "r") || strings.Contains(arg[1:], "R")) {
			return true
		}
	}
	return false
}

func containsArg(args []string, targets ...string) bool {
	for _, arg := range args {
		for _, target := range targets {
			if arg == target {
				return true
			}
		}
	}
	return false
}

func classifyCommand(argv []string, exe string) []DangerRule {
	if len(argv) == 0 && exe == "" {
		return nil
	}
	name := exe
	if name == "" && len(argv) > 0 {
		name = argv[0]
	}
	command := path.Base(name)
	var args []string
	if len(argv) > 0 {
		args = argv[1:]
	}
	var rules []DangerRule
	if containsArg([]string{command}, "reboot", "poweroff", "halt", "shutdown") {
		rules = append(rules, dangerRule("system_power_state", "critical", command+" changes host power or run state"))
	}
	if (command == "init" || command == "telinit") && containsArg(args, "0", "6") {
		rules = append(rules, dangerRule("system_runlevel", "critical", "command requests shutdown or reboot runlevel"))
	}
	if command == "systemctl" && containsArg(args, "reboot", "poweroff", "halt", "kexec") {
		rules = append(rules, dangerRule("system_power_state", "critical", "systemctl changes host power state"))
	}
	if command == "rm" {
		recursive := recursiveFlag(args)
		root := containsArg(args, "/", "/*")
		for _, arg := range args {
			if strings.HasPrefix(arg, "--no-preserve-root") {
				root = true
			}
		}
		if recursive && root {
			rules = append(rules, dangerRule("root_recursive_delete", "critical", "recursive deletion targets filesystem root"))
		} else if recursive {
			rules = append(rules, dangerRule("recursive_delete", "high", "recursive file deletion"))
		} else {
			rules = append(rules, dangerRule("file_delete", "warning", "file deletion command"))
		}
	}
	if command == "dd" {
		for _, arg := range args {
			if strings.HasPrefix(arg, "of=/dev/") {
				rules = append(rules, dangerRule("block_device_overwrite", "critical", "dd writes directly to a block device"))
				break
			}
		}
	}
	if command == "mkfs" || strings.HasPrefix(command, "mkfs.") || containsArg([]string{command}, "wipefs", "fdisk", "sfdisk", "parted") {
		rules = append(rules, dangerRule("disk_layout_modify", "critical", "disk or filesystem destructive operation"))
	}
	if containsArg([]string{command}, "chmod", "chown", "chgrp") && recursiveFlag(args) && containsArg(args, "/") {
		rules = append(rules, dangerRule("root_permission_modify", "high", "recursive permission change targets root"))
	}
	return rules
}
