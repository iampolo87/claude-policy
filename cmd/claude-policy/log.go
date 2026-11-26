package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/iampolo87/claude-policy/internal/state"
)

const logReasonChars = 240

type logLine struct {
	TS       time.Time `json:"ts"`
	Agent    string    `json:"agent_id"`
	Event    string    `json:"event"`
	Tool     string    `json:"tool"`
	Rule     string    `json:"rule"`
	Mode     string    `json:"mode"`
	Error    string    `json:"error"`
	Result   string    `json:"result"` // mine
	Decision *struct {
		Permission string `json:"permission"`
		Reason     string `json:"reason"`
		Context    string `json:"additional_context"`
		Block      bool   `json:"block"`
		Hard       bool   `json:"hard"`
		Updated    any    `json:"updated_input"`
	} `json:"decision"`
}

// runLog prints decisions.jsonl (rotated generation first), one line per
// decision, filtered by --rule and --since (Go duration or Nd).
func runLog(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rule := fs.String("rule", "", "only this rule")
	since := fs.String("since", "", "only decisions newer than this (e.g. 90m, 1d)")
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return 1
	}
	var cutoff time.Time
	if *since != "" {
		d, err := parseSince(*since)
		if err != nil {
			fmt.Fprintf(stderr, "--since: %v\n", err)
			return 1
		}
		cutoff = time.Now().Add(-d)
	}
	root, err := state.Root()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	n := 0
	for _, name := range []string{"decisions.jsonl.1", "decisions.jsonl"} {
		f, err := os.Open(filepath.Join(root, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 16<<20)
		for sc.Scan() {
			var l logLine
			if json.Unmarshal(sc.Bytes(), &l) != nil || (*rule != "" && l.Rule != *rule) || l.TS.Before(cutoff) {
				continue
			}
			fmt.Fprintln(stdout, formatLogLine(l))
			n++
		}
		f.Close()
	}
	fmt.Fprintf(stdout, "%d decisions\n", n)
	return 0
}

func parseSince(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err == nil && d < 0 {
		err = fmt.Errorf("invalid %q: negative", s)
	}
	return d, err
}

// formatLogLine: ts mode rule event[/tool] actor verdict: text
func formatLogLine(l logLine) string {
	where := l.Event
	if l.Tool != "" {
		where += "/" + l.Tool
	}
	mode, actor := l.Mode, "main"
	if mode == "" {
		mode = "-" // mine
	}
	if l.Agent != "" {
		actor = l.Agent
	}
	verdict, text := "none", ""
	switch d := l.Decision; {
	case l.Error != "":
		verdict, text = "error", l.Error
	case l.Result != "":
		verdict = l.Result
	case d == nil:
	case d.Permission != "":
		verdict, text = d.Permission, d.Reason
	case d.Block:
		verdict, text = "block", d.Reason
	case d.Updated != nil:
		verdict = "updated_input"
	case d.Context != "":
		verdict, text = "context", d.Context
	case d.Reason != "":
		verdict, text = "note", d.Reason // e.g. output_cap
	}
	if l.Decision != nil && l.Decision.Hard {
		verdict += "(hard)"
	}
	text = strings.Join(strings.Fields(text), " ")
	if r := []rune(text); len(r) > logReasonChars {
		text = string(r[:logReasonChars]) + "…"
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s %s %s %s %s: %s",
		l.TS.UTC().Format(time.DateTime), mode, l.Rule, where, actor, verdict, text))
}
