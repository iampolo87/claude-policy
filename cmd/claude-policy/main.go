// Command claude-policy is the single binary behind every Claude Code hook.
//
// Invariant: `hook` and `probe` always exit 0. Exit 2 (also what an
// unrecovered Go panic exits with) means "deny" to Claude Code, so every
// failure here fails open.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/rules"
	"github.com/iampolo87/claude-policy/internal/state"
)

const (
	maxHookStdin  = 16 << 20
	maxProbeStdin = 4 << 20
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintf(stderr, "claude-policy: panic: %v\n", p)
			code = 0
		}
	}()
	switch {
	case len(args) == 1 && args[0] == "hook":
		return runHook(stdin, stdout, stderr)
	case len(args) == 1 && args[0] == "probe":
		runProbe(stdin)
		return 0
	case len(args) == 1 && args[0] == "mine":
		return runMine(stdin)
	case len(args) == 2 && args[0] == "config" && args[1] == "check":
		return configCheck(stdout, stderr)
	case len(args) >= 1 && args[0] == "statusline":
		return runStatusline(args[1:], stdin, stdout)
	case len(args) >= 1 && args[0] == "log":
		return runLog(args[1:], stdout, stderr)
	case len(args) >= 1 && args[0] == "stats":
		return runStats(args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, "usage: claude-policy hook | probe | mine | log [--rule R] [--since 1d] | stats [--since 7d] [--rule R] [--session ID] [--json] [--baseline c/r/d] | config check | statusline <renderer>")
	return 1 // never 2: a mistyped subcommand in settings.json must not deny every tool call
}

// runHook prints exactly one JSON object, "{}" on any failure, and exits 0.
func runHook(stdin io.Reader, stdout, stderr io.Writer) (code int) {
	t0 := time.Now()
	out := []byte("{}")
	defer func() {
		if p := recover(); p != nil {
			out = []byte("{}")
			fmt.Fprintf(stderr, "claude-policy: panic: %v\n", p)
		}
		stdout.Write(append(out, '\n'))
		code = 0
	}()

	raw, err := io.ReadAll(io.LimitReader(stdin, maxHookStdin+1))
	if err != nil || len(raw) > maxHookStdin {
		return 0
	}
	in, err := hook.Parse(raw)
	if err != nil {
		// stderr only: a CC envelope change silently disabling rules must be visible
		fmt.Fprintf(stderr, "claude-policy: bad hook input: %v\n", err)
	}
	if in == nil {
		return 0
	}

	cfg := config.Defaults()
	if p, err := config.Path(); err == nil {
		if cfg, err = config.LoadFor(p, in.Cwd); err != nil {
			fmt.Fprintf(stderr, "claude-policy: %v\n", err)
		}
	}

	root, _ := state.Root() // "" disables state; every Store op then errors
	st := state.New(root, in.SessionID, in.AgentID)
	st.Prune(in.HookEventName, in.Source)
	st.RotateMetrics(in.HookEventName, in.Source, cfg.Metrics.Keep, cfg.Metrics.MaxBytes)

	// No HTML escaping: it would triple every <>& in updatedToolOutput.
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	o, stats := rules.RunStats(context.Background(), rules.Registry, cfg, in, st)
	if e.Encode(o) == nil {
		out = bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	}
	if cfg.Metrics.Mode == "on" {
		writeMetric(st, in, t0, stats)
	}
	return 0
}

// writeMetric appends the per-call metrics line; fail open, never panics.
func writeMetric(st *state.Store, in *hook.Input, t0 time.Time, stats []rules.Stat) {
	defer func() { recover() }()
	// total spans runHook from entry (stdin read, config, prune, rules, encode) to
	// before this append and the stdout write; process start/exit is not in it.
	el := time.Since(t0)
	st.AppendMetric(struct {
		TS      string       `json:"ts"`
		Session string       `json:"session_id"`
		Agent   string       `json:"agent_id,omitempty"`
		Event   string       `json:"event"`
		Tool    string       `json:"tool,omitempty"`
		TotalMS int64        `json:"total_ms"`
		TotalUS int64        `json:"total_us"`
		Rules   []rules.Stat `json:"rules"`
	}{time.Now().UTC().Format(time.RFC3339Nano), in.SessionID, in.AgentID, in.HookEventName, in.ToolName, el.Milliseconds(), el.Microseconds(), stats})
}

func configCheck(stdout, stderr io.Writer) int {
	p, err := config.Path()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	cwd, _ := os.Getwd()
	if _, err := config.LoadFor(p, cwd); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	if pp := config.ProjectPath(cwd, p); pp != "" {
		fmt.Fprintln(stdout, "project file:", pp)
	}
	return 0
}

// runProbe stores raw stdin verbatim under probe/<event>/ and drops captures
// older than state.MaxAge. Silent on every path.
func runProbe(stdin io.Reader) {
	raw, _ := io.ReadAll(io.LimitReader(stdin, maxProbeStdin))
	var env struct {
		Event string `json:"hook_event_name"`
	}
	json.Unmarshal(raw, &env)
	root, err := state.Root()
	if err != nil {
		return
	}
	dir := filepath.Join(root, state.ProbeDir, state.SafeName(env.Event, "unknown"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}

	// Sweep every event dir: captures hold prompts and tool output, and an
	// event that stops firing would otherwise keep them forever.
	cutoff := time.Now().Add(-state.MaxAge)
	olds, _ := filepath.Glob(filepath.Join(root, state.ProbeDir, "*", "*.json"))
	for _, p := range olds {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && fi.ModTime().Before(cutoff) {
			os.Remove(p)
		}
	}

	base := time.Now().UTC().Format("2006-01-02T15-04-05.000000000Z") + "-" + strconv.Itoa(os.Getpid())
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			name += "-" + strconv.Itoa(i)
		}
		f, err := os.OpenFile(filepath.Join(dir, name+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return
		}
		f.Write(raw)
		f.Close()
		return
	}
}
