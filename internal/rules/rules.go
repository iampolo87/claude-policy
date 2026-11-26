// Package rules holds every policy rule (one file per rule) and the runner
// that applies them to one hook call.
package rules

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// Rule is one policy. Apply returns nil for no opinion. It must honour ctx;
// a rule that overruns its deadline is abandoned and counts as no opinion.
type Rule interface {
	Name() string // the [rules.<name>] key in policy.toml
	Events() []string
	Apply(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision
}

// A rule may also implement:
//
//	Tools() []string         // run only for these tool_name values (empty = all)
//	Timeout() time.Duration  // deadline override (0 = DefaultTimeout)
const DefaultTimeout = 200 * time.Millisecond

// Registry is the production rule list, in merge order (the first
// updatedInput wins).
var Registry = []Rule{}

type logEntry struct {
	TS      string `json:"ts"`
	Session string `json:"session_id"`
	Agent   string `json:"agent_id,omitempty"`
	Event   string `json:"event"`
	Tool    string `json:"tool,omitempty"`
	Rule    string `json:"rule"`
	Mode    string `json:"mode"`
	// MS/US: wall time of Apply, set by Run on every line it writes (0 is the
	// common case); nil, so absent, on a rule's own fail-open lines.
	MS       *int64         `json:"ms,omitempty"`
	US       *int64         `json:"us,omitempty"`
	Decision *hook.Decision `json:"decision,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// Run applies the rules matching in's event and tool, sequentially, and
// merges what they decide. Mode off skips a rule; log records its decision
// in decisions.jsonl and drops it (unless Hard); enforce records and keeps
// it. A rule that panics or overruns is no opinion, logged.
func Run(ctx context.Context, rs []Rule, cfg *config.Config, in *hook.Input, st *state.Store) hook.Output {
	o, _ := RunStats(ctx, rs, cfg, in, st)
	return o
}

// Stat is one executed rule's wall time and what it returned (see verdict).
type Stat struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"`
	MS      int64  `json:"ms"`
	US      int64  `json:"us"`
	Verdict string `json:"verdict"`
}

// verdict names what a rule returned, whatever its mode: none, error, a
// permission, block, output, input, context, else decision.
func verdict(d *hook.Decision, err error) string {
	switch {
	case err != nil:
		return "error"
	case d == nil:
		return "none"
	case d.Permission != "":
		return d.Permission
	case d.Block:
		return "block"
	case d.UpdatedToolOutput != nil:
		return "output"
	case d.UpdatedInput != nil:
		return "input"
	case d.AdditionalContext != "":
		return "context"
	}
	return "decision"
}

// RunStats is Run plus a Stat for every rule that actually ran, in order.
func RunStats(ctx context.Context, rs []Rule, cfg *config.Config, in *hook.Input, st *state.Store) (hook.Output, []Stat) {
	var ds []*hook.Decision
	stats := []Stat{}
	for _, r := range rs {
		if !slices.Contains(r.Events(), in.HookEventName) {
			continue
		}
		if t, ok := r.(interface{ Tools() []string }); ok {
			if tools := t.Tools(); len(tools) > 0 && !slices.Contains(tools, in.ToolName) {
				continue
			}
		}
		mode := cfg.Mode(r.Name())
		if mode != "log" && mode != "enforce" {
			continue
		}
		t0 := time.Now()
		d, err := apply(ctx, r, in, cfg, st)
		el := time.Since(t0)
		ms, us := el.Milliseconds(), el.Microseconds()
		stats = append(stats, Stat{r.Name(), mode, ms, us, verdict(d, err)})
		if d == nil && err == nil {
			continue
		}
		e := logEntry{
			TS: time.Now().UTC().Format(time.RFC3339Nano), Session: in.SessionID, Agent: in.AgentID,
			Event: in.HookEventName, Tool: in.ToolName, Rule: r.Name(), Mode: mode, MS: &ms, US: &us, Decision: d,
		}
		if d != nil && d.Private {
			ld := *d
			ld.AdditionalContext = fmt.Sprintf("(private, %d chars)", len(d.AdditionalContext))
			e.Decision = &ld
		}
		if err != nil {
			e.Error = err.Error()
			fmt.Fprintf(os.Stderr, "claude-policy: rule %s: %v (fail open)\n", r.Name(), err)
		}
		st.AppendDecision(e) // best effort
		if d != nil && (mode == "enforce" || d.Hard) {
			ds = append(ds, d)
		}
	}
	return hook.Merge(in.HookEventName, in.ToolName, ds), stats
}

// apply runs one rule under its deadline. The goroutine recovers its own
// panic: an unrecovered panic in any goroutine exits 2, which denies every
// tool call.
func apply(ctx context.Context, r Rule, in *hook.Input, cfg *config.Config, st *state.Store) (*hook.Decision, error) {
	timeout := DefaultTimeout
	if t, ok := r.(interface{ Timeout() time.Duration }); ok && t.Timeout() > 0 {
		timeout = t.Timeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		d   *hook.Decision
		err error
	}
	ch := make(chan result, 1) // buffered: an abandoned rule must not block forever
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- result{err: fmt.Errorf("panic: %v", p)}
			}
		}()
		ch <- result{d: r.Apply(ctx, in, cfg, st)}
	}()
	select {
	case res := <-ch:
		return res.d, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("deadline %v: %w", timeout, ctx.Err())
	}
}
