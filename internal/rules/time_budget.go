package rules

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// timeBudget is an opt-in, advisory time budget: `budget:20m` in a prompt
// starts it, `budget:off` clears it, and each tool result (success or
// failure) gets `elapsed Xs / Ns` while it is active. Auto-clears at 2x.
type timeBudget struct{}

func init() { Registry = append(Registry, timeBudget{}) }

var tbNow = time.Now

const tbFile = "time_budget"

var tbRe = regexp.MustCompile(`(?i)\bbudget:(off|(\d+)([smh]?))\b`)

func (timeBudget) Name() string { return "time_budget" }
func (timeBudget) Events() []string {
	return []string{"UserPromptSubmit", "PostToolUse", "PostToolUseFailure"}
}

func tbClear(st *state.Store) {
	st.Update(tbFile, func([]byte) []byte { return []byte{} }) // empty file = no budget
}

func (timeBudget) Apply(ctx context.Context, in *hook.Input, _ *config.Config, st *state.Store) *hook.Decision {
	if ctx.Err() != nil {
		return nil
	}
	if in.HookEventName == "UserPromptSubmit" {
		if promptInjected(in.Prompt) {
			return nil
		}
		m := tbRe.FindStringSubmatch(in.Prompt)
		if m == nil {
			return nil
		}
		if strings.EqualFold(m[1], "off") {
			tbClear(st)
			return nil
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return nil
		}
		unit := map[string]int{"": 60, "s": 1, "m": 60, "h": 3600}[strings.ToLower(m[3])]
		budget := n * unit
		if st.Write(tbFile, fmt.Appendf(nil, "%d %d", tbNow().Unix(), budget)) != nil {
			return nil
		}
		return &hook.Decision{AdditionalContext: fmt.Sprintf("Time budget for this task: %ds. Elapsed time is appended after each tool "+
			"result as `elapsed Xs / %ds`. Pace the work to finish inside it; run "+
			"independent units in parallel rather than in sequence.", budget, budget)}
	}
	b, _ := st.Read(tbFile)
	var start, budget int64
	if _, err := fmt.Sscanf(string(b), "%d %d", &start, &budget); err != nil {
		return nil
	}
	elapsed := tbNow().Unix() - start
	if elapsed > 2*budget {
		tbClear(st)
		return nil
	}
	return &hook.Decision{AdditionalContext: fmt.Sprintf("elapsed %ds / %ds", elapsed, budget)}
}
