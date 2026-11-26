package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// sessionNotice adds context at SessionStart: the configured startup line,
// the post-compaction line, the cold-resume warning, and one line per
// enabled integration.
type sessionNotice struct{}

func init() { Registry = append(Registry, sessionNotice{}) }

func (sessionNotice) Name() string     { return "session_notice" }
func (sessionNotice) Events() []string { return []string{"SessionStart"} }

func (sessionNotice) Apply(_ context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	sn := cfg.Rules.SessionNotice
	var lines []string
	add := func(l string) {
		if l != "" {
			lines = append(lines, l)
		}
	}
	add(sn.Startup)
	switch in.Source {
	case "compact":
		if cfg.Mode("checkpoint") != "enforce" { // in enforce the checkpoint rule owns this prose
			add(sn.PostCompact)
		}
		// `claude-policy mine` mined this transcript into the same wing just before compaction.
		if wing := cfg.Integrations.Mempalace.Wing(in.TranscriptPath); wing != "" {
			add(fmt.Sprintf("[MEMPALACE] Pre-compaction transcript is mined into wing `%s`. When the summary lacks exact wording, commands, error text or a decision rationale, palace_query that wing before re-deriving or asking.", wing))
		}
	case "resume", "fork":
		add(coldResume(in.Raw, sn.ColdResumeUSDWarn))
	}
	if n := cfg.Integrations.Herdr.Notice; n != "" && os.Getenv("HERDR_ENV") == "1" {
		pane := os.Getenv("HERDR_PANE_ID")
		if pane == "" {
			pane = "unknown"
		}
		add(strings.ReplaceAll(n, "{pane}", pane))
	}
	if len(lines) == 0 {
		return nil
	}
	return &hook.Decision{AdditionalContext: strings.Join(lines, "\n")}
}

// coldResume returns the [COLD-RESUME] line, or "" when the payload lacks
// estimated_cache_write_usd or it is under warn.
func coldResume(raw json.RawMessage, warn float64) string {
	var p struct {
		USD     *float64 `json:"estimated_cache_write_usd"`
		Tokens  *float64 `json:"context_tokens"`
		Expired *bool    `json:"prompt_cache_likely_expired"`
	}
	if json.Unmarshal(raw, &p) != nil || p.USD == nil || *p.USD < warn || p.Expired != nil && !*p.Expired {
		return ""
	}
	tokens := ""
	if p.Tokens != nil {
		tokens = fmt.Sprintf(" ~%.0f tokens", *p.Tokens)
	}
	return fmt.Sprintf("[COLD-RESUME] Prompt cache likely expired: this resume re-writes%s at cache-write price (est. $%.2f). If little work remains, /clear and restart with a narrow brief.", tokens, *p.USD)
}
