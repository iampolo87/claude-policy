package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
)

func notice(t *testing.T, payload string) string {
	t.Helper()
	in, err := hook.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	d := sessionNotice{}.Apply(context.Background(), in, suiteCfg(), nil)
	if d == nil || d.Hard {
		t.Fatalf("bad decision %+v", d)
	}
	return d.AdditionalContext
}

func TestSessionNotice(t *testing.T) {
	cases := []struct {
		name, env, pane, payload string
		has, not                 []string
	}{
		{"startup", "", "", `{"source":"startup"}`, []string{"[NOTICE]"}, []string{"[POST-COMPACT]", "[HERDR]", "[COLD-RESUME]"}},
		{"compact wing", "", "", `{"source":"compact","transcript_path":"/h/.claude/projects/-work-user-projects-claude-policy/x.jsonl"}`,
			[]string{"[POST-COMPACT]", "wing `claude-policy`"}, nil},
		{"compact no wing", "", "", `{"source":"compact","transcript_path":"/h/.claude/projects/other/x.jsonl"}`,
			[]string{"[POST-COMPACT]"}, []string{"[MEMPALACE]"}},
		{"resume over", "", "", `{"source":"resume","estimated_cache_write_usd":0.5,"context_tokens":120000}`,
			[]string{"[COLD-RESUME] Prompt cache likely expired: this resume re-writes ~120000 tokens at cache-write price (est. $0.50). If little work remains, /clear and restart with a narrow brief."}, nil},
		{"resume under", "", "", `{"source":"resume","estimated_cache_write_usd":0.49,"context_tokens":1}`, nil, []string{"[COLD-RESUME]"}},
		{"resume absent", "", "", `{"source":"resume"}`, nil, []string{"[COLD-RESUME]"}},
		{"resume no tokens", "", "", `{"source":"resume","estimated_cache_write_usd":1.234}`, []string{"re-writes at cache-write price (est. $1.23)"}, []string{"tokens at"}},
		{"cache warm", "", "", `{"source":"resume","estimated_cache_write_usd":2,"prompt_cache_likely_expired":false}`, nil, []string{"[COLD-RESUME]"}},
		{"cache expired", "", "", `{"source":"resume","estimated_cache_write_usd":2,"prompt_cache_likely_expired":true}`, []string{"[COLD-RESUME]"}, nil},
		{"compact empty wing", "", "", `{"source":"compact","transcript_path":"/h/.claude/projects/-work-user-projects-/x.jsonl"}`,
			[]string{"[POST-COMPACT]"}, []string{"[MEMPALACE]"}},
		{"fork", "", "", `{"source":"fork","estimated_cache_write_usd":2,"context_tokens":5}`, []string{"[COLD-RESUME]", "~5 tokens", "$2.00"}, nil},
		{"startup ignores cost", "", "", `{"source":"startup","estimated_cache_write_usd":9}`, nil, []string{"[COLD-RESUME]"}},
		{"herdr on", "1", "p7", `{"source":"startup"}`, []string{"[HERDR] Inside herdr (pane p7);"}, nil},
		{"herdr no pane", "1", "", `{"source":"startup"}`, []string{"(pane unknown)"}, nil},
		{"herdr off", "0", "p7", `{"source":"startup"}`, nil, []string{"[HERDR]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("HERDR_ENV", c.env)
			t.Setenv("HERDR_PANE_ID", c.pane)
			got := notice(t, c.payload)
			for _, s := range c.has {
				if !strings.Contains(got, s) {
					t.Errorf("missing %q in %q", s, got)
				}
			}
			for _, s := range c.not {
				if strings.Contains(got, s) {
					t.Errorf("unexpected %q in %q", s, got)
				}
			}
		})
	}
}

func TestSessionNoticeCompactEnforceOmitsProse(t *testing.T) {
	t.Setenv("HERDR_ENV", "")
	in, _ := hook.Parse([]byte(`{"source":"compact","transcript_path":"/h/.claude/projects/-work-user-projects-claude-policy/x.jsonl"}`))
	cfg := suiteCfg()
	cfg.Rules.Checkpoint.Mode = "enforce"
	got := sessionNotice{}.Apply(context.Background(), in, cfg, nil).AdditionalContext
	if strings.Contains(got, "[POST-COMPACT]") || !strings.Contains(got, "[MEMPALACE]") {
		t.Fatalf("got %q", got)
	}
}

// With nothing configured the rule has nothing to say: no startup line, no
// integration line, and the post-compaction line only after a compaction.
func TestSessionNoticeDefaults(t *testing.T) {
	t.Setenv("HERDR_ENV", "1")
	t.Setenv("HERDR_PANE_ID", "p7")
	for payload, want := range map[string]string{
		`{"source":"startup"}`: "",
		`{"source":"compact","transcript_path":"/h/.claude/projects/-work-user-projects-claude-policy/x.jsonl"}`: noticePostCompact,
	} {
		in, _ := hook.Parse([]byte(payload))
		d := sessionNotice{}.Apply(context.Background(), in, config.Defaults(), nil)
		if got := ""; d != nil {
			got = d.AdditionalContext
			if got != want {
				t.Errorf("%s: got %q want %q", payload, got, want)
			}
		} else if want != "" {
			t.Errorf("%s: got nil want %q", payload, want)
		}
	}
}
