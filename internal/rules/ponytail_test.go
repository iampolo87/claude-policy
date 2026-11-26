package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
)

func ponytailRun(t *testing.T, tool string, ti map[string]any, level string, env string) *hook.Decision {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PONYTAIL_OFF", env)
	if level != "" {
		os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
		os.WriteFile(filepath.Join(home, ".claude", ".ponytail-mode"), []byte(level), 0o644)
	}
	raw, _ := json.Marshal(ti)
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: tool, ToolInput: raw}
	return ponytail{}.Apply(context.Background(), in, suiteCfg(), nil)
}

func TestPonytailPort(t *testing.T) {
	deb := map[string]any{"content": "function debounce(fn){}"}
	cases := []struct {
		name  string
		tool  string
		ti    map[string]any
		level string
		env   string
		deny  bool
	}{
		{"debounce denies", "Write", deb, "full", "", true},
		{"normal allows", "Write", map[string]any{"content": "export const sum=(a,b)=>a+b"}, "full", "", false},
		{"override comment", "Write", map[string]any{"content": "// ponytail-allow: vendored\nfunction debounce(fn){}"}, "full", "", false},
		{"PONYTAIL_OFF", "Write", deb, "full", "1", false},
		{"level off", "Write", deb, "off", "", false},
		{"edit throttle", "Edit", map[string]any{"new_string": "const throttle = (fn)=>{}"}, "full", "", true},
		{"missing file defaults full", "Write", deb, "", "", true},
		{"ultra denies", "Write", deb, "ultra", "", true},
		{"lite allows", "Write", deb, "lite", "", false},
		{"invalid level defaults full", "Write", deb, "bogus", "", true},
		{"level case/whitespace", "Write", deb, " OFF\n", "", false},
		{"multiedit", "MultiEdit", map[string]any{"edits": []map[string]any{{"new_string": "x"}, {"new_string": "FUNCTION Debounce"}, {"new_string": "function debounce(){}"}}}, "full", "", true},
		{"multiedit clean", "MultiEdit", map[string]any{"edits": []map[string]any{{"new_string": "x"}}}, "full", "", false},
		{"edit ignores old_string", "Edit", map[string]any{"old_string": "function debounce(){}", "new_string": "x"}, "full", "", false},
		{"empty content", "Write", map[string]any{"content": ""}, "full", "", false},
		{"case-insensitive", "Write", map[string]any{"content": "MATH.random().toString(36)"}, "full", "", true},
	}
	for _, c := range cases {
		d := ponytailRun(t, c.tool, c.ti, c.level, c.env)
		if got := d != nil && d.Permission == "deny"; got != c.deny {
			t.Errorf("%s: deny=%v want %v (%+v)", c.name, got, c.deny, d)
		}
		if d != nil && (d.Hard || d.UpdatedInput != nil) {
			t.Errorf("%s: Hard/UpdatedInput set", c.name)
		}
	}
}

func TestPonytailReasonAndBadRegex(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PONYTAIL_OFF", "")
	cfg := suiteCfg()
	cfg.Rules.Ponytail.Signatures = append([]config.Signature{{Label: "bad", Regex: "(", Hint: "h"}}, cfg.Rules.Ponytail.Signatures...)
	raw, _ := json.Marshal(map[string]any{"content": "function debounce(){} function throttle(){}"})
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: "Write", ToolInput: raw}
	d := ponytail{}.Apply(context.Background(), in, cfg, nil)
	if d == nil {
		t.Fatal("nil decision")
	}
	want := "Ponytail gate: [debounce] debounce exists (lodash / 3-line native); don't reinvent; [throttle] throttle exists (lodash); don't reinvent. Override: add `ponytail-allow: <reason>` in the code, set PONYTAIL_OFF=1, or set ~/.claude/.ponytail-mode to off/lite."
	if d.Reason != want || strings.Contains(d.Reason, "bad") {
		t.Errorf("reason = %q", d.Reason)
	}
}
