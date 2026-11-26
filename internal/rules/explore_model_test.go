package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/hook"
)

func applyExplore(tool, ti, model string) *hook.Decision {
	cfg := suiteCfg()
	if model != "" {
		cfg.Rules.ExploreModel.DefaultModel = model
	}
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: tool, ToolInput: json.RawMessage(ti)}
	return exploreModel{}.Apply(context.Background(), in, cfg, nil)
}

func TestExploreModel(t *testing.T) {
	const noModel = `{"description":"d","subagent_type":"Explore","extra":{"a":[1,2]}}`
	for _, tool := range []string{"Agent", "Task"} {
		d := applyExplore(tool, noModel, "")
		if d == nil || d.Permission != "" || d.Reason == "" {
			t.Fatalf("%s: decision %+v", tool, d)
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal(d.UpdatedInput, &got); err != nil {
			t.Fatal(err)
		}
		if string(got["model"]) != `"haiku"` || string(got["extra"]) != `{"a":[1,2]}` || string(got["description"]) != `"d"` || len(got) != 4 {
			t.Fatalf("%s: %s", tool, d.UpdatedInput)
		}
	}
	if d := applyExplore("Agent", `{"subagent_type":"Explore","model":""}`, ""); d == nil {
		t.Fatal("empty model must be filled")
	}
	if d := applyExplore("Agent", noModel, "sonnet"); d == nil || !strings.Contains(string(d.UpdatedInput), `"model":"sonnet"`) {
		t.Fatalf("cfg model: %+v", d)
	}
	// auto mode's classifier cannot judge a rewritten call: deny with the fix instead.
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: "Agent", PermissionMode: "auto", ToolInput: json.RawMessage(noModel)}
	if d := (exploreModel{}).Apply(context.Background(), in, suiteCfg(), nil); d == nil || d.Permission != "deny" ||
		d.UpdatedInput != nil || !strings.Contains(d.Reason, `model: "haiku"`) {
		t.Fatalf("auto mode: %+v", d)
	}
	for _, c := range []string{
		`{"subagent_type":"Explore","model":"opus"}`,
		`{"subagent_type":"Plan"}`,
		`{"description":"x"}`,
		`[1]`, `"x"`, `null`, ``,
	} {
		if d := applyExplore("Agent", c, ""); d != nil {
			t.Fatalf("%s: want nil, got %+v", c, d)
		}
	}
}
