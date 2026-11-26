package hook

import (
	"encoding/json"
	"testing"
)

func marshal(t *testing.T, o Output) string {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMergeNoOpinionIsEmptyObject(t *testing.T) {
	for _, ds := range [][]*Decision{nil, {nil, nil}, {{}}} {
		if got := marshal(t, Merge("PreToolUse", "Bash", ds)); got != "{}" {
			t.Fatalf("got %s, want {}", got)
		}
	}
}

func TestMergePermissionPrecedence(t *testing.T) {
	cases := []struct {
		ds        []*Decision
		perm, why string
	}{
		{[]*Decision{{Permission: "allow", Reason: "a"}, {Permission: "ask", Reason: "b"}}, "ask", "b"},
		{[]*Decision{{Permission: "ask", Reason: "b"}, {Permission: "defer", Reason: "c"}}, "defer", "c"},
		{[]*Decision{{Permission: "deny", Reason: "d1"}, {Permission: "defer"}, {Permission: "deny", Reason: "d2"}, {Permission: "allow", Reason: "x"}}, "deny", "d1\nd2"},
		{[]*Decision{{Permission: "bogus", Reason: "z"}, {Permission: "allow", Reason: "a"}}, "allow", "a"},
	}
	for i, c := range cases {
		o := Merge("PreToolUse", "Agent", c.ds)
		if o.HookSpecificOutput == nil || o.HookSpecificOutput.PermissionDecision != c.perm || o.HookSpecificOutput.PermissionDecisionReason != c.why {
			t.Fatalf("case %d: got %s", i, marshal(t, o))
		}
		if o.HookSpecificOutput.HookEventName != "PreToolUse" {
			t.Fatalf("case %d: missing hookEventName", i)
		}
	}
}

func TestMergeUpdatedInput(t *testing.T) {
	ds := []*Decision{
		{UpdatedInput: json.RawMessage(`{"model":"haiku"}`)},
		{UpdatedInput: json.RawMessage(`{"model":"opus"}`)},
	}
	if got := marshal(t, Merge("PreToolUse", "Agent", ds)); got != `{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{"model":"haiku"}}}` {
		t.Fatalf("first updatedInput must win, got %s", got)
	}
	for _, tool := range []string{"Bash", "Read"} {
		if got := marshal(t, Merge("PreToolUse", tool, ds)); got != "{}" {
			t.Fatalf("%s: updatedInput must be dropped, got %s", tool, got)
		}
	}
	bad := []*Decision{{UpdatedInput: json.RawMessage(`{nope`)}}
	if got := marshal(t, Merge("PreToolUse", "Agent", bad)); got != "{}" {
		t.Fatalf("invalid updatedInput must be dropped, got %s", got)
	}
	if got := marshal(t, Merge("PostToolUse", "Agent", ds)); got != "{}" {
		t.Fatalf("updatedInput outside PreToolUse must be dropped, got %s", got)
	}
	for _, raw := range []string{`null`, `[1]`, `"x"`, `3`} {
		ds := []*Decision{{Permission: "deny", UpdatedInput: json.RawMessage(raw)}}
		if got := marshal(t, Merge("PreToolUse", "Agent", ds)); got != `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}` {
			t.Fatalf("non-object updatedInput %s must be dropped, got %s", raw, got)
		}
	}
}

func TestMergeContextAndBlock(t *testing.T) {
	ds := []*Decision{{AdditionalContext: "one"}, nil, {AdditionalContext: "two"}}
	if got := marshal(t, Merge("SessionStart", "", ds)); got != `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"one\n\ntwo"}}` {
		t.Fatalf("got %s", got)
	}
	ds = []*Decision{{AdditionalContext: "ctx"}, {Block: true, Reason: "r1"}, {Block: true, Reason: "r2"}, {Permission: "deny"}}
	got := marshal(t, Merge("Stop", "", ds))
	if got != `{"decision":"block","reason":"r1\nr2","hookSpecificOutput":{"hookEventName":"Stop","additionalContext":"ctx"}}` {
		t.Fatalf("got %s", got)
	}
	if got := marshal(t, Merge("PreToolUse", "Bash", []*Decision{{Block: true, Reason: "x"}})); got != "{}" {
		t.Fatalf("block on PreToolUse must be ignored, got %s", got)
	}
	for _, ev := range []string{"SessionEnd", "PreCompact", "PostCompact"} {
		if got := marshal(t, Merge(ev, "", []*Decision{{AdditionalContext: "ctx"}})); got != "{}" {
			t.Fatalf("%s has no hookSpecificOutput, got %s", ev, got)
		}
	}
}

func TestParse(t *testing.T) {
	in, err := Parse([]byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s","stop_hook_active":true,"extra":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if in.HookEventName != "PreToolUse" || in.ToolName != "Bash" || string(in.ToolInput) != `{"command":"ls"}` || !in.StopHookActive || len(in.Raw) == 0 {
		t.Fatalf("bad parse: %+v", in)
	}
	for _, bad := range []string{"", "garbage", `"str"`, `[1]`, `7`, `{"session_id":"s"`} {
		if in, err := Parse([]byte(bad)); in != nil || err == nil {
			t.Fatalf("Parse(%q) must fail", bad)
		}
	}
}

// One field with an unexpected type must not cost every rule its input.
func TestParseLenient(t *testing.T) {
	in, err := Parse([]byte(`{"permission_mode":7,"session_id":"s","tool_name":["x"],"hook_event_name":"PreToolUse","stop_hook_active":"yes","tool_input":{"command":"ls"}}`))
	if in == nil || err == nil {
		t.Fatalf("want an Input plus the field error, got %v, %v", in, err)
	}
	if in.PermissionMode != "" || in.ToolName != "" || in.StopHookActive ||
		in.SessionID != "s" || in.HookEventName != "PreToolUse" || string(in.ToolInput) != `{"command":"ls"}` {
		t.Fatalf("bad parse: %+v", in)
	}
}

func TestMergeUpdatedToolOutputPostToolUseOnly(t *testing.T) {
	ds := []*Decision{{UpdatedToolOutput: json.RawMessage(`{bad`)}, {UpdatedToolOutput: json.RawMessage(`{"stdout":"a"}`)}, {UpdatedToolOutput: json.RawMessage(`{"stdout":"b"}`)}}
	want := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"stdout":"a"}}}`
	if got := marshal(t, Merge("PostToolUse", "Bash", ds)); got != want {
		t.Fatalf("got %s", got)
	}
	if got := marshal(t, Merge("PreToolUse", "Bash", ds)); got != "{}" {
		t.Fatalf("PreToolUse got %s", got)
	}
	b, _ := json.Marshal(ds[1])
	if string(b) != "{}" {
		t.Fatalf("decision log leaks tool output: %s", b)
	}
}
