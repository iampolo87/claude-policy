// Package hook holds the Claude Code hook envelope types and the merge of
// rule decisions into the one JSON object a hook call prints.
package hook

import (
	"encoding/json"
	"errors"
	"strings"
)

// Input is the stdin envelope common to every hook event. Fields whose shape
// depends on the tool stay raw; Raw keeps the whole envelope for fields not
// modelled here. Rules must treat it as read-only.
type Input struct {
	SessionID            string          `json:"session_id"`
	TranscriptPath       string          `json:"transcript_path"`
	Cwd                  string          `json:"cwd"`
	HookEventName        string          `json:"hook_event_name"`
	PermissionMode       string          `json:"permission_mode"`
	AgentID              string          `json:"agent_id"`
	AgentType            string          `json:"agent_type"`
	AgentTranscriptPath  string          `json:"agent_transcript_path"`
	ToolName             string          `json:"tool_name"`
	ToolInput            json.RawMessage `json:"tool_input"`
	ToolResponse         json.RawMessage `json:"tool_response"`
	ToolUseID            string          `json:"tool_use_id"`
	Source               string          `json:"source"`
	StopHookActive       bool            `json:"stop_hook_active"`
	LastAssistantMessage string          `json:"last_assistant_message"`
	Trigger              string          `json:"trigger"`
	CompactSummary       string          `json:"compact_summary"`
	Prompt               string          `json:"prompt"`
	ScratchpadDir        string          `json:"scratchpad_dir"`
	Error                string          `json:"error"`        // PostToolUseFailure
	IsInterrupt          bool            `json:"is_interrupt"` // PostToolUseFailure
	Raw                  json.RawMessage `json:"-"`
}

// Parse decodes a hook envelope. Anything that is not a JSON object returns
// a nil Input (the caller then prints "{}"). A field with an unexpected type
// stays zero and the rest still parse: encoding/json skips that field, keeps
// decoding and reports it as an UnmarshalTypeError naming the field, which
// Parse returns beside a usable Input.
func Parse(b []byte) (*Input, error) {
	in := &Input{}
	err := json.Unmarshal(b, in)
	if err != nil {
		var te *json.UnmarshalTypeError
		if !errors.As(err, &te) || te.Field == "" { // Field "" = the envelope itself is not an object
			return nil, err
		}
	}
	in.Raw = b
	return in, err
}

// Decision is what a rule returns; nil means no opinion.
type Decision struct {
	// Permission is allow|deny|ask|defer; PreToolUse only.
	Permission string `json:"permission,omitempty"`
	// Reason is the permissionDecisionReason (PreToolUse) or the block
	// reason (every other event).
	Reason string `json:"reason,omitempty"`
	// UpdatedInput fully replaces tool_input; PreToolUse only, never for
	// Bash or Read (other hooks may own those).
	UpdatedInput      json.RawMessage `json:"updated_input,omitempty"`
	AdditionalContext string          `json:"additional_context,omitempty"`
	// Block emits top-level decision:"block" (Stop, SubagentStop, …); not
	// PreToolUse, which uses Permission.
	Block bool `json:"block,omitempty"`
	// UpdatedToolOutput replaces the tool result the model sees; PostToolUse
	// only. Kept out of decisions.jsonl (it can be ~8k chars).
	UpdatedToolOutput json.RawMessage `json:"-"`
	// Private logs AdditionalContext as its length only: it carries prompt
	// and command text that must not outlive the session dir.
	Private bool `json:"-"`
	// Hard makes the runner apply the decision even when the rule is in log
	// mode (destructive hard_deny). An off rule never runs.
	Hard bool `json:"hard,omitempty"`
	// CharsIn/CharsOut are output_cap's result size before and after the
	// cap (log mode: the cap it would apply). Logged only.
	CharsIn  int `json:"chars_in,omitempty"`
	CharsOut int `json:"chars_out,omitempty"`
}

// Output is the stdout JSON. The zero value marshals to "{}".
type Output struct {
	Decision           string          `json:"decision,omitempty"`
	Reason             string          `json:"reason,omitempty"`
	HookSpecificOutput *SpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type SpecificOutput struct {
	HookEventName            string          `json:"hookEventName"`
	PermissionDecision       string          `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string          `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             json.RawMessage `json:"updatedInput,omitempty"`
	AdditionalContext        string          `json:"additionalContext,omitempty"`
	UpdatedToolOutput        json.RawMessage `json:"updatedToolOutput,omitempty"`
}

var permissionRank = map[string]int{"allow": 1, "ask": 2, "defer": 3, "deny": 4}

// contextEvents accept hookSpecificOutput (see README, Hook API facts); for
// any other event additionalContext is dropped so the output stays valid.
var contextEvents = map[string]bool{
	"PreToolUse": true, "PostToolUse": true, "PostToolUseFailure": true, "UserPromptSubmit": true,
	"SessionStart": true, "SubagentStart": true, "Stop": true, "SubagentStop": true,
}

// Merge folds decisions (in registry order) into one Output:
// deny > defer > ask > allow keeping the reasons of the winning level,
// additionalContext concatenated, the first valid updatedInput wins (dropped
// for Bash/Read), any block wins with its reasons concatenated.
func Merge(event, tool string, ds []*Decision) Output {
	pre := event == "PreToolUse"
	var (
		rank                   int
		perm                   string
		permWhy, blockWhy, ctx []string
		updated, toolOut       json.RawMessage
		block                  bool
	)
	for _, d := range ds {
		if d == nil {
			continue
		}
		if d.AdditionalContext != "" && contextEvents[event] {
			ctx = append(ctx, d.AdditionalContext)
		}
		if !pre {
			if event == "PostToolUse" && toolOut == nil && len(d.UpdatedToolOutput) > 0 && json.Valid(d.UpdatedToolOutput) {
				toolOut = d.UpdatedToolOutput
			}
			if d.Block {
				block = true
				if d.Reason != "" {
					blockWhy = append(blockWhy, d.Reason)
				}
			}
			continue
		}
		if r := permissionRank[d.Permission]; r > rank {
			rank, perm, permWhy = r, d.Permission, nil
		}
		if r := permissionRank[d.Permission]; r > 0 && r == rank && d.Reason != "" {
			permWhy = append(permWhy, d.Reason)
		}
		// updatedInput replaces tool_input, so only a JSON object is valid.
		if updated == nil && tool != "Bash" && tool != "Read" &&
			strings.HasPrefix(strings.TrimSpace(string(d.UpdatedInput)), "{") && json.Valid(d.UpdatedInput) {
			updated = d.UpdatedInput
		}
	}

	var o Output
	if block {
		o.Decision, o.Reason = "block", strings.Join(blockWhy, "\n")
	}
	if perm != "" || updated != nil || toolOut != nil || len(ctx) > 0 {
		o.HookSpecificOutput = &SpecificOutput{
			HookEventName:            event,
			PermissionDecision:       perm,
			PermissionDecisionReason: strings.Join(permWhy, "\n"),
			UpdatedInput:             updated,
			AdditionalContext:        strings.Join(ctx, "\n\n"),
			UpdatedToolOutput:        toolOut,
		}
	}
	return o
}
