package rules

import (
	"context"
	"encoding/json"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// exploreModel fills in Explore's missing model parameter. An explicit model
// is never overwritten. No Permission: an allow would skip the user's
// permission flow, so hook.Merge drops the reason (accepted). Under auto
// mode it denies with the model to pass instead of rewriting.
type exploreModel struct{}

func init() { Registry = append(Registry, exploreModel{}) }

func (exploreModel) Name() string     { return "explore_model" }
func (exploreModel) Events() []string { return []string{"PreToolUse"} }
func (exploreModel) Tools() []string  { return []string{"Agent", "Task"} }

func (exploreModel) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	var ti map[string]json.RawMessage
	if json.Unmarshal(in.ToolInput, &ti) != nil || ti == nil { // non-object or null
		return nil
	}
	var sub, model string
	_ = json.Unmarshal(ti["subagent_type"], &sub)
	_ = json.Unmarshal(ti["model"], &model)
	if sub != "Explore" || model != "" {
		return nil
	}
	if raw, present := ti["model"]; present && string(raw) != `""` && string(raw) != "null" {
		return nil // explicit non-string model: leave as written
	}
	m, err := json.Marshal(cfg.Rules.ExploreModel.DefaultModel)
	if err != nil {
		return nil
	}
	if in.PermissionMode == "auto" {
		// auto mode's classifier returns no verdict on a hook-rewritten Agent
		// call and refuses it; deny instead so the model reissues it unchanged.
		return &hook.Decision{
			Permission: "deny",
			Reason:     "Explore needs an explicit model under auto mode; reissue the call with model: " + string(m),
		}
	}
	ti["model"] = m
	out, err := json.Marshal(ti)
	if err != nil {
		return nil
	}
	return &hook.Decision{
		Reason:       "Explore spawned without a model; defaulted to " + cfg.Rules.ExploreModel.DefaultModel,
		UpdatedInput: out,
	}
}
