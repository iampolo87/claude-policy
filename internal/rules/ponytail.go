package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// ponytail denies new code that reinvents a stdlib/native solution. Level:
// off, lite (allow, warn on stderr), full/ultra (deny). It is full unless
// [rules.ponytail] level_file names a file saying otherwise; a missing or
// invalid file means full.
type ponytail struct{}

func init() { Registry = append(Registry, ponytail{}) }

func (ponytail) Name() string     { return "ponytail" }
func (ponytail) Events() []string { return []string{"PreToolUse"} }
func (ponytail) Tools() []string  { return []string{"Write", "Edit", "MultiEdit"} }

func ponytailLevel(file string) string {
	if file == "~" || strings.HasPrefix(file, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "full"
		}
		file = filepath.Join(home, file[1:])
	}
	if file == "" {
		return "full"
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "full"
	}
	switch m := strings.ToLower(strings.TrimSpace(string(b))); m {
	case "off", "lite", "full", "ultra":
		return m
	}
	return "full"
}

func (ponytail) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	level := ponytailLevel(cfg.Rules.Ponytail.LevelFile)
	if level == "off" || os.Getenv("PONYTAIL_OFF") == "1" {
		return nil
	}
	var ti struct {
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		Edits     []struct {
			NewString string `json:"new_string"`
		} `json:"edits"`
	}
	if json.Unmarshal(in.ToolInput, &ti) != nil {
		return nil
	}
	var code string
	switch in.ToolName {
	case "Write":
		code = ti.Content
	case "Edit":
		code = ti.NewString
	case "MultiEdit":
		parts := make([]string, len(ti.Edits))
		for i, e := range ti.Edits {
			parts[i] = e.NewString
		}
		code = strings.Join(parts, "\n")
	}
	if code == "" || strings.Contains(code, "ponytail-allow") {
		return nil
	}
	var hits []string
	for _, s := range cfg.Rules.Ponytail.Signatures {
		if ctx.Err() != nil {
			return nil
		}
		rx, err := regexp.Compile("(?i)" + s.Regex)
		if err != nil {
			continue
		}
		if rx.MatchString(code) {
			hits = append(hits, "["+s.Label+"] "+s.Hint)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	reason := "Ponytail gate: " + strings.Join(hits, "; ") +
		". Override: add `ponytail-allow: <reason>` in the code"
	if f := cfg.Rules.Ponytail.LevelFile; f != "" {
		reason += ", set PONYTAIL_OFF=1, or set " + f + " to off/lite."
	} else {
		reason += " or set PONYTAIL_OFF=1."
	}
	if level == "lite" { // warn, allow
		os.Stderr.WriteString(reason + "\n")
		return nil
	}
	return &hook.Decision{Permission: "deny", Reason: reason}
}
