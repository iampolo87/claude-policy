package rules

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// piiEgress asks before a Bash, Monitor, WebFetch or WebSearch call carries the
// user's account email (or a configured needle) to the outside, e.g. in a
// User-Agent header (anthropics/claude-code#107757). Bash is matched whole:
// a local command naming the email, or reading it from where it is stored
// (emailSources), asks too, which the user can approve.
// ponytail: plain and percent-encoded text only; base64, hex or shell
// concatenation ('a”@b') pass.
type piiEgress struct{}

func init() { Registry = append(Registry, piiEgress{}) }

func (piiEgress) Name() string     { return "pii_egress" }
func (piiEgress) Events() []string { return []string{"PreToolUse"} }
func (piiEgress) Tools() []string  { return []string{"Bash", "Monitor", "WebFetch", "WebSearch"} }

// emailSources name where a command would read the address at run time.
var emailSources = []string{"user.email", "oauthaccount", "emailaddress", ".claude.json"}

func (piiEgress) Apply(_ context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	var v any
	if json.Unmarshal(in.ToolInput, &v) != nil {
		return nil
	}
	if _, ok := v.(map[string]any); !ok {
		return nil
	}
	var b strings.Builder
	collectStrings(v, &b)
	hay := strings.ToLower(b.String())
	cur := hay
	for range 3 { // %2540 is %40 escaped again
		cur = pctDecode(cur)
		hay += "\n" + cur
	}
	needles := slices.Concat(cfg.Rules.PIIEgress.Needles, []string{accountEmail()})
	if in.ToolName == "Bash" || in.ToolName == "Monitor" {
		needles = append(needles, emailSources...)
	}
	for _, n := range needles {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" && strings.Contains(hay, n) {
			return &hook.Decision{
				Permission: "ask",
				Reason: "pii_egress: this call contains or reads the user's personal data (account email or a configured needle) " +
					"and may send it outside. Drop it (a generic client name in any User-Agent) unless the user asked for it.",
			}
		}
	}
	return nil
}

// pctDecode decodes every valid %XX escape and keeps anything else as is.
func pctDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b.WriteByte(v[0])
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return strings.ToLower(b.String())
}

// collectStrings appends every string value under v, one per line.
func collectStrings(v any, b *strings.Builder) {
	switch t := v.(type) {
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	case map[string]any:
		for _, e := range t {
			collectStrings(e, b)
		}
	case []any:
		for _, e := range t {
			collectStrings(e, b)
		}
	}
}

// accountEmail is oauthAccount.emailAddress from Claude Code's .claude.json
// ($CLAUDE_CONFIG_DIR, else HOME); "" when unreadable.
func accountEmail() string {
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		dir, _ = os.UserHomeDir()
	}
	data, err := os.ReadFile(filepath.Join(dir, ".claude.json"))
	if err != nil {
		return ""
	}
	var c struct {
		OAuthAccount struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	_ = json.Unmarshal(data, &c)
	return c.OAuthAccount.EmailAddress
}
