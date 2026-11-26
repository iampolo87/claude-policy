package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// checkpoint keeps a small record of the session (edited files, prompts,
// commands, Risk line), writes it to disk at PreCompact and re-injects it at
// SessionStart(compact). Apply is mode-agnostic: the runner decides whether
// the injected context is kept (enforce) or only logged. Every step fails open.
type checkpoint struct{}

func init() { Registry = append(Registry, checkpoint{}) }

const (
	cpEdits    = "checkpoint.edits"
	cpCommands = "checkpoint.commands"
	cpPrompts  = "checkpoint.prompts"
	cpRisk     = "checkpoint.risk"

	cpMaxEdits    = 200
	cpMaxCommands = 10
	cpMaxPrompts  = 3
	cpCmdChars    = 200
	cpPromptChars = 1000
	// 2k headroom: session_notice's lines join the same SessionStart
	// additionalContext and CC spills hook values >10k chars.
	cpMaxFile      = 8000
	cpTruncMarker  = "\n… (truncated)\n"
	cpWorkChars    = 2500
	cpGitBudget    = 400 * time.Millisecond
	cpWorkBudget   = 400 * time.Millisecond
	cpTSLayout     = "20060102T150405.000000000Z"
	cpFilePrefix   = "checkpoint-"
	cpConsumedSufx = ".consumed"
)

func (checkpoint) Name() string { return "checkpoint" }
func (checkpoint) Events() []string {
	return []string{"PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "Stop", "PreCompact", "PostCompact", "SessionStart"}
}

// No Tools(): the runner would filter Stop (empty tool_name) out too.
func (checkpoint) Timeout() time.Duration { return time.Second }

var (
	cpEditTools = []string{"Edit", "Write", "MultiEdit", "NotebookEdit"}
	cpExitRe    = regexp.MustCompile(`^\s*Exit code (\d+)`)
)

type cpCommand struct {
	Cmd  string `json:"cmd"`
	Exit string `json:"exit"`
}

func (checkpoint) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision {
	if ctx.Err() != nil || st == nil {
		return nil
	}
	main := in.AgentID == ""
	switch in.HookEventName {
	case "PostToolUse", "PostToolUseFailure":
		cpRecordTool(in, st, main)
	case "UserPromptSubmit":
		if main {
			cpRecordPrompt(in, st)
		}
	case "Stop":
		if main {
			cpRecordRisk(in, st)
		}
	case "PreCompact":
		if main {
			cpWrite(ctx, in, cfg, st)
		}
	case "PostCompact":
		if main {
			cpPostCompact(in, cfg, st)
		}
	case "SessionStart":
		if main && in.Source == "compact" {
			return cpInject(st, cfg.Mode("checkpoint") == "enforce", cfg.Rules.SessionNotice.PostCompact, cfg.Integrations.ClaudeMem.WorkStateURL != "")
		}
	}
	return nil
}

// cpPush appends line to a newline-separated file, keeping the newest max.
// dedupe moves an existing equal line to the end.
func cpPush(st *state.Store, name, line string, max int, dedupe bool) {
	st.Update(name, func(old []byte) []byte {
		var ls []string
		for _, l := range strings.Split(string(old), "\n") {
			if l != "" && !(dedupe && l == line) {
				ls = append(ls, l)
			}
		}
		ls = append(ls, line)
		if len(ls) > max {
			ls = ls[len(ls)-max:]
		}
		return []byte(strings.Join(ls, "\n") + "\n")
	})
}

func cpLines(st *state.Store, name string) []string {
	b, _ := st.Read(name)
	var ls []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			ls = append(ls, l)
		}
	}
	return ls
}

// cpCut shortens s to at most n runes.
func cpCut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func cpRecordTool(in *hook.Input, st *state.Store, main bool) {
	if slices.Contains(cpEditTools, in.ToolName) && in.HookEventName == "PostToolUse" {
		var ti struct {
			FilePath     string `json:"file_path"`
			NotebookPath string `json:"notebook_path"`
		}
		if json.Unmarshal(in.ToolInput, &ti) != nil {
			return
		}
		p := ti.FilePath
		if p == "" {
			p = ti.NotebookPath
		}
		if p == "" {
			return
		}
		if strings.ContainsAny(p, "\n\r") { // one path per line in the state file
			return
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(in.Cwd, p)
		}
		cpPush(st, cpEdits, filepath.Clean(p), cpMaxEdits, true)
		return
	}
	if !main || in.ToolName != "Bash" {
		return
	}
	var ti struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(in.ToolInput, &ti) != nil || ti.Command == "" {
		return
	}
	exit := "0"
	if in.HookEventName == "PostToolUseFailure" {
		switch m := cpExitRe.FindStringSubmatch(in.Error); {
		case m != nil:
			exit = m[1]
		case in.IsInterrupt:
			exit = "interrupted"
		default:
			exit = "error"
		}
	}
	// ponytail: a command another hook rewrote arrives rewritten; stored as is.
	b, _ := json.Marshal(cpCommand{Cmd: cpCut(strings.Join(strings.Fields(ti.Command), " "), cpCmdChars), Exit: exit})
	cpPush(st, cpCommands, string(b), cpMaxCommands, false)
}

// promptInjected: task notifications and agent reports arrive as
// UserPromptSubmit but are not typed by the user.
func promptInjected(p string) bool {
	p = strings.TrimSpace(p)
	return strings.HasPrefix(p, "<task-notification>") || strings.HasPrefix(p, "<agent-message")
}

func cpRecordPrompt(in *hook.Input, st *state.Store) {
	if strings.TrimSpace(in.Prompt) == "" || promptInjected(in.Prompt) {
		return
	}
	b, _ := json.Marshal(cpCut(in.Prompt, cpPromptChars))
	cpPush(st, cpPrompts, string(b), cpMaxPrompts, false)
}

func cpRecordRisk(in *hook.Input, st *state.Store) {
	ls := strings.Split(in.LastAssistantMessage, "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(ls[i]); strings.HasPrefix(l, "Risk:") {
			st.Write(cpRisk, []byte(cpCut(l, 300)))
			return
		}
	}
}

// ---- PreCompact ----

func cpWrite(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) {
	now := time.Now().UTC()
	edits := cpLines(st, cpEdits)
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Checkpoint\n- trigger: %s\n- time: %s\n- cwd: %s\n", in.Trigger, now.Format(time.RFC3339), in.Cwd)

	sb.WriteString("\n## Edited files (newest last)\n")
	shown := edits[max(0, len(edits)-30):]
	for _, e := range shown {
		sb.WriteString("- " + e + "\n")
	}
	if len(shown) == 0 {
		sb.WriteString("(none)\n")
	}

	sb.WriteString("\n## Last user prompts\n")
	prompts := cpLines(st, cpPrompts)
	for _, l := range prompts {
		var p string
		if json.Unmarshal([]byte(l), &p) == nil {
			sb.WriteString("- " + strings.Join(strings.Fields(p), " ") + "\n")
		}
	}
	if len(prompts) == 0 {
		sb.WriteString("(none)\n")
	}

	sb.WriteString("\n## Last commands (exit)\n")
	cmds := cpLines(st, cpCommands)
	for _, l := range cmds {
		var c cpCommand
		if json.Unmarshal([]byte(l), &c) == nil {
			fmt.Fprintf(&sb, "- [%s] %s\n", c.Exit, c.Cmd)
		}
	}
	if len(cmds) == 0 {
		sb.WriteString("(none)\n")
	}

	sb.WriteString("\n## Last Risk line\n")
	if b, _ := st.Read(cpRisk); len(b) > 0 {
		sb.WriteString(string(b) + "\n")
	} else {
		sb.WriteString("(none)\n")
	}

	sb.WriteString("\n## Git\n")
	sb.WriteString(cpGit(ctx, in.Cwd, shown))

	if u := cfg.Integrations.ClaudeMem.WorkStateURL; u != "" {
		sb.WriteString("\n## Work state\n")
		sb.WriteString(cpWorkState(ctx, u, in.Cwd) + "\n")
	}

	out := sb.String()
	if len(out) > cpMaxFile {
		n := cpMaxFile - len(cpTruncMarker)
		for n > 0 && !utf8.RuneStart(out[n]) {
			n--
		}
		out = out[:n] + cpTruncMarker
	}
	st.Write(cpFilePrefix+now.Format(cpTSLayout)+".md", []byte(out))
}

func cpGit(ctx context.Context, cwd string, edits []string) string {
	ctx, cancel := context.WithTimeout(ctx, cpGitBudget)
	defer cancel()
	top := func(dir string) string {
		if dir == "" {
			return ""
		}
		out, err := cpGitCmd(ctx, dir, "rev-parse", "--show-toplevel")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	}
	var repos []string
	add := func(r string) {
		if r != "" && len(repos) < 5 && !slices.Contains(repos, r) {
			repos = append(repos, r)
		}
	}
	add(top(cwd))
	for _, e := range edits {
		if ctx.Err() != nil {
			break
		}
		add(top(filepath.Dir(e)))
	}
	if len(repos) == 0 {
		return "(no git repo)\n"
	}
	var sb strings.Builder
	for _, r := range repos {
		out, err := cpGitCmd(ctx, r, "status", "--short", "--branch")
		if err != nil {
			out = "(unavailable)\n"
		}
		ls := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(ls) > 30 {
			ls = append(ls[:30], "… (more)")
		}
		fmt.Fprintf(&sb, "### %s\n%s\n", r, strings.Join(ls, "\n"))
	}
	return sb.String()
}

func cpGitCmd(ctx context.Context, dir string, args ...string) (string, error) {
	// fsmonitor off: status must not run a repo-configured command.
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "-c", "core.fsmonitor=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	cmd.WaitDelay = 50 * time.Millisecond // a helper holding stdout must not outlive ctx
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// cpWorkState trusts the configured endpoint's plain-text body as is.
func cpWorkState(ctx context.Context, endpoint, cwd string) string {
	const bad = "(unavailable)"
	ctx, cancel := context.WithTimeout(ctx, cpWorkBudget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?cwd="+url.QueryEscape(cwd), nil)
	if err != nil {
		return bad
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return bad
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return bad
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return bad
	}
	s := strings.TrimSpace(strings.ToValidUTF8(string(b), ""))
	if s == "" {
		return bad
	}
	return cpCut(s, cpWorkChars)
}

// ---- PostCompact ----

func cpPostCompact(in *hook.Input, cfg *config.Config, st *state.Store) {
	var anchors, missing []string
	for _, e := range cpLines(st, cpEdits) {
		if b := filepath.Base(e); !slices.Contains(anchors, b) {
			anchors = append(anchors, b)
			if !strings.Contains(in.CompactSummary, b) {
				missing = append(missing, b)
			}
		}
	}
	sum := sha256.Sum256([]byte(in.CompactSummary))
	res := fmt.Sprintf("summary %d chars sha256:%s, anchors %d, missing %d", utf8.RuneCountInString(in.CompactSummary), hex.EncodeToString(sum[:])[:12], len(anchors), len(missing))
	if len(missing) > 0 {
		list := missing[:min(10, len(missing))]
		res += ": " + strings.Join(list, ", ")
		if len(missing) > 10 {
			res += ", …"
		}
	}
	st.AppendDecision(struct {
		TS      string `json:"ts"`
		Session string `json:"session_id"`
		Event   string `json:"event"`
		Rule    string `json:"rule"`
		Mode    string `json:"mode"`
		Result  string `json:"result"`
	}{time.Now().UTC().Format(time.RFC3339Nano), in.SessionID, in.HookEventName, "checkpoint", cfg.Mode("checkpoint"), res})
}

// ---- SessionStart(compact) ----

// cpInject injects the newest unconsumed checkpoint. In enforce it first
// claims it by renaming it .consumed (a lost rename race injects nothing)
// and consumes the older ones too; in log mode the files stay, so a later
// flip to enforce still finds them. It does not depend on PostCompact having
// run. Without a checkpoint it returns the post-compact notice that
// session_notice omits in enforce mode (nil when none is configured).
func cpInject(st *state.Store, consume bool, notice string, workState bool) *hook.Decision {
	var prose *hook.Decision
	if notice != "" {
		prose = &hook.Decision{AdditionalContext: notice}
	}
	if st.Dir == "" { // no state root: a relative path would hit the process cwd
		return prose
	}
	ents, _ := os.ReadDir(st.Dir) // sorted; fixed-width UTC timestamp: lexical = chronological
	var names []string
	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, cpFilePrefix) && strings.HasSuffix(n, ".md") && e.Type().IsRegular() {
			names = append(names, filepath.Join(st.Dir, n))
		}
	}
	if len(names) == 0 {
		return prose
	}
	newest := names[len(names)-1]
	read := newest
	if consume {
		read = newest + cpConsumedSufx
		if os.Rename(newest, read) != nil {
			return prose
		}
		for _, n := range names[:len(names)-1] {
			os.Rename(n, n+cpConsumedSufx)
		}
	}
	body, err := os.ReadFile(read)
	if err != nil || len(body) == 0 {
		return prose
	}
	recover := ""
	if workState { // the checkpoint then carries a "## Work state" section
		recover = "recover the work-state list, "
	}
	return &hook.Decision{Private: true, AdditionalContext: fmt.Sprintf("[CHECKPOINT] Pre-compaction state from %s (newer than the summary for files, prompts and commands). Before editing: reconcile git state and checks, %sthen restate the task in ≤10 bullets.\n%s", newest, recover, body)}
}
