package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iampolo87/claude-policy/internal/hook"
)

func applyCommit(t *testing.T, cmd string) *hook.Decision {
	t.Helper()
	ti, _ := json.Marshal(map[string]string{"command": cmd})
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: ti}
	return commitMessage{}.Apply(context.Background(), in, suiteCfg(), nil)
}

func TestCommitMessage(t *testing.T) {
	heredoc := func(body string) string {
		return "git commit -m \"$(cat <<'EOF'\n" + body + "\nEOF\n)\""
	}
	cases := []struct {
		name, cmd, want string // want: "" allow, else substring of the reason
	}{
		{"3 lines", `git commit -m "feat: x" -m "body 1" -m "body 2"`, ""},
		{"3 lines one arg", "git commit -m \"a\nb\n\nc\"", ""},
		{"4 paragraphs", `git commit -m a -m b -m c -m d`, "has 4 non-empty lines"},
		{"4 lines one arg", "git commit -am \"a\nb\nc\nd\"", "has 4 non-empty lines"},
		{"attached -m", `git commit -mfoo`, ""},
		{"--message=", `git commit --message=foo --message=bar`, ""},
		{"heredoc 3", heredoc("a\nb\n\nc"), ""},
		{"heredoc 4", heredoc("a\nb\nc\nd"), "has 4 non-empty lines"},
		{"-F file", `git commit -F msg.txt`, "-F/--file"},
		{"--file=", `git commit --file=msg.txt`, "-F/--file"},
		{"-C dir", `git -C /x commit -m ok`, ""},
		{"-C dir 4 lines", "git -C /x commit -m \"a\nb\nc\nd\"", "has 4 non-empty lines"},
		{"after cd", `cd x && git commit -m ok`, ""},
		{"in pipeline", "git commit -m \"a\nb\nc\nd\" | cat", "has 4 non-empty lines"},
		{"chained commits count apart", `git commit -m a -m b && git commit -m c -m d -m e`, ""},
		{"chained second too long", `git commit -m a && git commit -m b -m c -m d -m e`, "has 4 non-empty lines"},
		{"session trailer", "git commit -m \"x\n\nClaude-Session: abc\"", "AI-attribution"},
		{"session url", "git commit -m \"x\n\nhttps://claude.ai/code/session_1\"", "AI-attribution"},
		{"co-authored-by", `git commit -m "x" -m "Co-Authored-By: Bot <a@b.c>"`, "AI-attribution trailer"},
		{"generated with", `git commit -m "Generated with a tool"`, "AI-attribution trailer"},
		{"noreply", `git commit -m "x" -m "noreply@anthropic.com"`, "AI-attribution trailer"},
		{"claude-code url", `git commit -m "see claude.com/claude-code"`, "AI-attribution trailer"},
		{"robot", "git commit -m \"x \U0001F916\"", "attribution marker"},
		{"no-verify", `git commit --no-verify -m x`, "--no-verify is not allowed"},
		{"not a commit", `git status`, ""},
		{"echo", `echo "git commit"`, ""},
		{"git log", `git log --grep commit`, ""},
		{"commit as arg", `git checkout commit`, ""},
		{"other tool", `ls -la`, ""},
		{"time wrapper trailer", "time git commit -m 'x' -m 'Co-Authored-By: B <a@b.c>'", "AI-attribution"},
		{"time wrapper 4 lines", `time git commit -m a -m b -m c -m d`, "has 4 non-empty lines"},
		{"rtk wrapper 4 lines", `rtk git commit -m a -m b -m c -m d`, "has 4 non-empty lines"},
		{"nice wrapper 4 lines", `nice git commit -m a -m b -m c -m d`, "has 4 non-empty lines"},
		{"doas -F", `doas git commit -F m.txt`, "-F/--file"},
		{"time no-verify", `time git commit --no-verify -m x`, "--no-verify"},
		{"bash -c trailer", `bash -c "git commit -m 'Co-Authored-By: B <a@b.c>'"`, "AI-attribution"},
		{"eval no-verify", `eval 'git commit --no-verify -m x'`, "--no-verify"},
		{"backtick trailer", "echo `git commit -m 'Generated with x'`", "AI-attribution"},
		{"bash heredoc script", "bash <<'EOF'\ngit commit -m 'Generated with x'\nEOF", "AI-attribution"},
		{"bash here-string", `bash <<< "git commit --no-verify -m x"`, "--no-verify"},
		{"mixed case gate", `bash -c "GIT   COMMIT --no-verify"`, "--no-verify"},
		{"shift in -m 5 lines", "git commit -m \"shift a << b\nl2\nl3\nl4\nl5\"", "has 5 non-empty lines"},
		{"here-string in -m", `git commit -m "a <<< b" -m 2 -m 3 -m 4`, "has 4 non-empty lines"},
		{"chained time second 4", `git commit -m a && time git commit -m a -m b -m c -m d`, "has 4 non-empty lines"},
		{"wrapper ok", `time git commit -m a -m b`, ""},
		{"wrapped -C no-verify", `time git -C x commit --no-verify -m a`, "--no-verify"},
		{"bash -c -C no-verify", `bash -c 'git -C x commit --no-verify -m a'`, "--no-verify"},
		{"line continuation", "git \\\n commit --no-verify", "--no-verify"},
		{"heredoc spam no-verify", "git commit --no-verify -m a\n" + strings.Repeat("cat <<a\n", 8000), "--no-verify"},
		{"heredoc spam over cap", "git commit -m a\n" + strings.Repeat("cat <<a\n", 2100), "too long"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := applyCommit(t, c.cmd)
			if c.want == "" {
				if d != nil {
					t.Fatalf("want allow, got %+v", d)
				}
				return
			}
			if d == nil || d.Permission != "deny" || d.Hard || !strings.Contains(d.Reason, c.want) {
				t.Fatalf("want deny containing %q, got %+v", c.want, d)
			}
		})
	}
}

func TestCommitMessageDenyEntries(t *testing.T) {
	for _, e := range suiteCfg().Rules.CommitMessage.Deny {
		if d := applyCommit(t, "git commit -m 'x "+strings.ToUpper(e)+"'"); d == nil || d.Permission != "deny" {
			t.Errorf("deny entry %q not denied: %+v", e, d)
		}
	}
}

func TestCommitMessageTooLong(t *testing.T) {
	pad := strings.Repeat("x", 70<<10)
	if d := applyCommit(t, "git commit -m a # "+pad); d == nil || d.Permission != "deny" || !strings.Contains(d.Reason, "too long") {
		t.Fatalf("got %+v", d)
	}
	if d := applyCommit(t, "git -C x commit -m a # "+pad); d == nil || !strings.Contains(d.Reason, "too long") {
		t.Fatalf("long git -C commit: %+v", d)
	}
	if d := applyCommit(t, "echo "+pad); d != nil {
		t.Fatalf("ungated long command: %+v", d)
	}
}

func TestCommitMessageMaxLinesFromConfig(t *testing.T) {
	cfg := suiteCfg()
	cfg.Rules.CommitMessage.MaxLines = 1
	ti, _ := json.Marshal(map[string]string{"command": `git commit -m a -m b`})
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: ti}
	if d := (commitMessage{}).Apply(context.Background(), in, cfg, nil); d == nil || !strings.Contains(d.Reason, "limit is 1") {
		t.Fatalf("got %+v", d)
	}
}
