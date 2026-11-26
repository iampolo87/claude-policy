package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/shell"
	"github.com/iampolo87/claude-policy/internal/state"
)

func init() { Registry = append(Registry, commitMessage{}) }

// commitMessage denies commits carrying AI attribution, bypassing hooks or
// exceeding the message line limit.
type commitMessage struct{}

func (commitMessage) Name() string     { return "commit_message" }
func (commitMessage) Events() []string { return []string{"PreToolUse"} }
func (commitMessage) Tools() []string  { return []string{"Bash"} }

// maxCommitScan bounds what is tokenized: the tokenizer is superlinear on
// heredoc spam (64 KiB already overruns the 200 ms deadline), so a longer
// command that looks like a commit is denied.
const maxCommitScan = 16 << 10

// gitCommitRe is the cheap gate, checked before any parsing: "git" and later
// "commit" anywhere, so wrapped (time, bash -c, eval) and global-option
// (git -C x commit) forms reach the deny checks.
var gitCommitRe = regexp.MustCompile(`(?is)\bgit\b.*\bcommit\b`)

func (commitMessage) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, _ *state.Store) *hook.Decision {
	var ti struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(in.ToolInput, &ti) != nil || !gitCommitRe.MatchString(ti.Command) {
		return nil
	}
	c := cfg.Rules.CommitMessage
	cmd := ti.Command
	lower := strings.ToLower(cmd)
	for _, d := range c.Deny {
		if d == "" || !strings.Contains(lower, strings.ToLower(d)) {
			continue
		}
		switch d {
		case "\U0001F916":
			return denyCommit("Commit message carries the \U0001F916 attribution marker. Rewrite it without the marker.")
		case "--no-verify":
			return denyCommit("--no-verify is not allowed. Report the failing pre-commit hook to the user instead of bypassing it.")
		}
		return denyCommit("Commit message carries an AI-attribution trailer. Rewrite it without the trailer (see the conventional-commit skill: one-line Conventional Commit, no AI reference).")
	}
	if len(cmd) > maxCommitScan {
		return denyCommit("This command looks like a git commit but is too long to inspect. Split it or pass a shorter message.")
	}
	var commits []shell.Segment
	for _, s := range shell.Segments(cmd) {
		if s.Name() == "git" && gitSubcommand(s.Args()) >= 0 {
			commits = append(commits, s)
		}
	}
	commits = append(commits, wrappedCommits(cmd, commits)...)
	if ctx.Err() != nil {
		return nil
	}
	for _, s := range commits {
		n, fromFile := messageLines(s)
		if fromFile {
			return denyCommit(fmt.Sprintf("Commit message from -F/--file cannot be inspected. Pass it inline with -m (<= %d lines).", c.MaxLines))
		}
		if n > c.MaxLines {
			return denyCommit(fmt.Sprintf("Commit message has %d non-empty lines; the limit is %d (one subject line, at most two body lines). Trim it.", n, c.MaxLines))
		}
	}
	return nil
}

// wrappedCommits finds `git ... commit` behind wrappers the tokenizer does not
// know (time, nice, doas, rtk, ...) in the flat token list, as pseudo
// segments running to the next separator. Commits already parsed are skipped.
func wrappedCommits(cmd string, parsed []shell.Segment) []shell.Segment {
	toks := shell.Tokenize(cmd, true)
	var out []shell.Segment
next:
	for i, t := range toks {
		if t.Operator || shell.Executable(t.Value) != "git" {
			continue
		}
		for _, p := range parsed {
			if t.Index >= p.Start && t.Index < p.End {
				continue next
			}
		}
		j := i + 1
		for j < len(toks) && !toks[j].Operator {
			j++
		}
		seg := shell.Segment{Tokens: toks[i:j:j], Raw: cmd[t.Index:]}
		if j < len(toks) {
			seg.Raw = cmd[t.Index:toks[j].Index]
		}
		if gitSubcommand(seg.Args()) >= 0 {
			out = append(out, seg)
		}
	}
	return out
}

func denyCommit(reason string) *hook.Decision {
	return &hook.Decision{Permission: "deny", Reason: reason}
}

// gitSubcommand returns the index of "commit" in git's args when it is the
// subcommand (after global options such as -C dir), else -1.
func gitSubcommand(args []string) int {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if a == "commit" {
				return i
			}
			return -1
		}
	}
	return -1
}

func nonEmptyLines(s string) (n int) {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return
}

func isLetters(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// messageLines counts the non-empty message lines of a commit segment
// (-m values; heredoc bodies counted for `$(cat <<EOF ...)` values).
// fromFile reports -F/--file, whose message cannot be inspected.
func messageLines(s shell.Segment) (n int, fromFile bool) {
	var hs []shell.Heredoc
	if strings.Contains(s.Raw, "<<") {
		hs = shell.Heredocs(s.Raw)
	}
	hl := -1
	count := func(v string) {
		if len(hs) == 0 || !strings.Contains(v, "<<") {
			n += nonEmptyLines(v)
			return
		}
		if hl < 0 {
			hl = 0
			for _, h := range hs {
				hl += nonEmptyLines(s.Raw[h.BodyStart:h.BodyEnd])
			}
		}
		n += hl
	}
	args := s.Args()
	for i := gitSubcommand(args) + 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-F" || a == "--file" || strings.HasPrefix(a, "--file="):
			return 0, true
		case strings.HasPrefix(a, "--message="):
			count(a[len("--message="):])
		case a == "--message" || len(a) > 1 && a[0] == '-' && a[len(a)-1] == 'm' && isLetters(a[1:]):
			if i+1 < len(args) {
				i++
				count(args[i])
			}
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
			// -mfoo / -amfoo: letters up to the first m, then the attached message.
			if k := strings.IndexByte(a, 'm'); k > 0 && isLetters(a[1:k]) {
				count(a[k+1:])
			}
		}
	}
	return n, false
}
