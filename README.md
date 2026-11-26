# claude-policy

One static Go binary behind every [Claude Code](https://code.claude.com) hook.

Claude Code calls `claude-policy hook` on each hook event. The binary reads the
event from stdin, loads `~/.claude/policy.toml`, runs the rules that match, and
prints one JSON decision. Rules are code, not prose in a prompt: a destructive
command is parsed and stopped whether or not the model remembers it was told
not to run it.

- **No daemon, no runtime.** One process per hook call, a few milliseconds.
- **Every rule is `off`, `log` or `enforce`**, set in a TOML file that is read
  on every call. No rebuild, no restart.
- **A new install only observes.** Every rule starts in `log`: it records what
  it would have done and changes nothing. You read the log, then turn rules on
  one at a time.
- **It always exits 0.** Exit code 2 means "deny" to Claude Code, so a crash
  must never produce one. Every failure — bad input, bad config, a rule that
  panics or overruns its deadline — fails open and prints `{}`.

## Install

Needs Go 1.26 or later.

```sh
go install github.com/iampolo87/claude-policy/cmd/claude-policy@latest
command -v claude-policy    # usually ~/go/bin/claude-policy
```

Hooks do not always run with your interactive `PATH`, so use the absolute path
that `command -v` printed in the settings below.

## Wire it into Claude Code

Add this to `~/.claude/settings.json` (back the file up first), replacing
`/ABS/PATH/claude-policy` with the path from the previous step:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Agent|Task|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|WebFetch|WebSearch|Monitor",
        "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 5 }] }
    ],
    "PostToolUse": [
      { "matcher": ".*",
        "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 60 }] }
    ],
    "PostToolUseFailure": [
      { "matcher": ".*",
        "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 5 }] }
    ],
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 5 }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 5 }] }
    ],
    "PreCompact": [
      { "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 10 }] }
    ],
    "PostCompact": [
      { "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 5 }] }
    ],
    "SessionStart": [
      { "matcher": "startup|resume|clear|compact|fork",
        "hooks": [{ "type": "command", "command": "/ABS/PATH/claude-policy hook", "timeout": 5 }] }
    ]
  }
}
```

The same command serves every event; the binary dispatches on
`hook_event_name` and `tool_name`. An event you leave out only switches off the
rules that listen to it. `PostToolUse` has the long timeout because `lint` runs
your linters there.

Then check the setup:

```sh
claude-policy config check    # "ok", or what is wrong with policy.toml
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"t","tool_input":{"command":"rm -rf /"}}' \
  | claude-policy hook        # a deny: hard_deny applies even in log mode
```

No `policy.toml` is needed to start: without one the compiled-in defaults
apply.

## `log` and `enforce`

| mode | the rule runs | decision in the log | decision reaches Claude Code |
|---|---|---|---|
| `off` | no | no | no |
| `log` | yes | yes | no |
| `enforce` | yes | yes | yes |

The intended path for each rule is: leave it in `log` for a few days of real
work, read what it would have done, then set it to `enforce`.

```toml
# ~/.claude/policy.toml
[rules.destructive]
mode = "enforce"
```

Two things do not wait for `enforce`:

- `rules.destructive.hard_deny` (`rm -rf /`, `rm -rf ~`, `--no-preserve-root`,
  `mkfs` by default) is denied for every agent in `log` mode too. Only
  `mode = "off"` disables it.
- Rules that keep state (`checkpoint`, `loop_guard`, `time_budget`) keep it in
  `log` mode, so the log shows what they would have said.

## Reading the decision log

```sh
claude-policy log                      # every decision
claude-policy log --since 1d           # newer than a Go duration or Nd
claude-policy log --rule destructive --since 90m
```

One line per decision:

```
2026-11-20 14:03:11 log destructive PreToolUse/Bash main ask: destructive: git push --force …
2026-11-20 14:03:40 enforce output_cap PostToolUse/Bash agent-3f2 note: Bash 21840 → 8000 chars; spill …
```

The columns are time (UTC), the rule's mode when it ran, rule, event/tool, the
actor (`main` or the subagent id), and the verdict with its reason. A `log`
line with verdict `deny` or `ask` is a call that `enforce` would have stopped.

`claude-policy stats [--since 7d] [--rule R] [--session ID] [--json]` aggregates
the same data: per rule, how often it ran, stayed silent, fired by verdict for
the main agent and subagents, would have denied in `log` mode, and its latency;
for `output_cap`, characters cut and an estimate of tokens saved.

The files live under `~/.claude/state/policy/`:

| file | content |
|---|---|
| `decisions.jsonl` | one JSON line per decision; rotated to `decisions.jsonl.1` at 10 MB |
| `metrics.jsonl` | one JSON line per hook call with per-rule timings (`[metrics]`) |
| `<session_id>/` | per-session rule state; removed 24 h after last use, at the next session start |

They hold command lines, file paths and prompt excerpts from your sessions.
Treat them as private.

## Rules

All of them need nothing beyond Claude Code (plus `git`, and for `lint` the
linters you already have). All start in `log`.

| rule | event | what it does |
|---|---|---|
| `destructive` | PreToolUse Bash | Parses the command (wrappers, `$(…)`, heredocs, `bash -c`, variables) and classifies it: `git` (force push, `reset --hard`, `clean -f`, `branch -D`, pushes to protected branches…), `fs` (`rm -r` outside the allowed roots, recursive `chmod`/`chown` of `/`, `dd of=/dev/…`), `sql` (`DROP`/`TRUNCATE`/`DELETE FROM` through a client), `magento` (configured `bin/magento` subcommands). Each category answers allow, ask or deny, separately for the main agent and subagents. A command it cannot resolve asks. |
| `sensitive_paths` | PreToolUse file tools, Grep, Bash | Subagents may not touch the configured paths (`.env`, …). The main agent is never checked; what no agent may read belongs in `permissions.deny`. |
| `edit_surfaces` | PreToolUse Edit, Write | A subagent whose brief contains `## Allowed edit surfaces` may edit only the paths listed under it. |
| `pii_egress` | PreToolUse Bash, Monitor, WebFetch, WebSearch | Asks before a call carries your Claude account email, or a configured needle, to the outside. |
| `commit_message` | PreToolUse Bash | Denies a `git commit` whose message is too long, carries AI attribution, or uses `--no-verify`. |
| `loop_guard` | Pre/PostToolUse(Failure) | Stops the same failing command from being retried unchanged, and a long run of failures. |
| `ponytail` | PreToolUse Write, Edit | Denies new code matching a signature of something the platform already provides (a hand-rolled `debounce`, a `str_contains` polyfill…). |
| `explore_model` | PreToolUse Agent | Gives an `Explore` subagent spawned without a model the configured one. The only rule that rewrites a tool input. |
| `search_scope` | PreToolUse Bash | Tells the model when a recursive `grep`/`rg`/`git grep` silently skipped a gitignored directory such as `vendor/`. |
| `search_batch` | Pre/PostToolUse | Nudges an agent that sends read-only lookups one per message to send them together. |
| `output_cap` | PostToolUse | Replaces an oversized Bash or MCP result with head + pointer + tail and writes the full text to the session scratchpad. |
| `lint` | PostToolUse Edit, Write | `php -l` / `node --check` on the edited file; a syntax error blocks. `phpstan` and `phpcs` are opt-in and only inform. |
| `risk_line` | PostToolUse, Stop | Reminds the main agent, at a turn's first code edit, to end with a `Risk:` line; a turn that ends without one is logged. |
| `time_budget` | UserPromptSubmit, PostToolUse | `budget:20m` in a prompt starts an advisory clock shown after each tool result. |
| `checkpoint` | PreCompact, SessionStart | Writes edited files, last prompts and commands and `git status` before a compaction and injects them after it. |
| `session_notice` | SessionStart | Adds a line of yours at session start, a reminder after compaction, and a warning when a resume will re-write an expired prompt cache. |

Every key and its default is in [`policy.example.toml`](policy.example.toml).
A test keeps that file equal to the compiled-in defaults.

### Optional integrations

Three integrations with other tools ship in the same binary. They are off, and
contact nothing, until `policy.toml` turns them on and says where the tool is:

| table | what turning it on does |
|---|---|
| `[integrations.claude_mem]` `work_state_url` | `checkpoint` fetches `GET <url>?cwd=<cwd>` before a compaction and includes the text in the checkpoint. |
| `[integrations.mempalace]` `mine`, `bin`, `projects_root` | `claude-policy mine`, added as an async `PreCompact` hook, mines the transcript into a wing named after the project. |
| `[integrations.herdr]` `report`, `notice` | `claude-policy statusline <renderer>` reports model, effort, context and cost to the herdr pane; `notice` adds a line at session start inside a pane. |

`claude-policy statusline <renderer>` also works without herdr: it runs your
status line renderer with the same stdin and prints its output. For `mine`, add
`{ "type": "command", "command": "/ABS/PATH/claude-policy mine", "async": true, "timeout": 300 }`
beside the `PreCompact` hook above.

## Configuration

`~/.claude/policy.toml` is decoded over the compiled-in defaults on every hook
call. A list you set replaces the default list.

An unknown key or an invalid value is an error. The whole file is then
ignored, the defaults apply, and the reason goes to stderr on every call;
`claude-policy config check` shows it.

### Project file

The nearest `.claude/policy.toml` at or above the hook's working directory is
decoded on top of the global file. Because that file lives where the guarded
agent works and arrives with a clone, it may set exactly one thing:

```toml
[rules.destructive.git]
allow_actions = ["rebase"]
```

Anything else in it, or any error, leaves the global configuration in force.
Run `claude-policy config check` inside the project to see why.

While `destructive` is in `enforce`, an agent's write to any file named
`policy.toml` asks the main agent and is denied to a subagent.

## Behavior notes

- **Fail open.** Each rule runs under a deadline with its own `recover`:
  200 ms, or the longer one a rule declares (`loop_guard` 500 ms, `checkpoint`
  and `output_cap` 1 s, `lint` 45 s). A rule that panics or overruns is "no
  opinion", written to the log with an `error`.
- **Merging.** Across rules, deny beats ask beats allow. No rule ever returns
  `allow`: that would skip your own permission prompt.
- **Inputs are never rewritten for Bash or Read.** A hook that changes a
  command after it was approved gets it blocked under auto mode, and a rewrite
  can carry a command past a guard. `explore_model` rewrites `Agent` inputs
  only, and under auto mode denies with the model to pass instead.
- **Main agent and subagents are told apart** by `agent_id` in the hook input.
  State is kept per session, counters per agent.
- **`output_cap`** keeps 30 % head and 70 % tail and stays under Claude Code's
  own 10k-character hook-value spill, so a result is never spilled twice.
- **`edit_surfaces`** reads the subagent's brief from line 0 of its transcript.
  An unreadable brief allows and logs; a heading that names no path denies.
- **`risk_line`** never blocks a Stop.
- **`checkpoint`** files are `~/.claude/state/policy/<session>/checkpoint-<ts>.md`,
  at most 8k characters. In `enforce` the newest one is injected once after a
  compaction and marked `.consumed`.
- **`search_scope`** only adds context to the result. It is silent when the
  search bypasses Claude Code's shell shims (`command grep`, an absolute path),
  turns ignoring off, or the working directory cannot be resolved.
- **`ponytail:` comments** in the source mark a deliberate shortcut and name
  where it stops being sound.

### Hook API facts the design relies on

Checked against Claude Code 2.1.x.

- PreToolUse output is `hookSpecificOutput.{permissionDecision, permissionDecisionReason, updatedInput, additionalContext}`.
  Across hooks deny > defer > ask > allow, and `ask` prompts even in auto mode.
- PostToolUse `updatedToolOutput` replaces what the model sees and must have
  the tool's own output shape. Claude Code spills hook values over 10k
  characters to a file.
- A Bash command with a non-zero exit fires `PostToolUseFailure`, not
  `PostToolUse`.
- Stop input carries `last_assistant_message` and `stop_hook_active`.
- SessionStart `source` is `startup|resume|clear|compact|fork`; on resume and
  fork it carries `estimated_cache_write_usd`.
- Settings hooks run inside subagents too.

## Subcommands

| command | purpose |
|---|---|
| `claude-policy hook` | the hook: JSON event on stdin, one JSON object on stdout, exit 0 |
| `claude-policy config check` | validate the global file and the project file of the current directory |
| `claude-policy log [--rule R] [--since 1d]` | print the decision log |
| `claude-policy stats [--since 7d] [--rule R] [--session ID] [--json]` | aggregate decisions and timings |
| `claude-policy probe` | store the raw hook input under `~/.claude/state/policy/probe/<event>/` for 24 h, to see what Claude Code sends |
| `claude-policy statusline <renderer>` | run a status line renderer; herdr reporting when enabled |
| `claude-policy mine` | mempalace transcript mining when enabled |

## Development

```sh
go build ./... && go vet ./... && go test ./...
go test -fuzz=FuzzTokenize -fuzztime=1m ./internal/shell
scripts/check-private.sh
```

- `testdata/<event>/<case>.in.json` with `<case>.want.json` are replayed
  through the binary by `TestFixtures`. They run against
  `testdata/suite.policy.toml`, a profile with most rules in `enforce`; a
  `<case>.policy.toml` beside a fixture is merged over it.
- `scripts/check-private.sh` fails when a tracked file, or a commit's author or
  message, contains a home-directory path or a term from `.private-terms` (one
  extended regex per line; the file is gitignored and yours to keep).
- Build to a scratch path while testing a change. The installed binary runs on
  every hook of every open session.

Layout: `cmd/claude-policy` (subcommands), `internal/hook` (envelope, merge),
`internal/config` (TOML, defaults), `internal/state` (per-session files,
decision log), `internal/shell` (tokenizer), `internal/rules` (one file per
rule).

## Credits and license

MIT, see [LICENSE](LICENSE).

The shell tokenizer and the destructive-command recognizer are ported from
[gentle-shell](https://github.com/Gentleman-Programming/gentle-shell)
(MIT, Copyright (c) 2025 Mario Zechner). The TypeScript originals are vendored,
uncompiled, in [`reference/gentle-shell/`](reference/gentle-shell) at the commit
named in `SOURCE_COMMIT`, with their license. Ported from them:

| Go file | ported from |
|---|---|
| `internal/shell/tokenize.go` | `lib/destructive-command-guard.ts` (tokenizer layer) |
| `internal/rules/destructive.go` | `lib/destructive-command-guard.ts` (`recognizeDestructiveCommands`) |
| `internal/rules/edit_surfaces.go` (`normalizeSurfaceEntry`) | `lib/writer-surfaces.ts` |
| `internal/shell/tokenize_test.go`, `internal/rules/destructive_test.go` | the test vectors of `tests/destructive-command-guard.test.ts` |
