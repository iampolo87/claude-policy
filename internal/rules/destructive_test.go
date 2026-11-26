package rules

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
)

const dScratch = "/tmp/claude-1000/s/scratchpad"

func dIn(cmd, agent, cwd string) *hook.Input {
	ti, _ := json.Marshal(map[string]string{"command": cmd})
	return &hook.Input{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: ti, AgentID: agent, Cwd: cwd, ScratchpadDir: dScratch}
}

func dApply(cfg *config.Config, cmd, agent string) *hook.Decision {
	return destructive{}.Apply(context.Background(), dIn(cmd, agent, "/work/u/repo"), cfg, nil)
}

// Ported from reference/gentle-shell/tests/destructive-command-guard.test.ts,
// plus the PLAN.md categories: each must ask the main agent and deny a subagent.
var dDestructive = []string{
	// TS destructive
	`psql -c 'DROP TABLE users'`,
	`mysql --execute='TRUNCATE TABLE users'`,
	`sqlite3 app.db 'DELETE FROM users;'`,
	`psql -c 'DELETE FROM users WHERE 1=1'`,
	`echo 'DROP DATABASE app' | psql`,
	`printf '%s' 'TRUNCATE users' | mysql`,
	`env MODE=test sudo -u postgres /usr/bin/psql -c 'DROP SCHEMA public CASCADE'`,
	`sh -c "echo ready; psql -c 'DROP TABLE users'"`,
	`echo ready && rm -fr -- ./data`,
	`find ./data -type f -delete`,
	`find ./data -type f -exec rm -rf {} +`,
	`find ./data -print0 | xargs -0 rm -rf`,
	"psql <<'SQL'\nDROP TABLE users;\nSQL",
	`sqlite3 app.db 'SELECT 1; /* maintenance */ DROP TABLE users'`,
	`timeout 30 bash -lc 'rm -r ./data'`,
	`echo ready || (rm -r ./data)`,
	`rm -r /var/app/data`,
	`git -C /repo reset --hard HEAD`,
	`git clean -fd`,
	`git push --force-with-lease origin main`,
	`git branch -D old`,
	`git restore .`,
	`sh -c "psql -c \"DROP TABLE users\""`,
	`bash -lc "rm -r \"./data\""`,
	`psql -c 'DELETE FROM "where"'`,
	"mysql -e 'DELETE FROM `where`'",
	`sqlite3 app.db 'DELETE FROM [where]'`,
	`psql -c 'DROP TABLE "where"'`,
	`find cache -exec echo {} \; -exec rm -r {} \;`,
	`find cache -execdir echo {} \; -execdir rm -r {} \;`,
	`sudo -n rm -r ./data`,
	`command -p psql -c 'DROP TABLE users'`,
	`env -u MODE sudo -u postgres psql -c 'DROP TABLE users'`,
	`echo 'rm -rf /'; env X=1 sh -c 'rm --recursive ./data'`,
	// TS hard-denial list whose form is not a hard_deny entry here
	`rm -r "$HOME"`, `git -C /repo reset --hard`, `git push -f`, `git push ';' -f main`, `rm -r ';' /`,
	`rm -rf /tmp/tmp.abcdef1234 ~/foo`,
	// TS compound removals (reserved words, backticks, eval)
	`if true; then rm -rf data; fi`,
	`for d in a b; do rm -rf "$d"; done`,
	"echo `rm -rf data`",
	`eval 'rm -rf data'`,
	`if false; then :; else rm -rf data; fi`,
	`if false; then :; elif rm -rf data; then :; fi`,
	`while rm -rf data; do :; done`,
	`until rm -rf data; do :; done`,
	`if rm -rf data; then :; fi`,
	`{ rm -rf data; }`,
	`! rm -rf data`,
	`if true; then sudo rm -rf data; fi`,
	"echo \"now: `rm -rf data`\"",
	"echo `true; rm -rf data`",
	`eval "rm -rf data"`,
	`eval rm -rf data`,
	`eval -- 'rm -rf data'`,
	`command eval 'rm -rf data'`,
	`eval 'if true; then rm -rf data; fi'`,
	`eval 'git reset --hard'`,
	`! rm -rf ..`, `while true; do rm -rf ~/foo; done`,
	// TS removal-target list (no literal-target waiver applies)
	`rm -rf /tmp/tmp.abcdef1234 /tmp/x.log; git log -1`,
	`rm -r -f -- /tmp/tmp.abcdef1234`,
	"rm -rf /tmp/a && rm -r /tmp/b\n\nrm -r /tmp/c || true",
	`rm -rf /tmp/a; mv x /tmp/b; rm -rf /tmp/b`,
	`sudo rm -rf /tmp/tmp.abcdef1234`, `env rm -rf /tmp/tmp.abcdef1234`, `X=1 rm -rf /tmp/tmp.abcdef1234`,
	`xargs rm -rf /tmp/tmp.abcdef1234`, `/bin/rm -rf /tmp/tmp.abcdef1234`, `sh -c 'rm -rf /tmp/tmp.abcdef1234'`,
	`find /tmp -name tmp.abcdef1234 -exec rm -rf {} +`, `rm -rf "$TMPDIR/x"`, `rm -rf '/tmp/tmp.abcdef1234'`,
	`rm -rf`,
	`mv x /tmp/tmp.abcdef1234 && rm -rf /tmp/tmp.abcdef1234`, `cp -r x /tmp/tmp.abcdef1234; rm -rf /tmp/tmp.abcdef1234`,
	`(rm -rf /tmp/tmp.abcdef1234)`, `rm -rf /tmp/tmp.abcdef1234 & true`, `rm -rf /tmp/tmp.abcdef1234 | cat`,
	`{ rm -rf /tmp/tmp.abcdef1234; }`, `! rm -rf /tmp/tmp.abcdef1234`, `if true; then rm -rf /tmp/tmp.abcdef1234; fi`,
	"echo `rm -rf /tmp/tmp.abcdef1234`", `eval 'rm -rf /tmp/tmp.abcdef1234'`, `eval rm -rf /tmp/tmp.abcdef1234`,
	// git (PLAN list)
	`git push origin +main`, `git push --force origin x`, `git checkout -- .`, `git stash drop`, `git stash clear`,
	`git clean -xdf`, `git branch --delete --force x`, `git reset --hard origin/main`,
	// fs
	`rm -rf /tmp/x`, `rm -rf ./build`, `rm -rf ~/foo`, `rm -r /`,
	`rm -rf /tmp/claude-1000`, `rm -rf /tmp/claude-1000/../etc`, `rm -rf /tmp/claude-1000/*`, `rm -rf "$TMP"/x`,
	`rm -rf /tmp/claude-1000/x /etc/y`, `xargs rm -rf /tmp/claude-1000/x`, `rm -rf ~root/x`,
	`chmod -R 777 /`, `sudo chown -R me ~`, `chown -R me:me $HOME`, `chmod --recursive 700 /*`,
	`dd if=x.img of=/dev/sda bs=4M`,
	// sql
	`mysql -e 'DROP DATABASE x'`, "mysql db <<'SQL'\nTRUNCATE x;\nSQL",
	// magento
	`bin/magento setup:uninstall`, `php bin/magento module:uninstall Vendor_X`,
	`php -d memory_limit=-1 bin/magento indexer:reset`, `n98-magerun2 indexer:reset`,
	`bin/magento -n setup:db:status-clean`, `docker compose exec php bin/magento setup:uninstall`,
	// substitution bodies inside double quotes
	`git commit -m "$(rm -rf data)"`,
}

// Ported TS benign lists plus near misses of every category: no opinion.
var dBenign = []string{
	`pnpm test && pnpm run build`, `git status`, `git push origin feat`,
	`psql -c 'SELECT * FROM users'`, `sqlite3 app.db 'DELETE FROM users WHERE id=7'`,
	`psql -c "SELECT 'DROP TABLE users'"`,
	`echo 'rm -rf ./data; DROP TABLE users'`, `printf '%s' 'TRUNCATE TABLE users'`,
	`rg 'DROP TABLE' docs`, `rm ./one-file`, `find . -name '*.ts'`,
	"psql <<'SQL'\nSELECT 'DROP TABLE users';\nSQL",
	`git log --oneline`, `env X=1 echo 'rm -r ./data'`,
	`find . -exec echo 'DROP TABLE users' {} +`,
	`git push origin feat && printf '%s' '-f'`,
	`echo ';' rm -r cache`,
	`echo \; rm -r cache`,
	`printf '%s ' ';' rm -r ./data`,
	`echo '|' rm -r cache`,
	`echo '&&' rm -r cache`,
	`echo ')' rm -r cache`,
	`psql -c 'DELETE FROM "where" WHERE id=7'`,
	`psql -c "SELECT \"where\", 'DROP TABLE users'"`,
	`find cache -exec echo {} \; -exec echo 'rm -r data' {} \;`,
	`if [ -f x ]; then echo ok; fi`, `for f in *; do cat "$f"; done`, "echo `date`", `eval "$(ssh-agent -s)"`,
	`grep "then rm -rf" x`, `echo 'then rm -rf data'`, "echo '`rm -rf data`'", "echo \\`rm -rf data\\`",
	`eval 'echo rm -rf data'`, `eval "$cmd"`, `while read -r line; do echo "$line"; done < x`,
	`if git diff --quiet; then git push origin feat; fi`, "echo 'unterminated `rm -rf data'",
	// not hard, not destructive
	`echo 'rm -rf /'`, `rg 'rm -rf /'`, `git commit -m "rm -rf /"`, `grep -- --no-preserve-root x`, `echo mkfs`, `man mkfs`,
	"git commit -m \"$(cat <<'EOF'\nfix: x\n\nrm -rf / and git push --force\nEOF\n)\"",
	"cat <<'EOF' > notes.md\nrm -rf /\nmkfs /dev/sda\nEOF",
	// allow_roots
	`rm -rf /tmp/claude-1000/x`, `rm -rf ` + dScratch + `/out /tmp/claude-1000/y`, `rm -rf -- '/tmp/claude-1000/a b'`,
	// near misses
	`git stash`, `git stash list`, `git checkout main`, `git branch -d x`, `git push -u origin x`,
	`chmod -R 755 ./dir`, `chmod 644 /etc/x`, `dd if=/dev/zero of=/dev/null count=1`, `dd if=a of=b`,
	`mysql -e 'SELECT 1'`, `bin/magento cache:flush`, `bin/magento setup:upgrade`, `echo bin/magento setup:uninstall`,
	`rg 'magento setup:uninstall'`,
	// no head, but nothing unresolved
	`A=1`, `env`, `env -i`, `FOO=bar; echo $FOO`, `go test 2>&1 | tail`, `time go test ./...`,
}

var dHard = []string{
	`rm -fr /`, `rm -rf /tmp/tmp.abcdef1234 /`, `if true; then rm -rf ~; fi`, `for d in a; do rm -rf /; done`,
	`{ rm -rf "$HOME"; }`, "echo `rm -rf ~`", `eval 'rm -rf /'`,
	`rm -rf --no-preserve-root /`, `sudo rm -r -f /*`, `rm -R --force ~/`, `/bin/rm -fr ${HOME}`, `rm / -rf`,
	`mkfs.ext4 /dev/sda1`, `sudo mkfs -t ext4 /dev/sdb`, `bash -c "rm -rf /"`, `echo "$(rm -rf ~)"`,
	`chown --no-preserve-root -R x /`, `rm -rf "$HOME/"`,
	`rm -rf --no-preserve-root /tmp/tmp.abcdef1234`, // TS removal-target list; a hard_deny flag here
}

// Commands Segments cannot resolve ask both actors.
var dUnresolved = []string{
	`sudo --bogus rm x`, `env -S 'rm -rf data'`, "cat <<EOF\n$(rm -rf data)\nEOF",
	`eval eval eval eval eval eval true`, "cat <<EOF\nunterminated",
}

func TestDestructiveVectors(t *testing.T) {
	cfg := suiteCfg()
	check := func(list []string, wantMain, wantSub string, hard bool) {
		for _, cmd := range list {
			t.Run(cmd, func(t *testing.T) {
				for _, c := range []struct{ agent, want string }{{"", wantMain}, {"a1", wantSub}} {
					d := dApply(cfg, cmd, c.agent)
					switch {
					case c.want == "" && d != nil:
						t.Fatalf("agent %q: want no opinion, got %+v", c.agent, d)
					case c.want != "" && (d == nil || d.Permission != c.want || d.Hard != hard || d.UpdatedInput != nil):
						t.Fatalf("agent %q: want %s hard=%v, got %+v", c.agent, c.want, hard, d)
					}
				}
			})
		}
	}
	check(dDestructive, "ask", "deny", false)
	check(dBenign, "", "", false)
	check(dHard, "deny", "deny", true)
	check(dUnresolved, "ask", "ask", false)
}

func TestDestructiveVerdicts(t *testing.T) {
	cfg := suiteCfg()
	if d := dApply(cfg, `git push -f`, ""); d == nil || d.Reason != "destructive: git ask (main): git push -f" {
		t.Fatalf("reason: %+v", d)
	}
	if d := dApply(cfg, `rm -rf /`, "a1"); d == nil || d.Reason != `destructive: hard_deny "rm -rf /": rm -rf /` {
		t.Fatalf("hard reason: %+v", d)
	}
	if d := dApply(cfg, `ls; rm -r x`+strings.Repeat("y", 300), "a1"); d == nil || len(d.Reason) > 260 || !strings.Contains(d.Reason, "fs deny (subagent): rm -r xyy") {
		t.Fatalf("clipped reason: %+v", d)
	}
	cfg.Rules.Destructive.Git.Policy = config.Policy{Main: "deny", Subagent: "allow"}
	cfg.Rules.Destructive.SQL = config.Policy{Main: "deny", Subagent: "ask"}
	if d := dApply(cfg, `git push -f`, ""); d == nil || d.Permission != "deny" {
		t.Fatalf("main deny: %+v", d)
	}
	if d := dApply(cfg, `git push -f`, "a1"); d != nil {
		t.Fatalf("allow is no opinion: %+v", d)
	}
	cfg.Rules.Destructive.Git.Main = "ask"
	if d := dApply(cfg, `git push -f; psql -c 'DROP TABLE x'`, ""); d == nil || d.Permission != "deny" || !strings.HasPrefix(d.Reason, "destructive: sql deny (main): psql") {
		t.Fatalf("strongest wins: %+v", d)
	}
	if d := dApply(cfg, `git push -f; psql -c 'DROP TABLE x'`, "a1"); d == nil || d.Permission != "ask" {
		t.Fatalf("subagent ask: %+v", d)
	}
	cfg.Rules.Destructive.HardDeny = []string{"git push --force", "shred"}
	for _, cmd := range []string{`git push origin main --force`, `shred -u x`} {
		if d := dApply(cfg, cmd, ""); d == nil || !d.Hard {
			t.Fatalf("custom hard_deny %q: %+v", cmd, d)
		}
	}
	if d := dApply(cfg, `rm -rf /`, ""); d == nil || d.Hard {
		t.Fatalf("hard_deny comes from config only: %+v", d)
	}
}

func TestDestructiveAllowRoots(t *testing.T) {
	cfg := suiteCfg()
	run := func(cmd, cwd string, scratch string) *hook.Decision {
		in := dIn(cmd, "a1", cwd)
		in.ScratchpadDir = scratch
		return destructive{}.Apply(context.Background(), in, cfg, nil)
	}
	if d := run(`rm -rf build ./x`, dScratch+"/sub", dScratch); d != nil {
		t.Fatalf("relative inside root: %+v", d)
	}
	if d := run(`rm -rf build ../x`, dScratch+"/sub", dScratch); d == nil {
		t.Fatal("a .. component never qualifies: the cwd may be a symlink")
	}
	if d := run(`rm -rf build`, "", dScratch); d == nil {
		t.Fatal("relative without cwd must be outside")
	}
	cfg.Rules.Destructive.FS.AllowRoots = []string{"$scratchpad_dir"}
	if d := run(`rm -rf `+dScratch+`/x`, "/", ""); d == nil {
		t.Fatal("empty scratchpad_dir entry must be skipped")
	}
	if d := run(`rm -rf `+dScratch+`/x`, "/", dScratch); d != nil {
		t.Fatalf("scratchpad entry: %+v", d)
	}
	cfg.Rules.Destructive.FS.AllowRoots = []string{"~/cache"}
	if d := run(`rm -rf ~/cache/x`, "/", ""); d != nil {
		t.Fatalf("~ entry and target: %+v", d)
	}
}

func TestDestructiveLatency(t *testing.T) {
	cmds := []string{
		`git status`, `go test ./... 2>&1 | tail -20`, `cd /work/u/repo && git diff --stat HEAD~3`,
		"git commit -m \"$(cat <<'EOF'\nfeat: x\n\nbody line\nEOF\n)\"", `find . -name '*.go' -exec gofmt -l {} +`,
		`rm -rf /tmp/claude-1000/x && mkdir -p /tmp/claude-1000/x`, `bash -c "npm ci && npm run build"`,
		`php bin/magento cache:flush && bin/magento setup:upgrade`, `psql -c 'SELECT 1' | head`, `ls -la`,
	}
	cfg := suiteCfg()
	start := time.Now()
	for i := range 1000 {
		dApply(cfg, cmds[i%len(cmds)], "")
	}
	if avg := time.Since(start) / 1000; avg > time.Millisecond {
		t.Fatalf("average %v per command, want < 1ms", avg)
	}
}

func TestDestructiveLongCommandAsks(t *testing.T) {
	if d := dApply(suiteCfg(), "echo "+strings.Repeat("x", 70<<10), ""); d == nil || d.Permission != "ask" {
		t.Fatalf("oversized command: %+v", d)
	}
}

// Review findings: each input is the reviewer's, with its expected verdict.
var (
	dReviewDestructive = []string{
		"git push \\\n--force", "gi\\\nt push --force", // 2: backslash-newline joins
		`$'git' push --force`, `git push $'--force'`, `rm $'-rf' ./data`, // 3: ANSI-C quoting
		"cat <<$'EOF'\nx\nEOF\ngit push --force\n$EOF", "x=$(cat <<'EOF'\nhi\nEOF)\ngit push --force\nEOF", // 4
		`bash -c -- 'git push --force'`, `bash -c -e 'git push --force'`, "bash <<'EOF'\ngit push --force\nEOF", // 5
		`bash <<<'git push --force'`, `function f { git push --force; }; f`, `f() { git push --force; }; f`,
		`builtin eval 'git push --force'`, `su -c 'git push --force'`, `su - root --command='git push --force'`,
		`flock /tmp/l git push --force`, `flock -n /tmp/l -c 'git push --force'`, `taskset -c 0 git push --force`,
		`coproc git push --force`, `echo 'git push --force' | sh`, "cat <<'EOF' | sh\ngit push --force\nEOF",
		`sh -s < /dev/null <<<'git push --force'`,
		`git push --force>/dev/null`,                                                   // 6
		`rm -rf '~'`,                                                                   // 7: a literal directory, not the home
		`mysql -e'DROP TABLE users'`, `psql -c'DROP TABLE users'`, `rm --recur ./data`, // 10
		`bin/magento s:uninstall`, `php bin/magento mod:unin Vendor_X`, `bin/magento s:d:status-clean`, `bin/magento i:res`,
		`git --config-env x=y push --force`,
		`git checkout .`,         // 12
		`G=git; $G push --force`, // a literal assignment resolves the dynamic head
		// Review: a redirection among wrapper options or positionals is no lock file or value.
		`flock >/dev/null /tmp/l rm -rf ./data`, `timeout 2>/dev/null 5 rm -rf ./data`, `taskset >/dev/null 0x1 rm -rf ./data`,
		`flock 2>&1 /tmp/l git push --force`, `sudo >/dev/null -u root rm -rf ./data`, `env >/dev/null -i rm -rf ./data`,
		`timeout -s >/dev/null KILL 5 rm -rf ./data`, `sudo -u >/dev/null root rm -rf ./data`, `flock -- >/dev/null /tmp/l rm -rf ./data`,
		// Named-fd redirections ({fd}>file) are redirections too.
		`{fd}>/dev/null git push --force`, `env {fd}>/dev/null rm -rf ./data`, `sudo {fd}>/dev/null rm -rf ./data`,
		`sudo -u {fd}>/dev/null root rm -rf ./data`, `flock {fd}>/tmp/l /tmp/x rm -rf ./data`,
		`timeout {fd}>/dev/null 5 rm -rf ./data`, `{fd}<&- rm -rf ./data`,
		`{a[1]}>/dev/null git push --force`, `sudo {a[1]}>/dev/null rm -rf ./data`, `{a[i+1]}>>x rm -rf ./data`,
		`sudo {a[1^0]}>/dev/null rm -rf ./data`,
		// An info flag followed by words keeps the normal parse.
		`flock -V /tmp/l rm -rf ./data`, `timeout --version 5 rm -rf ./data`, `env --version rm -rf ./data`,
	}
	dReviewUnresolved = []string{
		`$G push --force`, `$(echo git) push --force`, "`echo git` push --force", // 3: dynamic head
		"cat <<$(x)\na\n$(x)\ncat .env\n$",                                                       // 4: not modeled
		`curl x | bash`, `bash <(curl x)`, `source <(curl x)`, `git -c alias.p='push --force' p`, // 5, 10
		`git --config-env=alias.p=X p`,
		`flock -hV`, `timeout -s --version`, // no info shortcut for clusters or a consumed value
		// A {NAME[ word the tokenizer did not take as a redirection may still be one for bash.
		`{a[1>0]}>/dev/null rm -rf /`, `timeout {a[1>0]}>x 5 rm -rf ./data`, `sudo -u {a[1|0]}>x root rm -rf ./data`,
	}
	dReviewHard = []string{
		"rm -rf \\\n/",               // 2
		`rm $'-rf' /`, `rm -rf $'/'`, // 3
		`echo 'rm -rf /' | sh`, `busybox rm -rf /`, `bash -c -- 'rm -rf /'`, // 5
		`rm -rf />/dev/null`, `rm -rf / >/dev/null`, `>/dev/null rm -rf /`, // 6
		`rm --recur --forc /`, `rm -rf --no-pres /tmp/x`, // 10
		`flock --version /tmp/l rm -rf /`, `{fd}>/dev/null rm -rf /`, `{a[1]}>/dev/null rm -rf /`,
		`{a[1^0]}>/dev/null rm -rf /`, `{a[!0]}>/dev/null rm -rf /`, `{a[1?2:3]}>/dev/null rm -rf /`,
		`{a[1,2]}>/dev/null rm -rf /`, `{a[1==1]}>/dev/null rm -rf /`, `{a[2#1]}>/dev/null rm -rf /`,
		`{a[a[1]]}>/dev/null rm -rf /`, `{a["1"]}>/dev/null rm -rf /`,
	}
	dReviewBenign = []string{
		`echo ok # see (mkfs docs)`, "# note (rm -rf ~ is blocked)\nls", `echo hi # ; rm -rf /`, // 7
		`git commit -m "--no-preserve-root"`, "x=`cat <<'EOF'\nrm -rf /\nEOF`",
		`bin/magento s:up`, `bin/magento i:rei`, `bin/magento s:d:status`, `bash script.sh`, `bash -c 'echo hi'`,
		`echo hi | bash -c 'cat'`, `rm -rf /tmp/claude-1000/x >/dev/null 2>&1`, `git checkout -b x`, `$(go env GOPATH)`,
		`flock --version`, `flock --help | grep -E 'nonblock|conflict-exit'`, `timeout --version`, `flock -V`, // review
		`flock --version 2>&1 | grep x`, `flock --help >/dev/null`, `taskset -h`, `taskset -V`, `sudo flock --version`,
		`echo {fd} {a,b}>/dev/null`, `{ ls; } {fd}>/dev/null`,
	}
)

func TestDestructiveReview(t *testing.T) {
	cfg := suiteCfg()
	home, _ := os.UserHomeDir()
	hard := slices.Clone(dReviewHard)
	if home != "" {
		hard = append(hard, `rm -rf `+home, `rm -rf `+home+`/`) // 10: the home spelled out
	}
	if u, err := user.Current(); err == nil {
		hard = append(hard, `rm -rf ~`+u.Username, `rm -rf ~`+u.Username+`/`)
	}
	check := func(list []string, wantMain, wantSub string, isHard bool) {
		for _, cmd := range list {
			t.Run(cmd, func(t *testing.T) {
				for _, c := range []struct{ agent, want string }{{"", wantMain}, {"a1", wantSub}} {
					d := dApply(cfg, cmd, c.agent)
					switch {
					case c.want == "" && d != nil:
						t.Fatalf("agent %q: want no opinion, got %+v", c.agent, d)
					case c.want != "" && (d == nil || d.Permission != c.want || d.Hard != isHard):
						t.Fatalf("agent %q: want %s hard=%v, got %+v", c.agent, c.want, isHard, d)
					}
				}
			})
		}
	}
	check(dReviewDestructive, "ask", "deny", false)
	check(dReviewUnresolved, "ask", "ask", false)
	check(hard, "deny", "deny", true)
	check(dReviewBenign, "", "", false)
	if d := dApply(cfg, `x; $(echo git) push --force`, ""); d == nil || d.Reason != "destructive: unresolved ask (main): $(echo git) push --force" {
		t.Fatalf("dynamic head reason: %+v", d)
	}
}

// 4: commit_message counts the message bash reads in the heredoc shapes
// bash closes differently.
func TestDestructiveReviewCommitShapes(t *testing.T) {
	for _, cmd := range []string{
		"git commit -m \"$(cat <<$'EOF'\nl1\nl2\nl3\nl4\nEOF\n)\"",
		"git commit -m \"$(cat <<'EOF'\nl1\nl2\nl3\nl4\nEOF)\"",
		"git commit -m \"`cat <<'EOF'\nl1\nl2\nl3\nl4\nEOF`\"",
	} {
		d := commitMessage{}.Apply(context.Background(), dIn(cmd, "", "/work/u/repo"), suiteCfg(), nil)
		if d == nil || !strings.Contains(d.Reason, "has 4 non-empty lines") {
			t.Errorf("%q: %+v", cmd, d)
		}
	}
}

// 11: a file redirected or catted into a SQL client is read.
func TestDestructiveSQLFiles(t *testing.T) {
	dir := t.TempDir()
	for name, sql := range map[string]string{"drop.sql": "SELECT 1;\nDROP TABLE users;\n", "ok.sql": "SELECT 1;\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(sql), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := suiteCfg()
	for cmd, want := range map[string]string{
		`mysql app < drop.sql`: "sql", `cat drop.sql | mysql`: "sql", `mysql app <` + dir + `/drop.sql`: "sql",
		`mysql app < ok.sql`: "", `cat ok.sql | mysql app`: "", `mysql app < missing.sql`: "unresolved",
		`mysql app < $F`: "unresolved", `zcat x.gz | mysql app`: "", `mysql -e 'SELECT 1' </dev/null`: "",
	} {
		d := destructive{}.Apply(context.Background(), dIn(cmd, "a1", dir), cfg, nil)
		switch {
		case want == "" && d != nil, want != "" && (d == nil || !strings.HasPrefix(d.Reason, "destructive: "+want+" ")):
			t.Errorf("%q: want %q, got %+v", cmd, want, d)
		}
	}
}

// 9: allow_roots compares paths with their symlinks resolved.
func TestDestructiveAllowRootsSymlinks(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{root, filepath.Join(outside, "projects")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(base, "rootlink")); err != nil {
		t.Fatal(err)
	}
	cfg := suiteCfg()
	cfg.Rules.Destructive.FS.AllowRoots = []string{root}
	run := func(cmd string) *hook.Decision {
		return destructive{}.Apply(context.Background(), dIn(cmd, "a1", base), cfg, nil)
	}
	if d := run(`rm -rf ` + root + `/link/projects`); d == nil || d.Permission != "deny" {
		t.Fatalf("through a symlink out of the root: %+v", d)
	}
	if d := run(`rm -rf ` + root + `/x ` + base + `/rootlink/y`); d != nil {
		t.Fatalf("inside the root: %+v", d)
	}
	cfg.Rules.Destructive.FS.AllowRoots = []string{base + "/rootlink"}
	if d := run(`rm -rf ` + root + `/x`); d != nil {
		t.Fatalf("a symlinked root: %+v", d)
	}
}

// 1: adversarial shapes stay well below the 200 ms deadline at the 16 KiB cap.
func TestDestructiveAdversarialLatency(t *testing.T) {
	shapes := map[string]string{
		"mysql heredocs":   "rm -rf /;" + strings.Repeat("mysql <<a\n", 1600),
		"bash heredocs":    "rm -rf /;" + strings.Repeat("bash <<a\n", 1800),
		"joined lines":     "rm -rf /;cat <<EOF\n" + strings.Repeat("x\\\n", 5000),
		"closed heredocs":  "rm -rf /;" + strings.Repeat("cat <<a\nx\na\n", 1300),
		"nested subst":     "rm -rf /;" + strings.Repeat("$(", 8000),
		"dq subst":         "rm -rf /;echo " + strings.Repeat("\"$(", 5000),
		"backticks":        "rm -rf /;" + strings.Repeat("`a", 8000),
		"subst heredocs":   "rm -rf /;" + strings.Repeat("x=$(cat <<a\n", 1300),
		"comments":         "rm -rf /;" + strings.Repeat("a #(\n", 3000),
		"redirections":     "rm -rf /;" + strings.Repeat("a>b ", 4000),
		"sql pipe heredoc": "rm -rf /;" + strings.Repeat("cat <<a | mysql\nDROP TABLE x\na\n", 500),
		"bindings":         "rm -rf /;" + strings.Repeat("V=/x/$V;", 2000) + "echo $V",
		"long value uses":  "rm -rf /;V=" + strings.Repeat("a", 8000) + ";" + strings.Repeat("echo $V;", 1000),
		"many uses":        "rm -rf /;V=a;" + strings.Repeat("$V ", 3000),
		"mktemp substs":    "rm -rf /;" + strings.Repeat("D=$(mktemp -d -p x a.XXX) && ", 600),
		"loops":            "rm -rf /;" + strings.Repeat("for i in a; do rm -rf x; ", 700),
		"allowed rm chain": "rm -rf /;" + strings.Repeat("rm -rf /tmp/claude-1000/x && ", 400) + "a | b",
		"allowed rm pipes": "rm -rf /;" + strings.Repeat("rm -rf /tmp/claude-1000/x && a | ", 300) + "b",
		"nested traps":     "rm -rf /;" + strings.Repeat("trap '", 3000),
		"find execs":       "rm -rf /;find " + strings.Repeat("-exec rm -rf /tmp/claude-1000/x ';' ", 400),
		"xargs shells":     "rm -rf /;" + strings.Repeat("xargs sh -c 'rm -rf /tmp/claude-1000/x'|", 250),
	}
	cfg := suiteCfg()
	for name, cmd := range shapes {
		cmd = cmd[:min(len(cmd), maxDestructiveScan)]
		// best of three: one run alone also measures the scheduler and the GC
		var d *hook.Decision
		el := time.Hour
		for range 3 {
			start := time.Now()
			d = dApply(cfg, cmd, "a1")
			el = min(el, time.Since(start))
		}
		if el > 100*time.Millisecond { // half the deadline, so a slower machine than the author's still passes
			t.Errorf("%s: %v", name, el)
		}
		if d == nil || !d.Hard {
			t.Errorf("%s: hard_deny lost: %+v", name, d)
		}
	}
}

// Review round 2: heredoc closes and comments inside substitutions,
// pipe producers, cd before a relative rm target.
func TestDestructiveReview2(t *testing.T) {
	cfg := suiteCfg()
	check := func(list []string, wantMain, wantSub string, isHard bool) {
		for _, cmd := range list {
			t.Run(cmd, func(t *testing.T) {
				for _, c := range []struct{ agent, want string }{{"", wantMain}, {"a1", wantSub}} {
					d := dApply(cfg, cmd, c.agent)
					switch {
					case c.want == "" && d != nil:
						t.Fatalf("agent %q: want no opinion, got %+v", c.agent, d)
					case c.want != "" && (d == nil || d.Permission != c.want || d.Hard != isHard):
						t.Fatalf("agent %q: want %s hard=%v, got %+v", c.agent, c.want, isHard, d)
					}
				}
			})
		}
	}
	check([]string{
		"x=$(cat <<EOF\nEOFX '\nEOF\n)\nrm -rf /\n#'", // 1: EOFX is body text in $(...)
		"x=`cat <<EOF\nab`; rm -rf /\nEOF\n`",         // 1: a backtick ends the body in backticks
		"echo $(# ) '\nrm -rf /\n#'\n)",               // 2: a comment in $(...) runs to the newline
		"x=`# ) '\nrm -rf /\n#'\n`",
		`printf '%s\n' 'rm -rf /' | bash`, `echo -n 'rm -rf /' | sh`, `echo -e 'rm -rf /' | sh`, // 3
		`printf -- '%s' 'rm -rf /' | sh`, `echo -nE 'rm -rf /' | sh`,
	}, "deny", "deny", true)
	check([]string{
		"x=$(cat <<EOF\nEOFX '\nEOF\n)\ngit push --force\n#'", // 1
		"echo $(# ) '\ngit push --force\n#'\n)",               // 2
		"x=`# ) '\ngit push --force\n#'\n`",
	}, "ask", "deny", false)
	check([]string{`printf '%b' 'ls' | sh`, `printf 'ls\n' | sh`, `echo -e 'ls\nx' | sh`}, "ask", "ask", false) // 3
	check([]string{
		"x=$(cat <<'EOF'\nEOF is the marker\nrm -rf / is blocked\nEOF\n)", // 1
		"x=$(cat <<EOF\nEOF X\nEOF'\nrm -rf /\nEOF\n)",
		"echo $(# comment (with parens) and `ticks`\necho hi\n)", // 2
		`printf '%s\n' ls | sh`, `echo -n ls | sh`,
	}, "", "", false)
	run := func(cmd, cwd string) *hook.Decision {
		return destructive{}.Apply(context.Background(), dIn(cmd, "a1", cwd), cfg, nil)
	}
	for _, cmd := range []string{`cd / && rm -rf work/user`, `cd /tmp && rm -rf ../home`, `pushd /; rm -rf etc`, `popd; rm -rf x`} { // 4
		if d := run(cmd, dScratch); d == nil || d.Permission != "deny" {
			t.Errorf("%q after cd: %+v", cmd, d)
		}
	}
	for _, cmd := range []string{`cd /tmp/claude-1000/x && rm -rf /tmp/claude-1000/x/build`, `rm -rf build; cd /`} {
		if d := run(cmd, dScratch); d != nil {
			t.Errorf("%q: %+v", cmd, d)
		}
	}
	// 2: commit_message sees the commit a comment in $(...) no longer hides.
	cmd := "echo $(# ) '\ngit commit -m 'l1\nl2\nl3\nl4'\n#'\n)"
	if d := (commitMessage{}).Apply(context.Background(), dIn(cmd, "", "/work/u/repo"), cfg, nil); d == nil || !strings.Contains(d.Reason, "has 4 non-empty lines") {
		t.Errorf("%q: %+v", cmd, d)
	}
}

// dVerdict is "" (no opinion), "hard" or the finding category of d.
func dVerdict(d *hook.Decision) string {
	switch {
	case d == nil:
		return ""
	case d.Hard:
		return "hard"
	}
	cat, _, _ := strings.Cut(strings.TrimPrefix(d.Reason, "destructive: "), " ")
	return cat
}

// dCheck runs each command as main and subagent from cwd and compares the
// verdict category, which both actors share.
func dCheck(t *testing.T, cfg *config.Config, cwd string, cases map[string]string) {
	t.Helper()
	for cmd, want := range cases {
		for _, agent := range []string{"", "a1"} {
			d := destructive{}.Apply(context.Background(), dIn(cmd, agent, cwd), cfg, nil)
			if got := dVerdict(d); got != want {
				t.Errorf("%q agent %q: want %q, got %+v", clip(cmd), agent, want, d)
			}
		}
	}
}

// A: a literal assignment earlier in the same command, at top level and in
// a sequential position, resolves $V and ${V}.
func TestDestructiveVarBindings(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		// resolved
		`S=/tmp/claude-1000/p/s/scratchpad && rm -rf $S/base && mkdir $S/base`:                         "",
		`S=/tmp/claude-1000/p/s/scratchpad; mkdir -p $S/mut && cd $S/mut && rm -rf repo && mkdir repo`: "",
		`h=$(mktemp -d -p /tmp/claude-1000) && echo hi && rm -rf $h`:                                   "",
		`h=$(mktemp -d) && cd $h && rm -rf x`:                                                          "",
		`D=/tmp/claude-1000/x; rm -rf $D/zip`:                                                          "",
		`D='/tmp/claude-1000/x'; rm -rf "${D}/zip"`:                                                    "",
		`export D=/tmp/claude-1000/x; rm -rf $D/zip`:                                                   "",
		"D=/tmp/claude-1000/x\nrm -rf $D/zip":                                                          "",
		`D=/etc; D=/tmp/claude-1000/x; rm -rf $D/zip`:                                                  "",
		`R=/tmp/claude-1000; D="$R/x"; rm -rf $D`:                                                      "",
		`true && D=/tmp/claude-1000/x && rm -rf $D/zip`:                                                "",
		`M="mariadb --defaults-file=$HOME/.my.cnf db"; $M -e "SELECT 1 FROM t"`:                        "",
		`P="php8.4 bin/magento"; $P config:set a/b 1`:                                                  "",
		`T=/abs/node_modules/.bin/tsc; $T --noEmit`:                                                    "",
		`B=/usr/bin/ugrep; exec -a ugrep $B --help`:                                                    "", // C
		`FOO=bar; echo $FOO`:                                                                           "",
		`S='/tmp/claude-1000/a;rm -rf /'; echo $S`:                                                     "", // unsafe value: left alone
		// resolved into a finding
		`P=bin/magento; $P setup:uninstall`:    "magento",
		`M="mariadb db"; $M -e "DROP TABLE t"`: "sql",
		`S=/; rm -rf $S`:                       "hard",
		`D=/etc; rm -rf $D/x`:                  "fs",
		`S='/tmp/claude-1000/a b'; rm -rf $S`:  "fs", // unquoted: splits, b is relative to the repo
		`G=git; $G push --force`:               "git",
		// unresolved targets behave as today
		`rm -rf $X/zip`:                                                 "fs",
		`rm -rf $S/x; S=/tmp/claude-1000/a`:                             "fs",
		`S=/tmp/claude-1000/a rm -rf $S/x`:                              "fs",
		`(S=/tmp/claude-1000/a); rm -rf $S/x`:                           "fs",
		`x=$(S=/tmp/claude-1000/a); rm -rf $S/x`:                        "fs",
		`S=/tmp/claude-1000/a | true; rm -rf $S/x`:                      "fs",
		`S=/tmp/claude-1000/a & rm -rf $S/x`:                            "fs",
		`for S in /tmp/claude-1000/a; do :; done; rm -rf $S/x`:          "fs",
		`S=/tmp/claude-1000/a; for S in /etc; do rm -rf $S/x; done`:     "fs",
		`S=/tmp/claude-1000/a; while :; do rm -rf $S/x; S=/etc; done`:   "fs",
		`if true; then S=/tmp/claude-1000/a; fi; rm -rf $S/x`:           "fs",
		`S=$(pwd)/x; rm -rf $S`:                                         "fs",
		`S="$PWD/x"; rm -rf $S`:                                         "fs",
		`S=~/x; rm -rf $S`:                                              "fs",
		`false && S=/tmp/claude-1000/a; rm -rf $S/x`:                    "fs",
		`S=/tmp/claude-1000/a; false && S=/etc; rm -rf $S/x`:            "fs",
		`S=/tmp/claude-1000/a; f() { rm -rf $S/x; }; S=/etc; f`:         "fs",
		`S=/tmp/claude-1000/a; eval "$(foo)"; rm -rf $S/x`:              "fs",
		`S=/tmp/claude-1000/a; read S; rm -rf $S/x`:                     "fs",
		`S=/tmp/claude-1000/a; S+=/../../etc; rm -rf $S/x`:              "fs",
		`S=/tmp/claude-1000/a; rm -rf '$S/x'`:                           "fs",
		`S=/tmp/claude-1000/a; rm -rf $SX/x`:                            "fs",
		`IFS=/; S=/tmp/claude-1000/a; rm -rf $S`:                        "fs",
		`S=/tmp/claude-1000/a; case x in x) S=/etc;; esac; rm -rf $S/x`: "fs",
		`S=/tmp/claude-1000/a; cd $S; rm -rf repo`:                      "fs", // cd may fail: repo may be the cwd's
		`S=/tmp/claude-1000/a; cd $S && true; rm -rf repo`:              "fs",
		`cd /tmp/claude-1000/a && rm -rf ../../../etc`:                  "fs",
		"S=/tmp/claude-1000/a; echo `rm -rf repo`; cd $S && true":       "fs",
		`cd /tmp/claude-1000 && eval 'cd /' && rm -rf home`:             "fs",
		`h=$(mktemp -d); rm -rf $h/../x`:                                "fs",
		`h=$(mktemp -d) | true; rm -rf $h`:                              "fs",
		`h=$(echo /tmp/claude-1000/x); rm -rf $h`:                       "fs",
	})
}

// B: git commands that only touch the index or refuse to lose work.
func TestDestructiveGitIndexOnly(t *testing.T) {
	cases := map[string]string{}
	for _, c := range []string{`git reset`, `git reset -q`, `git reset --soft HEAD~1`, `git reset --mixed HEAD~1`,
		`git reset --keep HEAD~1`, `git reset HEAD~1`, `git reset -- a b`, `git reset HEAD -- a`, `git reset --quiet -- a`,
		`git restore --staged a`, `git restore -S a b`, `git restore --staged --source=HEAD~1 a`, `git restore -S -s HEAD a`} {
		cases[c] = ""
	}
	for _, c := range []string{`git reset --hard`, `git reset --merge HEAD`, `git reset --ha`, `git reset -q --hard`,
		`git reset --recurse-submodules HEAD`, `git restore a`, `git restore -S -W a`, `git restore --staged --worktree a`,
		`git restore -SW a`, `git restore --source=HEAD a`, `git checkout -- f`, `git checkout HEAD -- f`,
		`git stash drop`, `git stash clear`} {
		cases[c] = "git"
	}
	dCheck(t, suiteCfg(), "/work/u/repo", cases)
}

// C: exec -a NAME runs its command.
func TestDestructiveExecArgv0(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`exec -a x rm -rf /work/u/proj/src`:   "fs",
		`exec -a ugrep /usr/bin/ugrep --help`: "",
		`exec -a x git push --force`:          "git",
	})
}

// D: an oversized command that is only an inert quoted heredoc write is
// scanned without its body.
func TestDestructiveLongHeredocWrite(t *testing.T) {
	body := strings.Repeat("rm -rf / is just text 'quoted\n", 1000) // > 16 KiB
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		"cat > out.go <<'EOF'\n" + body + "EOF":                                      "",
		"cat >> out.go <<'EOF'\n" + body + "EOF\n  \n":                               "",
		"mkdir -p ~/x/docs && cat > ~/x/docs/a.html <<'EOF'\n" + body + "EOF":        "",
		"tee -a out.txt <<\"EOF\" >/dev/null\n" + body + "EOF":                       "",
		"cat > out.go <<'EOF'\n" + body + "EOF\ngofmt -l . && go vet ./...":          "",
		"cat > out.go <<'EOF'\n" + body + "EOF\ngit push --force":                    "git",
		"cat > out.go <<'EOF'\n" + body + "EOF\nrm -rf /":                            "hard",
		"cat > out.go <<EOF\n" + body + "EOF":                                        "unresolved", // unquoted delimiter
		"cat > out.go <<'EOF'\n" + body:                                              "unresolved", // unterminated
		"cat > out.go <<'EOF' && rm -rf /tmp/x\n" + body + "EOF":                     "unresolved",
		"cat > $(rm -rf x) <<'EOF'\n" + body + "EOF":                                 "unresolved",
		"echo hi; cat > out.go <<'EOF'\n" + body + "EOF":                             "unresolved",
		"cat > out.go <<'EOF'\n" + body + "EOF\n" + strings.Repeat("echo x\n", 3000): "unresolved", // the rest is over the cap
	})
}

// E: regenerable build output inside a git work tree may go.
func TestDestructiveRegenerable(t *testing.T) {
	repo := t.TempDir()
	for _, d := range []string{".git", "var/cache/mage--1", "var/page_cache/819_", "var/view_preprocessed/pub/static/frontend",
		"generated/code/Vendorone/X", "generated/metadata", "pub/static/frontend", "pub/static/adminhtml/Magento", "app/code/X"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]string{
		`rm -rf /var/cache`:                   "fs",
		`rm -rf pub/static`:                   "fs",
		`rm -rf generated`:                    "fs",
		`rm -rf generated/.htaccess`:          "fs",
		`rm -rf app/code/X`:                   "fs",
		`rm -rf var/cache app/code/X`:         "fs",
		`rm -rf var/cache/../../app`:          "fs",
		`rm -rf var/*`:                        "fs",
		`rm -rf ` + repo:                      "fs",
		`cd /tmp && rm -rf var/cache`:         "fs",
		`rm -rf var/cache ` + dScratch + `/x`: "",
		`cd ` + repo + `/var && rm -rf cache`: "",
		`rm -rf ` + repo + `/generated/code`:  "",
	}
	for _, p := range []string{"var/cache", "var/cache/*", "var/page_cache", "var/page_cache/819_",
		"var/view_preprocessed/pub/static/frontend", "generated/code/Vendorone/X", "generated/code", "generated/metadata",
		"generated/*", "pub/static/frontend", "pub/static/adminhtml/Magento", "./var/cache/"} {
		cases[`rm -rf `+p] = ""
	}
	dCheck(t, suiteCfg(), repo, cases)
	if d := (destructive{}).Apply(context.Background(), dIn(`rm -rf var/cache`, "a1", t.TempDir()), suiteCfg(), nil); d == nil {
		t.Fatal("outside a git work tree: no match")
	}

	// A Magento install that is no git repo is anchored by its bin/magento.
	m2 := t.TempDir()
	for _, d := range []string{"bin", "var/page_cache", "generated/code/X"} {
		if err := os.MkdirAll(filepath.Join(m2, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(m2, "bin/magento"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	dCheck(t, suiteCfg(), m2, map[string]string{
		`rm -rf var/page_cache/*`: "",
		`rm -rf generated/code/X`: "",
		`rm -rf app/code/X`:       "fs",
		`rm -rf bin`:              "fs",
	})
}

// F: bash may change a bound value again before its use: ${V:=...} and
// friends anywhere in the text, a DEBUG trap, or a dynamic special.
func TestDestructiveRewrittenVars(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`D=; : ${D:=/../../../work/u/proj}; rm -rf /tmp/claude-1000/x$D`:                                          "fs",
		`D=; echo "${D:=/../../../work/u/proj}"; rm -rf /tmp/claude-1000/x$D`:                                     "fs",
		"D=\ncat <<EOF\n${D:=/../../../work/u/proj}\nEOF\nrm -rf /tmp/claude-1000/x$D":                            "fs",
		`D=; : ${D:=/work/u/proj}; rm -rf /tmp/claude-1000/x $D`:                                                  "fs",
		`D=; : ${D=/work/u/proj}; rm -rf /tmp/claude-1000/x $D`:                                                   "fs",
		`D=; : ${D?x} ${D[0]:=/etc}; rm -rf /tmp/claude-1000/x $D`:                                                "fs",
		`trap ': ;D=/work/u/proj' DEBUG; D=/tmp/claude-1000/x; rm -rf $D`:                                         "fs",
		`LINENO=a/b/c/d; mkdir -p /tmp/claude-1000/$LINENO; rm -rf /tmp/claude-1000/$LINENO/../../../work/u/proj`: "fs",
		`SECONDS=a/1/1/1; rm -rf /tmp/claude-1000/a/$SECONDS/../../../work/u/proj`:                                "fs",
		`LINENO=/tmp/claude-1000/x; rm -rf $LINENO`:                                                               "fs",
		`RANDOM=/tmp/claude-1000/x; rm -rf $RANDOM`:                                                               "fs",
		`BASH_ARGV0=/tmp/claude-1000/x; rm -rf $BASH_ARGV0`:                                                       "fs",
		`REPLY=/tmp/claude-1000/x; rm -rf $REPLY`:                                                                 "fs",
		`D=/tmp/claude-1000/x; : ${D:-/etc}; rm -rf $D`:                                                           "", // :- does not assign
	})
}

// G: a failed mktemp leaves its variable empty; it binds only along &&.
func TestDestructiveMktempChain(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`D=$(mktemp XX); rm -rf $D/work/u/proj`:                        "fs",
		"D=$(mktemp -d --tmpdir=/nonexistent)\nrm -rf $D/work/u/proj":  "fs",
		`D=$(mktemp -d) && rm -rf $D/x`:                                "",
		`D=$(mktemp -d) && cd $D && rm -rf x`:                          "",
		`D=$(mktemp -d) && true; rm -rf $D/x`:                          "fs",
		`D=$(mktemp -d) && true || rm -rf $D/x`:                        "fs",
		`D=$(mktemp -d) && ln -s / $D/x && rm -rf $D/x/../work/u/proj`: "fs",
	})
}

// H: an oversized command is rejected in time, whatever its first line.
func TestDestructiveOverCapLatency(t *testing.T) {
	cmd := ": # " + strings.Repeat("$(", 512<<10) + "\nrm -rf /work/u/proj"
	start := time.Now()
	d := dApply(suiteCfg(), cmd, "a1")
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Errorf("over cap: %v", el)
	}
	if got := dVerdict(d); got != "unresolved" {
		t.Errorf("over cap: want unresolved, got %+v", d)
	}
}

// I: the kernel resolves `..` after a symlink, so a target with a `..`
// component never qualifies for an allow path.
func TestDestructiveDotDotSymlink(t *testing.T) {
	repo := t.TempDir()
	for _, d := range []string{".git", "generated/code", "app/code/X", "var/cache"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(repo, "app/code/X"), filepath.Join(repo, "generated/code/link")); err != nil {
		t.Fatal(err)
	}
	dCheck(t, suiteCfg(), repo, map[string]string{
		`rm -rf generated/code/link/../Y`:                    "fs",
		`D=generated/code/link/..; rm -rf $D/Y`:              "fs",
		`rm -rf ./var/cache/`:                                "",
		`rm -rf generated/code/link/../Y ` + dScratch + `/x`: "fs",
	})

	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{root, filepath.Join(outside, "a")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "a"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	cfg := suiteCfg()
	cfg.Rules.Destructive.FS.AllowRoots = []string{root}
	dCheck(t, cfg, base, map[string]string{
		`rm -rf ` + root + `/link/../Y`: "fs",
		`rm -rf ` + root + `/Y`:         "",
	})
}

// J: a bin/magento or .git in the home directory does not make it a root.
func TestDestructiveRootWalkStopsAtHome(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{"bin", "var/cache", ".git", "p/var/cache"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "bin/magento"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	dCheck(t, suiteCfg(), home, map[string]string{
		`rm -rf var/cache`:              "fs",
		`rm -rf ` + home + `/var/cache`: "fs",
		`rm -rf p/var/cache`:            "fs",
	})
}

// K: `$(mktemp ...)` binds only a plain mktemp call; a redirect sends the
// name elsewhere and leaves the variable empty.
func TestDestructiveMktempRedirect(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`D=$(mktemp -d >/dev/null) && rm -rf $D/work/u/proj`:           "fs",
		`D=$(mktemp -d 1>&2) && rm -rf $D/work/u/proj`:                 "fs",
		`D=$(mktemp -d 2>&1 >/dev/null) && rm -rf $D/work/u/proj`:      "fs",
		`D=$(mktemp -d >f) && rm -rf $D/work/u/proj`:                   "fs",
		`D=$(mktemp -d $X) && rm -rf $D/work/u/proj`:                   "fs",
		`D=$(mktemp -d --tmpdir=/tmp/claude-1000 x.XXXX) && rm -rf $D`: "",
	})
}

// L: bash removes a backslash-newline before expanding ${V:=...}.
func TestDestructiveLineContinuationDefault(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		"D=; : ${D\\\n:=/work/u/proj}; rm -rf /tmp/claude-1000/x $D": "fs",
		"D=; : $\\\n{D:=/work/u/proj}; rm -rf /tmp/claude-1000/x $D": "fs",
		"D=; : ${D:\\\n=/work/u/proj}; rm -rf /tmp/claude-1000/x $D": "fs",
		"D=/tmp/claude-1000/x; : \\\n; rm -rf $D":                    "",
	})
}

// M: bash may resolve a cd target physically, so `..` in it leaves the
// directory unknown.
func TestDestructiveCdDotDot(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{root, filepath.Join(outside, "a")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "a"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	cfg := suiteCfg()
	cfg.Rules.Destructive.FS.AllowRoots = []string{root}
	dCheck(t, cfg, base, map[string]string{
		`cd ` + root + `/link/../zzz && rm -rf x`:       "fs",
		`set -P; cd ` + root + `/link/.. && rm -rf zzz`: "fs",
		`cd ` + root + `/zzz && rm -rf x`:               "",
	})

	repo := t.TempDir()
	for _, d := range []string{".git", "generated/code", "app/code/X"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(repo, "app/code/X"), filepath.Join(repo, "generated/code/link")); err != nil {
		t.Fatal(err)
	}
	dCheck(t, suiteCfg(), repo, map[string]string{
		`cd ./generated/code/link/.. && rm -rf Y`: "fs",
		`cd ./generated && rm -rf code`:           "",
	})
}

// N: the kernel follows a link or moved directory made earlier in the same
// command, which the hook cannot see: no allow path holds after one.
func TestDestructiveEarlierLink(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`D=$(mktemp -d) && ln -s /work/u $D/x && rm -rf $D/x/proj`:                                   "fs",
		`ln -s /work/u /tmp/claude-1000/l && rm -rf /tmp/claude-1000/l/proj`:                         "fs",
		`D=$(mktemp -d) && mv /work/u/proj $D/ && rm -rf $D`:                                         "fs",
		`echo $(ln -s /work/u /tmp/claude-1000/l); rm -rf /tmp/claude-1000/l/proj`:                   "fs",
		"echo `ln -s /work/u /tmp/claude-1000/l`; rm -rf /tmp/claude-1000/l/proj":                    "fs",
		`sh -c 'cp -as /work/u /tmp/claude-1000/l'; rm -rf /tmp/claude-1000/l/proj`:                  "fs",
		`sudo tar -xf a.tar -C /tmp/claude-1000; rm -rf /tmp/claude-1000/l/proj`:                     "fs",
		`S=/tmp/claude-1000/x; rm -rf $S/base && mkdir $S/base && git archive X | tar -x -C $S/base`: "",
		`S=/tmp/claude-1000/x; rm -rf $S/t; mkdir -p $S/t; cp a $S/t/`:                               "",
	})
	repo := t.TempDir()
	for _, d := range []string{".git", "generated/code", "app"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dCheck(t, suiteCfg(), repo, map[string]string{
		`ln -s ../../app generated/code/l && rm -rf generated/code/l/code`: "fs",
		`git checkout x && rm -rf generated/code`:                          "fs",
		`rm -rf generated/code && git checkout x`:                          "",
	})
}

// O: `{V}>file` stores an fd number in V.
func TestDestructiveFdVarWritten(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`D=/tmp/claude-1000/x; exec {D}>/dev/null; rm -rf $D`:  "fs",
		`D=/tmp/claude-1000/x; exec {D}<&-; rm -rf $D`:         "fs",
		`D=/tmp/claude-1000/x; echo {D} >/dev/null; rm -rf $D`: "",
		// A named fd outside exec writes V too (review).
		`D=/tmp/claude-1000/x; {D}>/dev/null true; rm -rf $D`:    "fs",
		`D=/tmp/claude-1000/x; true {D}>/dev/null; rm -rf $D`:    "fs",
		`D=/tmp/claude-1000/x; : {D}>/dev/null && rm -rf $D`:     "fs",
		`D=/tmp/claude-1000/x && {D}<&- true && rm -rf "$D"`:     "fs",
		`D=/tmp/claude-1000/x; {D[0]}>/dev/null true; rm -rf $D`: "fs",
		// An expanding subscript leaves the {V[ word unparsed: V counts as written.
		`D=/tmp/claude-1000/x; true {D[$#]}>/dev/null; rm -rf $D`:      "fs",
		`D=/tmp/claude-1000/x; true {D[$?]}>/dev/null && rm -rf "$D"`:  "fs",
		`z=0; D=/tmp/claude-1000/x; true {D[$z]}>/dev/null; rm -rf $D`: "fs",
		`z=0; D=/tmp/claude-1000/x; {D[$z]}>/dev/null true; rm -rf $D`: "fs",
	})
}

// P: with HOME empty the root walk still stops at the passwd home, and
// refuses regenerable paths when no home is known.
func TestDestructiveRootWalkNoHome(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{"bin", "var/cache", ".git"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "bin/magento"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", "")
	orig := userCurrent
	t.Cleanup(func() { userCurrent = orig })
	userCurrent = func() (*user.User, error) { return &user.User{Username: "u", HomeDir: home}, nil }
	dCheck(t, suiteCfg(), home, map[string]string{
		`rm -rf var/cache`:              "fs",
		`rm -rf ` + home + `/var/cache`: "fs",
	})

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	userCurrent = func() (*user.User, error) { return nil, os.ErrNotExist }
	dCheck(t, suiteCfg(), repo, map[string]string{`rm -rf var/cache`: "fs"})
}

// Q: the allow paths hold only when everything before the rm is a plain
// mktemp substitution or a safe head; any other code may link or move data.
func TestDestructiveRunsBeforeRm(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		// 1: a substitution in the rm segment's redirect or here-string runs first
		`rm -rf /tmp/claude-1000/l/proj 2>$(ln -s /work/u /tmp/claude-1000/l; echo /dev/null)`: "fs",
		`rm -rf /tmp/claude-1000/l/proj >$(ln -s /work/u /tmp/claude-1000/l; echo /dev/null)`:  "fs",
		`rm -rf /tmp/claude-1000/l/proj <<< $(ln -s /work/u /tmp/claude-1000/l)`:               "fs",
		`rm -rf /tmp/claude-1000/l/proj 2> >(ln -s /work/u /tmp/claude-1000/l)`:                "fs",
		`rm -rf /tmp/claude-1000/l/proj >"$(ln -s /work/u /tmp/claude-1000/l)"`:                "fs",
		// 2: a linker behind sh -c, eval or find -exec in a backtick body
		"echo `sh -c 'ln -s /work/u /tmp/claude-1000/l'`; rm -rf /tmp/claude-1000/l/proj":                       "fs",
		"echo `eval ln -s /work/u /tmp/claude-1000/l`; rm -rf /tmp/claude-1000/l/proj":                          "fs",
		"echo `find /work/u -maxdepth 0 -exec ln -s {} /tmp/claude-1000/l ';'`; rm -rf /tmp/claude-1000/l/proj": "fs",
		// 3: any program, a function that only runs one
		`python3 -c 'import os; os.symlink("/work/u", "/tmp/claude-1000/l")'; rm -rf /tmp/claude-1000/l/proj`: "fs",
		`perl -e 'symlink "/work/u", "/tmp/claude-1000/l"'; rm -rf /tmp/claude-1000/l/proj`:                   "fs",
		`node -e 'require("fs").symlinkSync("/work/u","/tmp/claude-1000/l")'; rm -rf /tmp/claude-1000/l/proj`: "fs",
		`cmake -E create_symlink /work/u /tmp/claude-1000/l && rm -rf /tmp/claude-1000/l/proj`:                "fs",
		`bsdtar -xf a.tar -C /tmp/claude-1000 && rm -rf /tmp/claude-1000/l/proj`:                              "fs",
		`7z x a.7z -o/tmp/claude-1000 && rm -rf /tmp/claude-1000/l/proj`:                                      "fs",
		`env ln -s /work/u /tmp/claude-1000/l; rm -rf /tmp/claude-1000/l/proj`:                                "fs",
		`f() { ln -s /work/u /tmp/claude-1000/l; }; f; rm -rf /tmp/claude-1000/l/proj`:                        "fs",
		// a loop or function runs its rm again after later code
		`for i in 1 2; do rm -rf /tmp/claude-1000/l/proj; ln -s /work/u /tmp/claude-1000/l; done`: "fs",
		`f() { rm -rf /tmp/claude-1000/l/proj; }; ln -s /work/u /tmp/claude-1000/l; f`:            "fs",
		// a plain mktemp, a cd chain, a nested shell
		`S=/tmp/claude-1000/x; rm -rf $S/base && mkdir $S/base && git archive X | tar -x -C $S/base`: "",
		`S=/tmp/claude-1000/x; rm -rf $S/t; mkdir -p $S/t; cp a $S/t/`:                               "",
		`D=$(mktemp -d) && rm -rf $D`:                                                     "",
		`cd /tmp/claude-1000/x && rm -rf build`:                                           "",
		`mkdir -p /tmp/claude-1000/x && ls /tmp/claude-1000 && rm -rf /tmp/claude-1000/x`: "",
		`sh -c 'rm -rf /tmp/claude-1000/x'`:                                               "",
		`for i in 1 2; do rm -rf /tmp/claude-1000/x; done`:                                "",
		// 4: mktemp options outside the allowlist leave V unbound
		`D=$(mktemp --help) && rm -rf -- $D`:               "fs",
		`D=$(mktemp --version) && rm -rf -- $D`:            "fs",
		`D=$(mktemp -V) && rm -rf -- $D`:                   "fs",
		`D=$(mktemp -u) && rm -rf -- $D`:                   "fs",
		`D=$(mktemp --dry-run) && rm -rf -- $D`:            "fs",
		`D=$(mktemp -d -p /tmp x.XXXXXX) && rm -rf -- $D`:  "",
		`D=$(mktemp -dq --suffix=.d) && rm -rf -- $D`:      "",
		`D=$(mktemp -t --tmpdir x.XXXXXX) && rm -rf -- $D`: "",
		// 5: arithmetic can assign: no binding in the command
		`D=/tmp/claude-1000/x; : $[D=5]; rm -rf $D`:    "fs",
		`D=/tmp/claude-1000/x; : ${A[D=5]}; rm -rf $D`: "fs",
		`D=/tmp/claude-1000/x; : $((D=5)); rm -rf $D`:  "fs",
		`D=/tmp/claude-1000/x; let D=5; rm -rf $D`:     "fs",
		`D=/tmp/claude-1000/x; rm -rf $D`:              "",
	})
	repo := t.TempDir()
	for _, d := range []string{"bin", "generated/code", "var/cache"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "bin/magento"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	dCheck(t, suiteCfg(), repo, map[string]string{
		`rm -rf generated/code var/cache && bin/magento setup:upgrade`: "",
		`bin/magento setup:upgrade && rm -rf generated/code var/cache`: "fs",
	})
}

// Round 5: concurrency, repetition and indirect execution turn the allow
// paths off.
func TestDestructiveConcurrentLists(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`{ ls -R / >/dev/null; rm -rf /tmp/claude-1000/l/proj; } & ln -s /work/u /tmp/claude-1000/l`:  "fs",
		`{ ls -R / >/dev/null; rm -rf /tmp/claude-1000/l/proj; } | ln -s /work/u /tmp/claude-1000/l`:  "fs",
		`{ ls -R / >/dev/null; rm -rf /tmp/claude-1000/l/proj; } |& ln -s /work/u /tmp/claude-1000/l`: "fs",
		`(ls -R / >/dev/null; rm -rf /tmp/claude-1000/l/proj) & ln -s /work/u /tmp/claude-1000/l`:     "fs",
		`sh -c 'while :; do rm -rf /tmp/claude-1000/l/proj; done' & ln -s /work/u /tmp/claude-1000/l`: "fs",
		`rm -rf /tmp/claude-1000/l/proj & ln -s /work/u /tmp/claude-1000/l`:                           "fs",
		`rm -rf /tmp/claude-1000/l/proj | ln -s /work/u /tmp/claude-1000/l`:                           "fs",
		`{ rm -rf /tmp/claude-1000/l/proj && true; } & ln -s /work/u /tmp/claude-1000/l`:              "fs",
		`rm -rf /tmp/claude-1000/x && sh -c 'ls | ln -s /work/u /tmp/claude-1000/l'`:                  "fs",
		`S=/tmp/claude-1000/x; rm -rf $S/base && mkdir $S/base && git archive X | tar -x -C $S/base`:  "",
		`rm -rf /tmp/claude-1000/x && true | ln -s /work/u /tmp/claude-1000/l`:                        "",
		`ls & rm -rf /tmp/claude-1000/x | cat`:                                                        "",
	})
}

// A function substitution runs a body the scan reads as plain arguments: it
// asks wherever bash would expand it, and literal text does not.
func TestDestructiveFunctionSubstitution(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`echo ${ rm -rf /work/u/important; }`:             "unresolved",
		`echo "${ rm -rf /work/u/important; }"`:           "unresolved",
		"echo ${\trm -rf /work/u/important; }":            "unresolved",
		"echo $\\\n{ rm -rf /work/u/important; }":         "unresolved",
		"echo ${\\\n rm -rf /work/u/important; }":         "unresolved",
		`x=${ echo hi; }`:                                 "unresolved",
		`echo a${ rm -rf /work/u/important; }`:            "unresolved",
		`echo ${x:-${ rm -rf /work/u/important; }}`:       "unresolved",
		`echo "$(echo ${ rm -rf /work/u/important; })"`:   "unresolved",
		"echo `echo ${ rm -rf /work/u/important; }`":      "unresolved",
		`cat <<<"${ rm -rf /work/u/important; }"`:         "unresolved",
		`echo hi > ${ rm -rf /work/u/important; }`:        "unresolved",
		`sh -c 'echo ${ rm -rf /work/u/important; }'`:     "unresolved",
		"echo `echo \\${ rm -rf /work/u/important; }`":    "unresolved", // backticks unescape \$
		`eval 'echo ${ rm -rf /work/u/important; }'`:      "unresolved",
		`eval echo \${ rm -rf /work/u/important\; }`:      "unresolved",
		`trap 'echo ${ rm -rf /work/u/important; }' EXIT`: "unresolved",
		`echo "${ x }"`: "unresolved", // bash runs x
		// literal text
		`echo '${ rm -rf /work/u/important; }'`:                "",
		`echo \${ x; }`:                                        "",
		`echo $'${ x; }'`:                                      "",
		`echo ${HOME} ${#x} "${x:-y}" ${x} $x`:                 "",
		`sed -n '1,${ /x/p }' f`:                               "",
		"cat > a.js <<'EOF'\nconst s = `${ x } ${ y; }`;\nEOF": "",
		`echo '${{ github.sha }}' "${{ matrix.os }}"`:          "",
	})
}

// A reserved word that a backslash-newline splits is still that word: the
// command after it is the head.
func TestDestructiveJoinedReservedWords(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		"i\\\nf rm -rf /work/u/projects; then :; fi":             "fs",
		"wh\\\nile rm -rf /work/u/projects; do :; done":          "fs",
		"un\\\ntil rm -rf /work/u/projects; do :; done":          "fs",
		"f\\\nor x in 1; d\\\no rm -rf /work/u/projects; done":   "fs",
		"if true; t\\\nhen rm -rf /work/u/projects; fi":          "fs",
		"if false; then :; el\\\nse rm -rf /work/u/projects; fi": "fs",
		"{\\\n rm -rf /work/u/projects; }":                       "fs",
		"!\\\n rm -rf /work/u/projects":                          "fs",
		"func\\\ntion f { rm -rf /work/u/projects; }; f":         "fs",
		"cop\\\nroc rm -rf /work/u/projects":                     "fs",
		"i\\\nf git reset --hard; then :; fi":                    "git",
		"i\\\nf rm -rf /; then :; fi":                            "hard",
		"i\\\nf rm -rf ~; then :; fi":                            "hard",
		// the loop repeats the rm after the link
		"wh\\\nile true; do rm -rf /tmp/claude-1000/l/proj; ln -s /work/u /tmp/claude-1000/l; done": "fs",
		// quoted or escaped: a command of that name, its words are arguments
		`"if" rm -rf /work/u/projects`: "",
		`\if rm -rf /work/u/projects`:  "",
	})
}

// Quoting the flat scans misread: `$$` before a quote, bash's reserved `time`,
// a heredoc a shell reads after bash unescaped it, quotes nested in `"${...}"`
// or in a quoted `$(...)`.
func TestDestructiveQuotingModels(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`echo $$'\'${ rm -rf /work/u/x; }''`:                    "unresolved",
		`echo $$'\'; rm -rf /work/u/x; echo ''`:                 "fs",
		`echo $$'\'; rm -rf /; echo ''`:                         "hard",
		`echo $$'\'"$(rm -rf /work/u/x)"''`:                     "fs",
		"echo $$'\\'`rm -rf /work/u/x`''":                       "fs",
		`time { rm -rf /work/u/x; }`:                            "fs",
		`time -p { rm -rf /work/u/x; }`:                         "fs",
		`time ! rm -rf /work/u/x`:                               "fs",
		`! time { git reset --hard; }`:                          "git",
		`time { rm -rf /; }`:                                    "hard",
		`time if rm -rf /work/u/x; then :; fi`:                  "fs",
		"ti\\\nme { rm -rf /work/u/x; }":                        "fs",
		`time rm -rf /work/u/x`:                                 "fs",
		"bash <<EOF\necho \\${ rm -rf /work/u/x; }\nEOF":        "unresolved",
		"bash <<EOF\necho \\`rm -rf /work/u/x\\`\nEOF":          "fs",
		"bash <<EOF\nr\\\nm -rf /work/u/x\nEOF":                 "fs",
		"cat <<EOF | sh\necho \\`rm -rf /work/u/x\\`\nEOF":      "fs",
		`echo "${x:-"'"${ rm -rf /work/u/x; }"'"}"`:             "unresolved",
		`echo "${x:-"'"$(rm -rf /work/u/x)"'"}"`:                "fs",
		"echo \"${x:-\"'\"`rm -rf /work/u/x`\"'\"}\"":           "fs",
		`echo "${x:-'${ rm -rf /work/u/x; }'}"`:                 "unresolved",
		"echo \"${x#'}\"'}`rm -rf /work/u/x`\" #'":              "unresolved",
		`echo $'\''"$(rm -rf /work/u/x)"`:                       "fs",
		"echo $'\\''\"`rm -rf /work/u/x`\"":                     "fs",
		`echo "$(echo ')' ; rm -rf /work/u/x)"`:                 "fs",
		`echo "$(echo "'")"${ rm -rf /work/u/x; }"$(echo "'")"`: "unresolved",
		`echo "$(case x in x) rm -rf /work/u/x;; esac)"`:        "fs",
		`echo "$(echo ${x:-)}; rm -rf /work/u/x)"`:              "fs",
		"echo \"$(case\\\n a in a) rm -rf /work/u/x;; esac)\"":  "fs",
		`echo ${x:-$'\'' ${ rm -rf /work/u/x; } $'\''}`:         "unresolved",
		// a bound variable still reaches the command after time
		`X=--hard; time git reset $X`:      "git",
		`X=-rf; time rm $X /work/u/x`:      "fs",
		`X=/; time rm -rf $X`:              "hard",
		`X=--hard; time -p git reset $X`:   "git",
		"X=--hard; tim\\\ne git reset $X":  "git",
		`D=$(mktemp -d) && time rm -rf $D`: "fs",
		// plain text and what the reader gets as text
		`echo $$ "$$" '$$'; ls`:                           "",
		`echo "pid $$'s log"`:                             "",
		`time ls -la /work/u`:                             "",
		`time -p make test`:                               "",
		"bash <<'EOF'\necho \\${ x; } \\`ls\\`\nEOF":      "",
		"cat <<EOF\ncost: \\$5 \\${ x; } \\`ls\\`\nEOF":   "",
		`echo "${x:-"a b"}" "${y}" '$(rm -rf /work/u/x)'`: "",
		`echo $'it\'s $(rm -rf /work/u/x)'`:               "",
		`echo "$(echo '(' a ')' "b)")"`:                   "",
	})
}

// Code the scan never reads as a command turns the allow paths off: a bash
// 5.3 function substitution, which an expanding heredoc body runs before the
// rm written ahead of it, and the command's own text run again.
func TestDestructiveUnreadCode(t *testing.T) {
	const ln = ` ln -s /work/u /tmp/claude-1000/l`
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		"cat <<EOF; rm -rf /tmp/claude-1000/l/proj\n${" + ln + "; }\nEOF":          "unresolved",
		"cat <<EOF; rm -rf /tmp/claude-1000/l/proj\n${|" + ln + "; }\nEOF":         "unresolved",
		"cat <<EOF; rm -rf /tmp/claude-1000/l/proj\n$\\\n{" + ln + "; }\nEOF":      "unresolved",
		`rm -rf /tmp/claude-1000/l/p;` + ln + `; eval "$BASH_EXECUTION_STRING"`:    "fs",
		`rm -rf /tmp/claude-1000/l/p;` + ln + `; bash -c "$BASH_EXECUTION_STRING"`: "fs",
		// a function substitution before the rm turns the allow paths off; ponytail: raw
		// text, a quoted one too (one bash expands asks: TestDestructiveFunctionSubstitution)
		`echo '${` + ln + `; }'; rm -rf /tmp/claude-1000/l/proj`:     "fs",
		`echo '${|` + ln + `; }'; rm -rf /tmp/claude-1000/l/proj`:    "fs",
		"echo '$\\\n{" + ln + "; }'; rm -rf /tmp/claude-1000/l/proj": "fs",
		// a parameter or literal text, no substitution
		`D=/tmp/claude-1000/x; echo ${D} ${#D} $D; rm -rf ${D}/zip`:    "",
		`echo '${{ github.sha }}'; rm -rf /tmp/claude-1000/x/proj`:     "",
		"cat <<'EOF'; rm -rf /tmp/claude-1000/x\n${ x } ${ y; }\nEOF":  "",
		"cat <<EOF; rm -rf /tmp/claude-1000/x\n${HOME} \\${ x; }\nEOF": "",
	})
}

func TestDestructiveRepeatedRm(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`find . -maxdepth 1 -exec rm -rf /tmp/claude-1000/l/proj ';' -exec ln -s /work/u /tmp/claude-1000/l ';'`:    "fs",
		`find . -maxdepth 1 -execdir rm -rf /tmp/claude-1000/l/proj ';' -exec ln -s /work/u /tmp/claude-1000/l ';'`: "fs",
		`find . -maxdepth 1 -ok rm -rf /tmp/claude-1000/l/proj ';' -exec ln -s /work/u /tmp/claude-1000/l ';'`:      "fs",
		`find . -maxdepth 1 -ok rm -rf /work/u/x ';'`:                                                               "fs",
		`printf 'a\nb\n' | xargs -n1 sh -c 'rm -rf /tmp/claude-1000/l/proj; ln -s /work/u /tmp/claude-1000/l'`:      "fs",
		`xargs -a list -n1 sh -c 'rm -rf /tmp/claude-1000/x'`:                                                       "fs",
		// 3: the replace string flows into the target
		`printf '../../work/u\n' | xargs -I@ sh -c 'rm -rf /tmp/claude-1000/@'`:   "fs",
		`printf '../../work/u\n' | xargs -IQ sh -c 'rm -rf /tmp/claude-1000/Q'`:   "fs",
		`printf '../../work/u\n' | xargs -I@ bash -c 'rm -rf /tmp/claude-1000/@'`: "fs",
		`xargs -a list -I@ sh -c 'rm -rf /tmp/claude-1000/@'`:                     "fs",
		`xargs -a list -I@ rm -rf /tmp/claude-1000/@`:                             "fs",
	})
}

// Text bash may run where the scan cannot see (indirectRun) turns the allow
// paths off. Binding itself goes on, for the other categories.
func TestDestructiveIndirectExec(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`D=/tmp/claude-1000/x; echo ${V@P}; rm -rf $D`:                                             "fs",
		`D=/tmp/claude-1000/x; [[ $V -eq 0 ]]; rm -rf "$D"`:                                        "fs",
		`D=/tmp/claude-1000/x; PS4=x; set -x; rm -rf $D/y`:                                         "fs",
		`D=$(mktemp -d) && echo ${!V} && rm -rf $D`:                                                "fs",
		`D=/tmp/claude-1000/x; printf -v D /work/u; rm -rf $D`:                                     "fs",
		`D=/tmp/claude-1000/x; export $'D=/work/u'; rm -rf $D`:                                     "fs",
		`D=/tmp/claude-1000/x; export "D=/work/u"; rm -rf $D`:                                      "fs",
		`D=/tmp/claude-1000/x; $'D'=/work/u; rm -rf $D`:                                            "fs",
		`D=/tmp/claude-1000/x; echo $'a' | python3 x.py; rm -rf $D`:                                "fs",
		`D=/tmp/claude-1000/x; echo "${PIPESTATUS[0]}"; rm -rf $D`:                                 "fs",
		`D=/tmp/claude-1000/x; echo "${A[D=5]}"; rm -rf $D`:                                        "fs",
		`D=/tmp/claude-1000/x; echo "${A[0+D]}"; rm -rf $D`:                                        "fs",
		`X=--hard; echo $'a'; git reset $X`:                                                        "git",
		`X=-rf; echo ${V@P}; rm $X /work/u/x`:                                                      "fs",
		`./cat; rm -rf /tmp/claude-1000/l/proj`:                                                    "fs",
		`/tmp/claude-1000/bin/echo x; rm -rf /tmp/claude-1000/l/proj`:                              "fs",
		`PS4=$'\x24(ln -s /work/u /tmp/claude-1000/l)'; set -x; rm -rf /tmp/claude-1000/l/proj`:    "fs",
		`echo ${V@P}; rm -rf /tmp/claude-1000/l/proj`:                                              "fs",
		`[[ $'a[\x24(ln -s /work/u /tmp/claude-1000/l)]' -eq 0 ]]; rm -rf /tmp/claude-1000/l/proj`: "fs",
		`[[ $V -eq 0 ]]; rm -rf /tmp/claude-1000/l/proj`:                                           "fs",
		`[[ -v $V ]]; rm -rf /tmp/claude-1000/l/proj`:                                              "fs",
		`test -v $V; rm -rf /tmp/claude-1000/l/proj`:                                               "fs",
		`echo $((V)); rm -rf /tmp/claude-1000/l/proj`:                                              "fs",
		`echo ${a:V}; rm -rf /tmp/claude-1000/l/proj`:                                              "fs",
		`echo ${!V}; rm -rf /tmp/claude-1000/l/proj`:                                               "fs",
		`set -ex; rm -rf /tmp/claude-1000/l/proj`:                                                  "fs",
		`set -o xtrace; rm -rf /tmp/claude-1000/l/proj`:                                            "fs",
		`printf -v P4 x; rm -rf /tmp/claude-1000/l/proj`:                                           "fs",
		`PROMPT_COMMAND=x; rm -rf /tmp/claude-1000/l/proj`:                                         "fs",
		`BASH_ENV=/tmp/claude-1000/e; sh -c 'rm -rf /tmp/claude-1000/l/proj'`:                      "fs",
		`export ENV=/tmp/claude-1000/e; rm -rf /tmp/claude-1000/l/proj`:                            "fs",
		`PATH=/tmp/claude-1000/b:$PATH; cat x; rm -rf /tmp/claude-1000/l/proj`:                     "fs",
		`CDPATH=/work/u; cd x && rm -rf build`:                                                     "fs",
		`echo ok; rm -rf /tmp/claude-1000/l/proj`:                                                  "",
	})
}

func TestDestructiveTrapBody(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`trap 'rm -rf /work/u/x' EXIT`:                                                 "fs",
		`trap -- 'rm -rf /work/u/x' EXIT`:                                              "fs",
		`trap 'rm -rf /tmp/claude-1000/l/proj' EXIT; ln -s /work/u /tmp/claude-1000/l`: "fs",
		`trap 'echo bye' EXIT`:                                                         "",
		`trap -p`:                                                                      "",
	})
}

// Round 6: bash evaluates array subscripts in builtin arguments, and a
// locale string `$""` splits a `$(` the scan would otherwise see.
func TestDestructiveSubscriptArgs(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`V="x[$""(ln -s /work/u /tmp/claude-1000/l)]"; a=x; unset 'a[V]'; rm -rf /tmp/claude-1000/l/proj`:     "fs",
		`V="x[$""(ln -s /work/u /tmp/claude-1000/l)]"; a=x; export -n 'a[V]'; rm -rf /tmp/claude-1000/l/proj`: "fs",
		`unset 'a[V]'; rm -rf /tmp/claude-1000/l/proj`:                                                        "fs",
		`export -n 'a[V]'; rm -rf /tmp/claude-1000/l/proj`:                                                    "fs",
		`local 'a[V]'=1; rm -rf /tmp/claude-1000/l/proj`:                                                      "fs",
		`echo $"x"; rm -rf /tmp/claude-1000/l/proj`:                                                           "fs",
		`unset V; rm -rf /tmp/claude-1000/l/proj`:                                                             "",
	})
}

// Round 6: GNU env takes every leading word with `=` as an assignment.
func TestDestructiveEnvAssignWords(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`rm -rf /work/u/proj`:                       "fs",
		`env 'X%=1' rm -rf /work/u/proj`:            "fs",
		`env 'X%=1' sh -c 'rm -rf /work/u/proj'`:    "fs",
		`env -i 'a b=1' 'X%=1' rm -rf /work/u/proj`: "fs",
		`env X=1 'Y-Z=2' nice rm -rf /work/u/proj`:  "fs",
	})
}

// A leading unquoted ~/ in a value expands like $HOME (unresolved
// asks on `T=~/x/tsc; $T ...`). A variable the scan cannot read still asks:
// unquoted, bash splits it and runs its first word.
func TestDestructiveTildeValueAndUnknownHead(t *testing.T) {
	dCheck(t, suiteCfg(), "/work/u/repo", map[string]string{
		`T=~/p/node_modules/.bin/tsc; $T --noEmit --strict`:  "",
		`T=~/p/node_modules/.bin/tsc && "$T" --noEmit`:       "",
		`T=~/bin/rm; $T -r /var/app/data`:                    "fs",
		`T=~/bin/tsc; T=rm; $T -r /var/app/data`:             "fs",
		`T="~/bin/tsc"; $T --noEmit`:                         "unresolved",
		`T=~other/bin/tsc; $T --noEmit`:                      "unresolved",
		`T=a:~/bin/tsc; $T --noEmit`:                         "unresolved",
		`HOME=/x; T=~/bin/tsc; $T --noEmit`:                  "unresolved",
		`export HO''ME=/x; T=~/bin/tsc; $T --noEmit`:         "unresolved",
		`$B/vitest run`:                                      "unresolved",
		`B=$PWD/x; $B/vitest run`:                            "unresolved",
		`B=$PWD; ${B}it reset --hard`:                        "unresolved",
		`true && D="git clean -fd /var/app"; $D/data /srv/x`: "unresolved",
	})
}

// Pre-existing bindVars gaps: a value ending in
// a space before a word-start character (# comment, ~ tilde) in the
// rewritten text.
func TestDestructiveVarGapComment(t *testing.T) {
	cfg := suiteCfg()
	for _, cmd := range []string{
		`B="x "; $B#y; git reset --hard`,
		`B="x "; echo $B#y; git reset --hard`,
		`B=echo; Ba="git reset --hard"; $B{a,} x`,
		// brace expansion runs before parameter expansion
		`B=x; Bx="reset --hard"; git {$B,}x`,
		`B=x; Bx="git reset --hard"; {$B,}x y`,
		`B=x; Bx="git reset --hard"; {a..b}$B; c{"$B",}x y`,
		// a brace head is never a lone word: it expands to several
		`B=x; Bx="git reset --hard"; {$B,}x`,
		`B=echo; Ba="git reset --hard"; $B{a,}`,
		`B=x; Bx="git reset --hard"; command {$B,}x`,
		`B="git reset --hard"; {$B,}`,
	} {
		if d := dApply(cfg, cmd, ""); d == nil {
			t.Errorf("%q: allowed", cmd)
		}
	}
	dCheck(t, cfg, "/work/u/repo", map[string]string{
		`B="x "; echo $B "#y"`:                         "",
		`D=/tmp/claude-1000/x; rm -rf $D/zip #note`:    "",
		`D=/tmp/claude-1000/x; rm -rf ${D}/a "${D}/b"`: "",
	})
}

// A command word bash expands could be a writer (read, printf -v, ...):
// bindings are unresolved after it unless it resolves to a non-writer.
func TestDestructiveVarGapHiddenWriter(t *testing.T) {
	cfg := suiteCfg()
	for _, w := range []string{
		`R=read; $R D`, `R="read -r"; $R D`, `C=command; $C read D`, `R=/usr/bin/mapfile; "$R" D`,
		`$(echo read) D`, "`echo read` D", `$X D`, `{read,D}`,
		`C=command; R=read; $C $R D`, `C=builtin; R=read; $C $R D`, `C="command -p"; R=read; $C $R D`,
		`C=command; $C {read,D}`,
	} {
		cmd := `D=/x; ` + w + ` <<< 'git clean -fd /var/app'; $D/data /srv/x`
		if d := dApply(cfg, cmd, ""); d == nil {
			t.Errorf("%q: allowed", cmd)
		}
	}
	for _, cmd := range []string{
		`P="printf -v"; D=/x; $P D 'git clean -fd /var/app'; $D/data /srv/x`,
		`R=read; D=/x; $R D <<< 'git clean -fd /var/app'; E=$D; $E/data /srv/x`,
		`R=read; D=/x; $R D <<< 'git clean -fd /var/app' && $D/data /srv/x`,
		`R=read; D=/x; for i in 1 2; do $D/data /srv/x; $R D <<< 'git clean -fd /var/app'; done`,
		`R=read; D=/x; if true; then $R D <<< 'git clean -fd /var/app'; fi; $D/data /srv/x`,
		// a literal writer whose name or option bash expands
		`V=D=/var/app; D=/tmp/claude-1000/x; export $V; rm -rf $D/data`,
		`V=D=/var/app; D=/tmp/claude-1000/x; readonly $V; rm -rf $D/data`,
		`V=-v; D=/tmp/claude-1000/x; printf $V D /var/app; rm -rf $D/data`,
		`V=-v; D=/tmp/claude-1000/x; printf -- $V; printf "$V" D /var/app; rm -rf $D/data`,
	} {
		if d := dApply(cfg, cmd, ""); d == nil {
			t.Errorf("%q: allowed", cmd)
		}
	}
	dCheck(t, cfg, "/work/u/repo", map[string]string{
		`T=/abs/tsc; G=/abs/eslint; $T --noEmit; $G .`:                             "",
		`T=/abs/tsc; G=/abs/eslint; for f in a b; do $T $f; done; $G .`:            "",
		`T=/abs/tsc; G=/abs/eslint; [ -x $T ] && "$T" --noEmit && ${G} .`:          "",
		`X=1; export FOO=$X; D=/tmp/claude-1000/x; rm -rf $D/data`:                 "",
		`D=/tmp/claude-1000/x; printf '%s\n' "$D"; printf -- "$D"; rm -rf $D/data`: "",
	})
}

// A ten-fold assignment chain, or thousands of copies of a 16 KiB value,
// is cut off by a budget, not expanded past the deadline.
func TestDestructiveVarGapValueSize(t *testing.T) {
	chain := "a=xxxxxxxx"
	for c := 'b'; c <= 'h'; c++ {
		chain += "; " + string(c) + "=" + strings.Repeat("$"+string(c-1), 10)
	}
	x := func(n int) string { return strings.Repeat("x", n) }
	for name, cmd := range map[string]string{
		"chain":  chain + "; echo $h",
		"copies": "a=" + x(4000) + "; b=$a$a$a$a\n" + strings.Repeat("c=$b\n", 2400) + "echo $c",
		// command words: each resolves a long value and re-tokenizes it
		"heads":      "a=" + x(2000) + "; " + strings.Repeat("$a;", 4600),
		"long heads": "a=" + x(3000) + "; b=$a$a$a$a; " + strings.Repeat("$b;", 1000),
		"huge heads": "a=" + x(14000) + "; b=$a$a$a$a; " + strings.Repeat("$b;", 600),
		// one word: the rewrite copies every $b before its cap applies
		"one word": "a=" + x(14000) + "; b=$a$a$a$a; echo " + strings.Repeat("$b", 600),
	} {
		cmd += "; git reset --hard"
		// the deadline fails open (nil): the verdict must arrive before it
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		start := time.Now()
		d := destructive{}.Apply(ctx, dIn(cmd, "", "/work/u/repo"), suiteCfg(), nil)
		cancel()
		if d == nil {
			t.Errorf("%s, %d bytes: allowed after %v", name, len(cmd), time.Since(start))
		}
	}
}

func TestGitAllowActionsExemptsMainOnly(t *testing.T) {
	cfg := suiteCfg()
	cfg.Rules.Destructive.Git.AllowActions = []string{"rebase"}
	for _, cmd := range []string{
		`git rebase --onto topic-base 1a2b3c4d topic-docs`,
		`git -C /repo rebase main`,
		`cd wt && git rebase --continue`,
	} {
		if d := dApply(cfg, cmd, ""); d != nil {
			t.Errorf("allowed action must pass for the main agent: %q got %+v", cmd, d)
		}
		if d := dApply(cfg, cmd, "agent-1"); d == nil || d.Permission != "deny" {
			t.Errorf("a subagent is not exempted: %q got %+v", cmd, d)
		}
		if d := dApply(suiteCfg(), cmd, ""); d == nil || d.Permission != "ask" {
			t.Errorf("without allow_actions it still asks: %q got %+v", cmd, d)
		}
	}
}

func TestGitAllowActionsKeepsOtherActionsAndCommandRunners(t *testing.T) {
	cfg := suiteCfg()
	cfg.Rules.Destructive.Git.AllowActions = []string{"rebase"}
	for _, cmd := range []string{
		`git clean -fd`,
		`git rebase main && git clean -fd`,
		`git push --force origin main`,
		// a rebase that runs a command or an editor is not the allowed rebase
		`git rebase -x 'rm -rf build' main`,
		`git rebase --exec='make clean' main`,
		`git rebase --exec 'make clean' main`,
		`git rebase --ex 'make clean' main`,
		`git rebase -ix true main`,
		`git rebase -i main`,
		`git rebase --interactive main`,
		`git rebase --edit-todo`,
		`git -c sequence.editor='rm -rf x' rebase main`,
		`git --config-env=core.editor=E rebase main`,
	} {
		if d := dApply(cfg, cmd, ""); d == nil || d.Permission != "ask" {
			t.Errorf("must still ask: %q got %+v", cmd, d)
		}
	}
	cfg.Rules.Destructive.Git.AllowActions = []string{"clean"}
	if d := dApply(cfg, `git clean -fd`, ""); d != nil {
		t.Errorf("clean allowed in the global file must pass, got %+v", d)
	}
}

func dEdit(tool, key, path, agent string) *hook.Decision {
	ti, _ := json.Marshal(map[string]string{key: path})
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: tool, ToolInput: ti, AgentID: agent, Cwd: "/work/u/repo", ScratchpadDir: dScratch}
	return destructive{}.Apply(context.Background(), in, suiteCfg(), nil)
}

func TestPolicyFileWritesAsk(t *testing.T) {
	for _, p := range []string{"/work/u/.claude/policy.toml", "/work/u/repo/.claude/policy.toml", ".claude/policy.toml",
		"/work/u/repo/.claude/worktrees/lane/.claude/policy.toml"} {
		for _, tool := range []string{"Edit", "Write", "MultiEdit"} {
			if d := dEdit(tool, "file_path", p, ""); d == nil || d.Permission != "ask" || !strings.Contains(d.Reason, "policy") {
				t.Errorf("%s %s: main must be asked, got %+v", tool, p, d)
			}
			if d := dEdit(tool, "file_path", p, "agent-1"); d == nil || d.Permission != "deny" {
				t.Errorf("%s %s: a subagent must be denied, got %+v", tool, p, d)
			}
		}
	}
	for _, p := range []string{"/work/u/repo/.claude/settings.json", "/work/u/repo/testdata/case.policy.toml", "/work/u/repo/docs/.claude/policy.toml.md", ""} {
		if d := dEdit("Edit", "file_path", p, ""); d != nil {
			t.Errorf("%q is not a policy file, got %+v", p, d)
		}
	}
	for _, cmd := range []string{
		`echo 'mode = "off"' >> .claude/policy.toml`,
		`sed -i 's/enforce/off/' ~/.claude/policy.toml`,
		`cp /tmp/claude-1000/p.toml /work/u/repo/.claude/policy.toml`,
		`sh -c "printf x > $HOME/.claude/policy.toml"`,
		`tee .claude/policy.toml < /tmp/claude-1000/p.toml`,
	} {
		if d := dApply(suiteCfg(), cmd, ""); d == nil || d.Permission != "ask" || !strings.Contains(d.Reason, "policy") {
			t.Errorf("bash write must ask: %q got %+v", cmd, d)
		}
		if d := dApply(suiteCfg(), cmd, "agent-1"); d == nil || d.Permission != "deny" {
			t.Errorf("bash write by a subagent must be denied: %q got %+v", cmd, d)
		}
	}
	if d := dApply(suiteCfg(), `echo .claude/settings.json; ls .claude`, ""); d != nil {
		t.Errorf("no policy file named, got %+v", d)
	}
}

// Review: a write that never names .claude/policy.toml as one word.
func TestPolicyFileWritesThroughDirectory(t *testing.T) {
	// reached through a symlinked or renamed directory: the file name alone counts
	for _, p := range []string{"/tmp/cl/policy.toml", "/work/u/repo/policy.toml"} {
		if d := dEdit("Write", "file_path", p, ""); d == nil || d.Permission != "ask" {
			t.Errorf("Write %s: main must be asked, got %+v", p, d)
		}
	}
	for _, cmd := range []string{
		`cp /tmp/claude-1000/evil/policy.toml ~/.claude/`,
		`install -m600 -t ~/.claude /tmp/claude-1000/evil/policy.toml`,
		`cd .claude && echo 'mode = "off"' > policy.toml`,
		`ln -s ~/.claude /tmp/claude-1000/cl`,
		`cp -r /tmp/claude-1000/evil/. .claude/`,
		`mv /tmp/claude-1000/evil sub/.claude`,
		`rsync -a /tmp/claude-1000/evil/ /work/u/.claude/`,
		`tar -C ~/.claude -xf /tmp/claude-1000/x.tar`,
		`cp --target-directory=/work/u/repo/.claude /tmp/claude-1000/x`,
		`sh -c 'ln -s "$HOME/.claude" /tmp/claude-1000/cl'`,
	} {
		if d := dApply(suiteCfg(), cmd, ""); d == nil || d.Permission != "ask" || !strings.Contains(d.Reason, "policy") {
			t.Errorf("must ask: %q got %+v", cmd, d)
		}
		if d := dApply(suiteCfg(), cmd, "agent-1"); d == nil || d.Permission != "deny" {
			t.Errorf("a subagent must be denied: %q got %+v", cmd, d)
		}
	}
	for _, cmd := range []string{`ls .claude`, `ls ~/.claude/`, `cat .claude/settings.json`, `cp a.txt b.txt`,
		`cp x.md .claude/worktrees/lane/docs/`, `git worktree add .claude/worktrees/lane`, `tar -tf /tmp/claude-1000/x.tar`} {
		if d := dApply(suiteCfg(), cmd, ""); d != nil {
			t.Errorf("no policy write: %q got %+v", cmd, d)
		}
	}
}

// Review: the policy scan must not make depth-4 nesting ask (the
// rule's own limit is deeper than bashSensitive's).
func TestPolicyScanKeepsDepthFourSilent(t *testing.T) {
	for _, cmd := range []string{`eval eval eval eval ls`, `x=$(y=$(z=$(w=$(git log -1))))`, `bash -c "bash -c 'bash -c \"bash -c ls\"'"`} {
		if d := dApply(suiteCfg(), cmd, ""); d != nil {
			t.Errorf("%q got %+v", cmd, d)
		}
	}
}

func TestGitAllowedRebaseWithExecPathAsks(t *testing.T) {
	cfg := suiteCfg()
	cfg.Rules.Destructive.Git.AllowActions = []string{"rebase"}
	for _, cmd := range []string{`git --exec-path=/tmp/claude-1000/bin rebase main`} {
		if d := dApply(cfg, cmd, ""); d == nil || d.Permission != "ask" {
			t.Errorf("%q got %+v", cmd, d)
		}
	}
}

// An rm target depends on the shell's directory, HOME, options and
// variables, and on rm being rm: it asks once the command does something the
// scan does not follow.
func TestDestructiveShellState(t *testing.T) {
	const cwd = "/tmp/claude-1000/w"
	const abs = "rm -rf " + cwd + "/x"
	dCheck(t, suiteCfg(), cwd, map[string]string{
		// a program is not followed: the shell may start with a function or
		// an alias of its name
		`rm -rf build`:                 "",
		`python3 gen.py; rm -rf build`: "fs",
		`git status && /usr/bin/php x.php | head -3; rm -rf build`:      "fs",
		`for i in 1 2; do curl -s localhost; rm -rf build; done`:        "fs",
		`make 2>&1 | tail -3; echo "rc=${PIPESTATUS[0]}"; rm -rf build`: "fs",
		`X=1 node x.js && cd ` + cwd + `/y && rm -rf build`:             "fs",
		// the shell's own words
		`shopt -s dotglob; rm -rf build`:                                                           "fs",
		`source ./env.sh; rm -rf build`:                                                            "fs",
		`. ./env.sh && rm -rf build`:                                                               "fs",
		`eval "$(tool env)"; rm -rf build`:                                                         "fs",
		`f() { cd /work/u; }; f; rm -rf build`:                                                     "fs",
		`f() { :; }; python3 gen.py; rm -rf build`:                                                 "fs",
		`f() { rm -rf build; }; cd /work/u/proj && f`:                                              "fs",
		`for d in /work/u/a /work/u/b; do rm -rf build; cd $d; done`:                               "fs",
		`$(echo cd /work/u); rm -rf build`:                                                         "fs",
		`X="cd /work/u"; $X; rm -rf build`:                                                         "fs",
		`set -- cd /work/u; "$@"; rm -rf build`:                                                    "fs",
		`f() { "$@"; }; f cd /work/u; rm -rf build`:                                                "fs",
		`read X <<< "cd /work/u"; $X; rm -rf build`:                                                "fs",
		`A="cd /work/u"; trap "$A" DEBUG; rm -rf build`:                                            "fs",
		`trap 'cd /work/u' DEBUG; cd ` + cwd + ` && rm -rf build`:                                  "fs",
		`for i in 1 2; do rm -rf build; trap 'cd /work/u' DEBUG; done`:                             "fs",
		`cd() { pushd /work/u; }; cd ` + cwd + ` && rm -rf build`:                                  "fs",
		`alias cd='cd /work/u;'` + "\n" + `cd ` + cwd + ` && rm -rf build`:                         "fs",
		`enable -n cd; cd ` + cwd + `/y && rm -rf build`:                                           "fs",
		`! cd ` + cwd + `/nonexist && rm -rf build`:                                                "fs",
		`env -C /work/u rm -rf build`:                                                              "fs",
		`sudo -D /work/u rm -rf build`:                                                             "fs",
		`rm -rf build; cd /work/u; bash -c "$BASH_EXECUTION_STRING"`:                               "fs",
		`BASH_ENV=./env.sh bash -c 'rm -rf build'`:                                                 "fs",
		`env 'BASH_FUNC_cd%%=() { builtin cd /work/u; }' bash -c 'cd ` + cwd + ` && rm -rf build'`: "fs",
		// text bash evaluates in the shell: a function substitution, however spelled
		`a=(x); unset 'a[${ cd /work/u; }]'; rm -rf build`:                "fs",
		`a=(x); unset 'a[$'"{ cd /work/u; }]"; rm -rf build`:              "fs",
		`[ -v 'a[$'"{ cd /work/u; }]" ]; rm -rf build`:                    "fs",
		`V='x[${ cd /work/u; }]'; (( V )); rm -rf build`:                  "fs",
		`A="\$"; B="{ cd /work/u; }"; V="x[$A$B]"; (( V )); rm -rf build`: "fs",
		`[[ $'x[\x24{ cd /work/u; }]' -eq 0 ]]; rm -rf build`:             "fs",
		`PS4='$''{ cd /work/u; }'; set -x; rm -rf build`:                  "fs",
		`A="\$"; B="{ cd /work/u; }"; PS4="$A$B"; set -x; rm -rf build`:   "fs",
		`read V <<< '$''{ cd /work/u; }'; echo "${V@P}"; rm -rf build`:    "fs",
		`PS4='${ cd /work/u; }'; set -x; cd ` + cwd + ` && rm -rf build`:  "fs",
		// an absolute target is no exception: binding, aliases and the
		// command hash can all change what it names
		`shopt -s dotglob; source ./env.sh; cd /work/u; ` + abs:           "fs",
		`PS4='${ cd /work/u; }'; set -x; trap 'cd /work/u' DEBUG; ` + abs: "fs",
		`f() { cd /work/u; }; f; for i in 1 2; do ` + abs + `; done`:      "fs",
		`python3 gen.py | tee log & ` + abs + ` | cat`:                    "fs",
		// rm, or the wrapper before it, may not be what the scan reads
		`hash -p /usr/bin/rm timeout; timeout /work/u ` + abs:                  "fs",
		`builtin hash -p /usr/bin/rm nice; nice ` + abs:                        "fs",
		`declare BASH_CMDS[timeout]=/usr/bin/rm; timeout /work/u ` + abs:       "fs",
		`printf -v 'BASH_CM''DS[timeout]' /usr/bin/rm; timeout /work/u ` + abs: "fs",
		`read 'BASH_ALIASES[rm]' <<< 'rm -rf /work/u #'` + "\n" + abs:          "fs",
		`N=BASH_; printf -v "${N}ALIASES[rm]" 'rm /work/u #'` + "\n" + abs:     "fs",
		// an assignment word before the command is not the command
		`a+=x rm -rf /`:                        "hard",
		`a+=x rm -rf /work/u/proj`:             "fs",
		`a[0]=x b[i+1]+=y rm -rf /work/u/proj`: "fs",
		`a+=x git reset --hard`:                "git",
		`a+=x cd /work/u; rm -rf build`:        "fs",
		// $_ is the last argument of the command before, whatever was assigned
		`_=--hard X=$_; git reset $X`:      "git",
		`_=/ D=$_; rm -rf $D`:              "hard",
		`echo /work/u/proj; rm -rf "${_}"`: "fs",
		// an expansion in an assignment word is not a command word
		`a+=$X true`:                  "",
		`a+=$(git reset --hard) true`: "git",
		// a builtin that writes one variable leaves the others bound
		`X=--hard; compgen -W x; git reset $X`:                "git",
		`X=--force; sleep 1 & wait -np V; git push $X`:        "git",
		`X=/; compgen -W x; rm -rf $X`:                        "hard",
		`D=` + cwd + `/x; compgen -V D -W /work/u; rm -rf $D`: "fs",
		`D=` + cwd + `/x; sleep 0 & wait -np D; rm -rf $D`:    "fs",
		`D=` + cwd + `/x; exec {a[D=5]}>/dev/null; rm -rf $D`: "fs",
		`D=` + cwd + `/x; coproc D { sleep 1; }; rm -rf $D`:   "fs",
		// an extended glob: the scan reads the target up to its "("
		`rm -rf /tmp/claude-1000/@(w)/../../work/u`:             "fs",
		`rm -rf ` + cwd + `/!(keep)`:                            "fs",
		`rm -rf ` + cwd + `/x /tmp/claude-1000/+(w)/../../etc`:  "fs",
		`rm -rf var/@(log|cache)`:                               "fs",
		`cd /tmp/claude-1000/@(w)/../../work/u && rm -rf build`: "fs",
		// a per-process path is not the hook's
		`rm -rf /proc/self/cwd/x`:                                          "fs",
		`cd /proc/self && rm -rf cwd/x`:                                    "fs",
		`shopt -s expand_aliases; alias rm='rm -rf /work/u '` + "\n" + abs: "fs",
		`rm() { command rm "$@" /work/u; }; ` + abs:                        "fs",
		`function rm { /usr/bin/rm "$@" /work/u; }; ` + abs:                "fs",
		`nice() { cd /work/u; shift; }; nice ` + abs:                       "fs",
		`for i in 1 2; do ` + abs + `; eval 'rm() { echo; }'; done`:        "fs",
		`enable -f /work/u/lib.so rm; ` + abs:                              "fs",
		`X=alias; $X rm=echo; ` + abs:                                      "fs",
		`env 'BASH_FUNC_rm%%=() { echo; }' bash -c '` + abs + `'`:          "fs",
		// what still asks whatever else runs
		`ls | xargs ` + abs:                             "fs",
		abs + `/../../y`:                                "fs",
		`rm -rf ` + cwd + `/*`:                          "fs",
		`rm -rf "$D"`:                                   "fs",
		`python3 gen.py; rm -rf /work/u/proj`:           "fs",
		abs + ` /work/u/proj`:                           "fs",
		`trap '` + abs + `' EXIT`:                       "fs",
		`find . -name x -exec ` + abs + ` +`:            "fs",
		`_=` + cwd + `/x; echo /work/u/proj; rm -rf $_`: "fs",
	})
	home := t.TempDir()
	repo := filepath.Join(home, "p")
	for _, d := range []string{".git", "var/cache", "pub/static/frontend"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	dCheck(t, suiteCfg(), repo, map[string]string{
		`rm -rf ~/p/var/cache`:                               "",
		`php bin/x; rm -rf pub/static/*`:                     "fs",
		`HOME=/opt; rm -rf ~/p/var/cache`:                    "fs",
		`read HOME <<< /opt; rm -rf ~/p/var/cache`:           "fs",
		`declare -n R=HOME; R=/opt; rm -rf ~/p/var/cache`:    "fs",
		`printf -v HOME %s /opt; cd ~/p && rm -rf var/cache`: "fs",
		`GLOBIGNORE=x; rm -rf pub/static/*`:                  "fs",
		`export HO''ME=/opt; rm -rf ~/p/var/cache`:           "fs",
		`echo HO$@ME; export $_=/opt; rm -rf ~/p/var/cache`:  "fs",
		`set -- HOME; export $1=/opt; rm -rf ~/p/var/cache`:  "fs",
		`bash -O dotglob -c 'rm -rf pub/static/*'`:           "fs",
		`N=HO; printf -v ${N}ME /opt; rm -rf ~/p/var/cache`:  "fs",
		`export GLOBIGNO\RE=x; rm -rf pub/static/*`:          "fs",
		`shopt -s dotglob; rm -rf pub/static/*`:              "fs",
	})
}
