package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/hook"
)

func spInput(tool string, ti map[string]string, agent string) *hook.Input {
	b, _ := json.Marshal(ti)
	return &hook.Input{HookEventName: "PreToolUse", ToolName: tool, ToolInput: b, AgentID: agent, Cwd: "/x/proj"}
}

func TestSensitivePaths(t *testing.T) {
	bash := func(c string) (string, map[string]string) { return "Bash", map[string]string{"command": c} }
	read := func(p string) (string, map[string]string) { return "Read", map[string]string{"file_path": p} }
	cases := []struct {
		name  string
		tool  string
		ti    map[string]string
		entry string // "" = no finding
	}{
		{"read abs", "Read", map[string]string{"file_path": "/x/proj/.env"}, ".env"},
		{"read example", "Read", map[string]string{"file_path": "/x/proj/.env.example"}, ""},
		{"read dist", "Read", map[string]string{"file_path": "/x/proj/app/etc/env.php.dist"}, ""},
		{"read relative", "Read", map[string]string{"file_path": "app/etc/env.php"}, "app/etc/env.php"},
		{"read other env.php", "Read", map[string]string{"file_path": "/x/proj/vendor/env.php"}, ""},
		{"edit", "Edit", map[string]string{"file_path": "/x/proj/auth.json"}, "auth.json"},
		{"write dotdot", "Write", map[string]string{"file_path": "/x/proj/sub/../.env"}, ".env"},
		{"multiedit", "MultiEdit", map[string]string{"file_path": "auth.json"}, "auth.json"},
		{"notebook", "NotebookEdit", map[string]string{"notebook_path": "/x/.env"}, ".env"},
		{"grep glob", "Grep", map[string]string{"pattern": "KEY", "glob": ".env*"}, ".env"},
		{"grep glob deep", "Grep", map[string]string{"pattern": "KEY", "glob": "**/auth.json"}, "auth.json"},
		{"grep glob app/etc", "Grep", map[string]string{"pattern": "db", "path": "/x/proj/app/etc", "glob": "*.php"}, "app/etc/env.php"},
		{"grep glob php root", "Grep", map[string]string{"pattern": "db", "glob": "*.php"}, ""},
		{"grep glob json", "Grep", map[string]string{"pattern": "x", "glob": "*.json"}, ""},
		{"grep path file", "Grep", map[string]string{"pattern": "x", "path": "/x/proj/.env"}, ".env"},
		{"grep path dir", "Grep", map[string]string{"pattern": "x", "path": "/x/proj"}, ""},
		{"cat", "", nil, ".env"},
	}
	cases[len(cases)-1].tool, cases[len(cases)-1].ti = bash("cat .env")
	for _, c := range []struct{ cmd, entry string }{
		{"sed -n 1p app/etc/env.php", "app/etc/env.php"},
		{"grep -r KEY auth.json", "auth.json"},
		{"cat < .env", ".env"},
		{"cat <.env", ".env"},
		{"echo x 2>/dev/null >>.env", ".env"},
		{"head -c 10 \"$(echo .env)\"", ".env"},
		{"head -c 10 $(echo .env)", ".env"},
		{"wc -c \"`echo auth.json`\"", "auth.json"},
		{"sh -c 'cat .env'", ".env"},
		{"sudo bash -lc \"cat .env\"", ".env"},
		{"eval 'cat .env'", ".env"},
		{"sh -c \"sh -c 'cat .env'\"", ".env"},
		{"bash <<EOF\ncat .env\nEOF", ".env"},
		{"cat <<'EOF' | sh\ncat .env\nEOF", ".env"},
		{"echo 'cat .env' | bash", ".env"},
		{"cp .env /tmp/x", ".env"},
		{"cat ./.e\"n\"v", ".env"},
		{"cat .en?", ".env"},
		{"cat .en{v,}", ".env"},
		{"cat app/etc/*", "app/etc/env.php"},
		{"F=.env; cat $F", ".env"},
		{"jq . --arg-file=auth.json", "auth.json"},
		{"echo hi; cd /x && less /x/proj/.env", ".env"},
		{"echo 'it'\"'\"'s' \"$(cat .env)\" 'x'", ".env"},
		// Review
		{"cat .e\\\nnv", ".env"}, // 2: backslash-newline joins
		{"cat $'.env'", ".env"},  // 3: ANSI-C quoting
		{"cat $'\\x2eenv'", ".env"},
		{"cat $\".env\"", ".env"},
		{"cat<.env", ".env"}, // 6: attached redirection
		{"git push>.env", ".env"},
		{"bash <<<'cat .env'", ".env"}, // 5: here-string into a shell
		{"su -c 'cat .env'", ".env"},
		{"x=`cat <<'EOF'\nhi\nEOF`; cat .env", ".env"},
		{"echo ok # cat .env", ""}, // 7: comments run nothing
		{"bash x.sh # cat .env", ""},
		{"cat README.md", ""},
		{"echo envfile", ""},
		{"ls", ""},
		{"ls *.json *", ""},
		{"cat .env.example", ""},
		{"cat <<'EOF'\n.env\nEOF", ""}, // data heredoc: text, not a path
		{"grep -F '$(cat .env)' notes.txt", ""},
		// Review round 2
		{"echo $(# ) '\ncat .env\n#'\n)", ".env"}, // 2: a comment in $(...) runs to the newline
		{"x=`# ) '\ncat .env\n#'\n`", ".env"},
		{"x=$(cat <<EOF\nEOFX '\nEOF\n)\ncat .env\n#'", ".env"}, // 1
		{"x=$(cat <<'EOF'\nEOF is .env\nEOF\n)", ""},
		// inline interpreter code reading a sensitive file
		{`cd /work/u/shop && PW="$(php -r '$c=include "app/etc/env.php"; echo $c["db"]["connection"]["default"]["password"];')" && mariadb -p"$PW" -e "SELECT 1"`, "app/etc/env.php"},
		{`export MYSQL_PWD=$(php8.4 -r '$e=include "app/etc/env.php"; echo $e["db"]["connection"]["default"]["password"];'); mariadb -e "SELECT 1"`, "app/etc/env.php"},
		{`MYSQL_PWD=$(php8.4 -r '$e=include "app/etc/env.php"; echo $e["db"];' 2>/dev/null) mariadb -e "SELECT 1"`, "app/etc/env.php"},
		{`/usr/bin/php8.3 -r 'var_dump(include __DIR__."/app/etc/env.php");'`, "app/etc/env.php"},
		{`sudo -u www php -r'include("app/etc/env.php");'`, "app/etc/env.php"},
		{`python3 -c "print(open('.env').read())"`, ".env"},
		{`python3.12 -Ic "open('.env')"`, ".env"},
		{`node -e "require('fs').readFileSync('/x/auth.json')"`, "auth.json"},
		{`node --eval="fs.readFileSync('.env')"`, ".env"},
		{`node -p 'x("auth.json")'`, "auth.json"},
		{`perl -lne 'open(F, ".env")'`, ".env"},
		{`ruby -e 'File.read(".env")'`, ".env"},
		{`sh -c "php -r 'include \"app/etc/env.php\";'"`, "app/etc/env.php"},
		{"php <<'EOF'\n<?php $c = include 'app/etc/env.php';\nEOF", "app/etc/env.php"},
		{"python3 - <<EOF\nprint(open('.env').read())\nEOF", ".env"},
		{`python3 <<<'open(".env")'`, ".env"},
		{`php -r 'echo PHP_VERSION;'`, ""},
		{`node -e "console.log(process.env.HOME)"`, ""},
		{`python3 -c "import os; print(os.environ['X'])"`, ""},
		{`php -r 'echo $_ENV["X"];'`, ""},
		{`python3 -c "import x; x.environment"`, ""},
		{"cat <<'EOF'\ninclude 'app/etc/env.php'\nEOF", ""}, // data heredoc: not an interpreter
		// quoted words are literal: no glob matching
		{`cd /w/p9r3; grep -h "P3D_GREP" tests/packet/*.packet | grep -v "^#" | grep -o "P3D_GREP=.*" | sort -u`, ""},
		{`grep -o 'X=.*' f`, ""},
		{`ls ".*"`, ""},
		{`cat '.en?'`, ""},
		{`cat ".env"`, ".env"},
		{"cat .*", ".env"},
		{"ls .env*", ".env"},
		{`cat ".env"*`, ".env"}, // the unquoted * still globs
		{`cat app/etc/"env".*`, "app/etc/env.php"},
		{`cat '.e'*`, ".env"},
		{`ls "x"'.*'`, ""},
		{`grep -o "a\"b.*" f`, ""}, // escaped quote inside double quotes
		// a quoted glob a tool matches itself still counts
		{`find . -name '.env*' -exec cat {} +`, ".env"},
		{`find . -name ".env*" | xargs cat`, ".env"},
		{`grep -r --include='.env*' PASS .`, ".env"},
		{`rg --hidden -g '.env*' PASS`, ".env"},
		{`git grep PASS -- '.env*'`, ".env"},
		{`grep -r --exclude='.env*' PASS .`, ""},
		{"cat <<'EOF' | python3\nprint(open('.env').read())\nEOF", ".env"},
		{"cat <<'EOF' | grep -v x | php\n<?php include 'app/etc/env.php';\nEOF", "app/etc/env.php"},
		{"cat <<'EOF' | wc -l\ninclude 'app/etc/env.php'\nEOF", ""},
		{"node -e 'require(`fs`).readFileSync(`.env`)'", ".env"},
		{`perl -e 'open(F, "<.env")'`, ".env"},
		// second blind review
		{`echo "print(open('.env').read())" | python3`, ".env"},
		{`printf '%s' "<?php echo file_get_contents('app/etc/env.php');" | php`, "app/etc/env.php"},
		{`echo "print(open('.env').read())" | tr a a | python3 -`, ".env"},
		{"{ cat <<'EOF'\nprint(open('.env').read())\nEOF\n} | python3", ".env"},
		{"( cat <<'EOF'\nprint(open('.env').read())\nEOF\n) | python3", ".env"},
		{`rg -g'.env*' PASS`, ".env"},
		{`rg -g.env* PASS`, ".env"},
		{`find . -iname '.ENV*'`, ".env"},
		{`find . -iname .ENV`, ".env"},
		{`rg --iglob '.ENV*' PASS`, ".env"},
		{`rg --iglob='.ENV*' PASS`, ".env"},
		{`git grep PASS '.env*'`, ".env"},
		{`git -C /x grep -n -e PASS -- x '.env*'`, ".env"},
		{`git grep -e PASS '.env*'`, ".env"},
		{`find . -regex '.*/\.env' -exec cat {} +`, ".env"},
		{`find . -iregex '.*/APP/ETC/ENV\.PHP'`, "app/etc/env.php"},
		{`echo "print(open('x').read())" | python3`, ""},
		{`echo "open('.env')" > notes.txt`, ""},
		{`echo "open('.env')"; python3 x.py`, ""},
		{`{ echo "print(open('.env').read())"; } | python3`, ".env"},
		{"cat <<'EOF' > notes.txt\nopen('.env')\nEOF", ""},
		{`rg -g '!.env*' PASS`, ""},
		{`rg -g'!.env*' PASS`, ""},
		{`find . -name '*.go'`, ""},
		{`find . -iname '*.GO'`, ""},
		{`git grep 'X=.*'`, ""},
		{`git grep -n 'X=.*' -- '*.go'`, ""},
		{`find . -regex '.*\.go'`, ""},
		// round 4: find's emacs regex syntax
		{`find . -regex '.*\.\(env\|json\)' -exec cat {} +`, ".env"},
		{`find . -regex '.*/\(\.env\)'`, ".env"},
		{`find . -regex '.*/\.env\|x'`, ".env"},
		{`find . -iregex '.*/\(AUTH\)\.json'`, "auth.json"},
		{`find . -regex '.*\.\(go\|md\)'`, ""},
		// round 4: git magic pathspecs and global options
		{`git grep PASS ':(top).env'`, ".env"},
		{`git grep PASS ':(icase).ENV'`, ".env"},
		{`git grep PASS ':(literal).env'`, ".env"},
		{`git grep PASS ':(glob).env*'`, ".env"},
		{`git grep PASS ':/.env'`, ".env"},
		{`git grep PASS -- ':/:.env*'`, ".env"},
		{`git --work-tree . grep --no-index PASS '.env*'`, ".env"},
		{`git -c core.x=y --git-dir /x/.git --namespace n grep PASS -- ':(top,icase)AUTH.JSON'`, "auth.json"},
		{`git grep PASS -- ':!.env'`, ""},
		{`git grep PASS -- ':^.env*'`, ""},
		{`git grep PASS ':(exclude).env*'`, ""},
		{`git grep PASS ':(top,exclude).env'`, ""},
		{`git grep PASS ':(literal).env*'`, ""},
		// round 4: interpreter input forms
		{`python3 <(echo "print(open('.env').read())")`, ".env"},
		{`python3 < <(echo "print(open('.env').read())")`, ".env"},
		{`echo "print(open('.env').read())" | pypy3`, ".env"},
		{`awk 'BEGIN{while((getline l < ".env")>0) print l}'`, ".env"},
		{`gawk -f /dev/stdin <<<'x' 'BEGIN{getline < ".env"}'`, ".env"},
		{`sed '1r .env' f`, ".env"},
		{`perl -ne 'print' -- 'open(F, ".env")'`, ".env"},
		{`bun -e "Bun.file('.env').text()"`, ".env"},
		{`lua5.4 -e 'io.open(".env")'`, ".env"},
		{`Rscript -e 'readLines(".env")'`, ".env"},
		{`deno eval 'Deno.readTextFileSync(".env")'`, ".env"},
		{`awk '{print $1}' f`, ""},
		{`sed -n 1p f`, ""},
		{`python3 x.py`, ""},
		{`python3 <(echo "print(1)")`, ""},
		{`diff <(echo a) <(echo "open('.env')")`, ""},
		// round 4: find's * matches a leading dot; excludes never deny
		{`find . -name '*.env' -exec cat {} +`, ".env"},
		{`find . -path '*/*.env'`, ".env"},
		{`find . -iname '*.ENV'`, ".env"},
		{`find . -name '*'`, ""},
		{`cat *.env`, ""},
		{"grep -r --exclude=.env* PASS .", ""},
		{"grep -r --exclude=.env PASS .", ""},
		{"grep -r --exclude-dir=.env* PASS .", ""},
		{`grep -o "X=.*" f`, ""},
		// round 5: emacs-only anchors and word boundaries in find -regex
		{`find . -regex '.*/\.env\'"'"'' -exec cat {} +`, ".env"},
		{"find . -regex '\\`.*/\\.env'", ".env"},
		{`find . -regex '.*/etc/\<env\.php'`, "app/etc/env.php"},
		{`find . -regex '.*/\.env\_>'`, ".env"},
		{`find . -regex '.*/\_<auth\.json\>'`, "auth.json"},
		{`find . -regex '.*/\b\.env\B'`, ".env"},
		{`find . -regex '.*\.go\'"'"''`, ""},
		// round 5: sed r/R/w/W glued to the file name; any program text
		{`sed '1r.env' /dev/null`, ".env"},
		{`sed '1Rapp/etc/env.php' /dev/null`, "app/etc/env.php"},
		{`sed -n 'w.env' f`, ".env"},
		{`gsed '$Rauth.json' f`, "auth.json"},
		{`awk '{print}' x.environment`, ""},
		{`sed 's/env/x/' f`, ""},
		// round 5: magic pathspecs for every git invocation
		{`git --attr-source HEAD grep PASS ':(top).env'`, ".env"},
		{`git -c alias.g=grep g PASS ':(top).env'`, ".env"},
		{`git diff ':(top).env'`, ".env"},
		{`git log -p -- ':/:.env*'`, ".env"},
		{`git show HEAD ':(icase)AUTH.JSON'`, "auth.json"},
		{`git --exec-path=/x checkout ':(glob)app/etc/env.*'`, "app/etc/env.php"},
		{`git commit -m 'fix env loader'`, ""},
		{`git log --grep=env`, ""},
		{`git diff -- ':!.env'`, ""},
		{`git diff ':(exclude).env*'`, ""},
		{`git status`, ""},
		// round 6: GNU env assignment words, find -regex spellings, git -c
		// values and sed program text
		{`env 'X%=1' cat .env`, ".env"},
		{`env 'X%=1' sh -c 'cat .env'`, ".env"},
		{`find . -regex '.*/[.]en[\v]' -exec cat {} +`, ".env"},
		{`find . -regex '.*/[.]en[^\x]' -exec cat {} +`, ".env"},
		{`find . -regex '.*/[[:alpha:].]en[\v]' -exec cat {} +`, ".env"},
		{`git -c 'alias.x=!cat .env' x`, ".env"},
		{`git -c core.pager='cat .env' log`, ".env"},
		{`git --config-env=core.pager=.env log`, ".env"},
		{`sed '1rapp/etc/./env.php' f`, "app/etc/env.php"},
		{`sed '1rapp//etc/.//./env.php' f`, "app/etc/env.php"},
		{`git -c core.pager=less log`, ""},
		{`sed 's#a/./b#c#' f`, ""},
	} {
		tool, ti := bash(c.cmd)
		cases = append(cases, struct {
			name  string
			tool  string
			ti    map[string]string
			entry string
		}{"bash " + c.cmd, tool, ti, c.entry})
	}
	cfg := suiteCfg()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := sensitivePaths{}.Apply(context.Background(), spInput(c.tool, c.ti, "a1"), cfg, nil)
			if c.entry == "" {
				if d != nil {
					t.Fatalf("want nil, got %+v", d)
				}
				return
			}
			if d == nil || d.Permission != "deny" || d.Hard || d.UpdatedInput != nil ||
				!strings.HasPrefix(d.Reason, "sensitive_paths: subagents may not access ") ||
				!strings.Contains(d.Reason, "(matches "+c.entry+"); ask the main agent") {
				t.Fatalf("want deny matching %s, got %+v", c.entry, d)
			}
		})
	}
	// main agent is never checked
	tool, ti := read("/x/proj/.env")
	if d := (sensitivePaths{}).Apply(context.Background(), spInput(tool, ti, ""), cfg, nil); d != nil {
		t.Fatalf("main agent: %+v", d)
	}
}

// 8: an oversized command is denied unscanned; 1: adversarial shapes at the
// cap stay far below the deadline.
func TestSensitivePathsLongCommand(t *testing.T) {
	cfg := suiteCfg()
	run := func(cmd string) *hook.Decision {
		return sensitivePaths{}.Apply(context.Background(), spInput("Bash", map[string]string{"command": cmd}, "a1"), cfg, nil)
	}
	if d := run("cat .env;" + strings.Repeat("x", 2<<20)); d == nil || d.Permission != "deny" || d.Reason != "sensitive_paths: command over 16 KiB not scanned" {
		t.Fatalf("oversized: %+v", d)
	}
	for name, cmd := range map[string]string{
		"shell heredocs": "bash <<a\n" + strings.Repeat("cat <<a\nx\na\n", 1300),
		"heredoc spam":   "sh;" + strings.Repeat("mysql <<a\n", 1600),
		"nested subst":   strings.Repeat("$(", 8000),
		"dq subst":       "echo " + strings.Repeat("\"$(", 5000),
		"pipes to sh":    strings.Repeat("echo x | sh;", 1300),
		"evals":          strings.Repeat("eval ", 3200),
		"php heredocs":   strings.Repeat("php <<a\nx\na\n", 1300),
		"inline code":    "php " + strings.Repeat("-r -lne ", 2000),
		"code matches":   "php -r '" + strings.Repeat(".env.", 3200),
		"find regexes":   strings.Repeat("find -regex '((((a{1000}){1000}){1000}){1000})' ", 300),
		"echo pipes":     strings.Repeat("echo x |", 2000) + " php",
		"git grep words": "git grep " + strings.Repeat("-e x ", 3000),
	} {
		cmd = cmd[:min(len(cmd), maxDestructiveScan)]
		// best of three: one run alone also measures the scheduler and the GC.
		// The bound is half the rule deadline.
		el := time.Hour
		for range 3 {
			start := time.Now()
			run(cmd)
			el = min(el, time.Since(start))
		}
		if el > 100*time.Millisecond {
			t.Errorf("%s: %v", name, el)
		}
	}
	if d := (sensitivePaths{}).Apply(context.Background(), spInput("Bash", map[string]string{"command": "cat .env;" + strings.Repeat("x", 2<<20)}, ""), cfg, nil); d != nil {
		t.Fatalf("main agent: %+v", d)
	}
	// round 4: costly -regex values past the cap must not run out the rule
	// deadline (no opinion = the .env read passes); they are denied uncompiled.
	for name, cmd := range map[string]string{
		"regex spam then read": strings.Repeat("find . -regex '(\\pL{30}){30}' ", 200) + "; cat .env",
		"regex count cap":      strings.Repeat("find . -regex 'x' ", maxFindRegexes+1),
		"regex bytes cap":      "find . -regex '" + strings.Repeat("x", maxFindRegexBytes+1) + "'",
	} {
		start := time.Now()
		d := run(cmd)
		if el := time.Since(start); el > 50*time.Millisecond {
			t.Errorf("%s: %v", name, el)
		}
		if d == nil || d.Permission != "deny" {
			t.Errorf("%s: want deny, got %+v", name, d)
		}
	}
	// the worst case inside the caps: every value at its share of the byte
	// cap, -iregex (both syntax variants, case-folded), \p classes, repetition
	// cap (RE2 and emacs spellings alike).
	share := maxFindRegexBytes / maxFindRegexes
	pad := func(s string) string { return s + strings.Repeat("x", share-len(s)) }
	re2 := pad(`(\pL{30}){30}|(\pN{30}){30}|(\pS{30}){30}|(\pP{30}){30}|`)
	emacs := pad(`\(\pL\{30\}\)\{30\}\|\(\pN\{30\}\)\{30\}\|\(\pS\{30\}\)\{30\}\|`)
	cmd := "find . " + strings.Repeat("-iregex '"+re2+"' -iregex '"+emacs+"' ", maxFindRegexes/2)
	start := time.Now()
	if d := run(cmd); d != nil {
		t.Errorf("regexes at cap: %+v", d)
	}
	el := time.Since(start)
	t.Logf("regexes at cap: %v", el)
	if el > 50*time.Millisecond {
		t.Errorf("regexes at cap: %v", el)
	}
}

func TestSensitivePathsHonoursCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := spInput("Bash", map[string]string{"command": "cat .env"}, "a1")
	if d := (sensitivePaths{}).Apply(ctx, in, suiteCfg(), nil); d != nil {
		t.Fatalf("cancelled ctx: %+v", d)
	}
}

// 5: a command nested past maxShellDepth is denied unscanned.
func TestSensitivePathsDepth(t *testing.T) {
	cmd := "echo $(echo $(echo $(echo $(echo \"$(cat .env)\"))))"
	d := sensitivePaths{}.Apply(context.Background(), spInput("Bash", map[string]string{"command": cmd}, "a1"), suiteCfg(), nil)
	if d == nil || d.Permission != "deny" || d.Reason != "sensitive_paths: command nested deeper than 3 not scanned" {
		t.Fatalf("past depth: %+v", d)
	}
}

// Round 5: a find -regex no spelling compiles is denied, not read as
// matching nothing (GNU find accepts syntax Go rejects).
func TestSensitivePathsUncheckableRegex(t *testing.T) {
	for _, cmd := range []string{`find . -regex '(['`, `find . -regex '.*/[[:nope:]]' -exec cat {} +`,
		// round 6: one spelling compiles to a literal, the other does not compile
		`find . -regextype posix-basic -regex '.*/\.en\(v\)\{1,1001\}' -exec cat {} +`,
		`find . -regextype posix-extended -regex '.*/\.en(v){1,1001}' -exec cat {} +`} {
		d := sensitivePaths{}.Apply(context.Background(), spInput("Bash", map[string]string{"command": cmd}, "a1"), suiteCfg(), nil)
		if d == nil || d.Permission != "deny" || !strings.Contains(d.Reason, "could not be checked") {
			t.Errorf("%s: %+v", cmd, d)
		}
	}
}
