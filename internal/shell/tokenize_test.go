package shell

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// render is a compact, lossless-enough view of what a guard sees:
// per segment, the skipped prefix (reserved words, assignments, wrappers)
// before "›", the head as its executable name (with <raw> when it differs),
// arguments as [value] or «value» when quoting/escaping changed the raw text,
// "ø" for no head, a redirection joined with an adjacent target, separators between segments ("⏎" for newline), and every
// backtick body as ‹body› at the end.
func render(command string) string {
	var b strings.Builder
	for _, s := range Segments(command) {
		if s.Cursor > 0 {
			raws := make([]string, s.Cursor)
			for i, t := range s.Tokens[:s.Cursor] {
				raws[i] = t.Raw
			}
			b.WriteString(strings.Join(raws, " ") + " › ")
		}
		if head, ok := s.Head(); !ok {
			b.WriteString("ø")
		} else {
			b.WriteString(s.Name())
			if head.Raw != s.Name() {
				b.WriteString("<" + head.Raw + ">")
			}
			args := s.Tokens[s.Cursor+1:]
			for i := 0; i < len(args); i++ {
				t := args[i]
				// a redirection and its adjacent target render as one word
				if t.Redirect && i+1 < len(args) && args[i+1].Index == t.Index+len(t.Raw) {
					i++
					t = Token{Value: t.Value + args[i].Value, Raw: t.Raw + args[i].Raw}
				}
				if t.Raw == t.Value {
					b.WriteString("[" + t.Value + "]")
				} else {
					b.WriteString("«" + t.Value + "»")
				}
			}
		}
		switch s.Separator {
		case "":
		case "\n":
			b.WriteString(" ⏎ ")
		default:
			b.WriteString(" " + s.Separator + " ")
		}
	}
	for _, bt := range BacktickBodies(command) {
		b.WriteString(" ‹" + bt.Body + "›")
	}
	return b.String()
}

// payloads lists every string a recognizer may re-scan as a nested command:
// argument values, space-joined runs of argument values or raws (eval,
// find -exec), and backtick bodies.
func payloads(command string) []string {
	var out []string
	for _, s := range Segments(command) {
		if s.Cursor >= len(s.Tokens) {
			continue
		}
		args := s.Tokens[s.Cursor+1:]
		for i := range args {
			for j := i + 1; j <= len(args); j++ {
				var values, raws []string
				for _, t := range args[i:j] {
					values = append(values, t.Value)
					raws = append(raws, t.Raw)
				}
				out = append(out, strings.Join(values, " "), strings.Join(raws, " "))
			}
		}
	}
	for _, bt := range BacktickBodies(command) {
		out = append(out, bt.Body)
	}
	return out
}

type vector struct {
	name   string            // original TS test title, or "tokenizer: ..." for tokenizer-level cases
	cmd    string            //
	want   string            // render(cmd)
	nested map[string]string // payload the recognizer re-scans -> render(payload)
	bodies []string          // heredoc bodies, in order (Heredocs: as bash reads them)
	opaque bool              // Opaque(cmd)
}

const (
	tDestructive = "recognizes executable destruction"
	tOrdinary    = "leaves ordinary commands and prose unchanged"
	tCompound    = "recognizes later compound destruction and shell wrappers without matching quoted prose"
	tHard        = "root/home recursive removal and destructive git retain hard denial"
	tReserved    = "recognizes destruction after reserved words, in backticks and in eval"
	t2285        = "issue #2285 examples are recursive filesystem data loss like a plain rm"
	tHardNested  = "root/home recursive removal behind reserved words, backticks or eval keeps its hard denial"
	tOrdCompound = "leaves ordinary compound, backtick and eval commands unchanged"
	tTargets     = "exposes literal removal targets only for a direct top-level rm that runs before every other segment"
)

// Every case of reference/gentle-shell/tests/destructive-command-guard.test.ts.
// Those tests assert recognizer verdicts; here each asserts the
// tokenizer-level fact the verdict depends on: which word is a segment head
// after unwrapping, which text stays a quoted argument, heredoc body or
// separator-free prose, and what nested payload a recognizer would re-scan.
var vectors = []vector{
	{name: tDestructive, cmd: `psql -c 'DROP TABLE users'`, want: `psql[-c]«DROP TABLE users»`},
	{name: tDestructive, cmd: `mysql --execute='TRUNCATE TABLE users'`, want: `mysql«--execute=TRUNCATE TABLE users»`},
	{name: tDestructive, cmd: `sqlite3 app.db 'DELETE FROM users;'`, want: `sqlite3[app.db]«DELETE FROM users;»`},
	{name: tDestructive, cmd: `psql -c 'DELETE FROM users WHERE 1=1'`, want: `psql[-c]«DELETE FROM users WHERE 1=1»`},
	{name: tDestructive, cmd: `echo 'DROP DATABASE app' | psql`, want: `echo«DROP DATABASE app» | psql`},
	{name: tDestructive, cmd: `printf '%s' 'TRUNCATE users' | mysql`, want: `printf«%s»«TRUNCATE users» | mysql`},
	{name: tDestructive, cmd: `env MODE=test sudo -u postgres /usr/bin/psql -c 'DROP SCHEMA public CASCADE'`,
		want: `env MODE=test sudo -u postgres › psql</usr/bin/psql>[-c]«DROP SCHEMA public CASCADE»`},
	{name: tDestructive, cmd: `sh -c "echo ready; psql -c 'DROP TABLE users'"`,
		want:   `sh[-c]«echo ready; psql -c 'DROP TABLE users'»`,
		nested: map[string]string{`echo ready; psql -c 'DROP TABLE users'`: `echo[ready] ; psql[-c]«DROP TABLE users»`}},
	{name: tDestructive, cmd: `echo ready && rm -fr -- ./data`, want: `echo[ready] && rm[-fr][--][./data]`},
	{name: tDestructive, cmd: `find ./data -type f -delete`, want: `find[./data][-type][f][-delete]`},
	{name: tDestructive, cmd: `find ./data -type f -exec rm -rf {} +`, want: `find[./data][-type][f][-exec][rm][-rf][{}][+]`,
		nested: map[string]string{`rm -rf {}`: `rm[-rf][{}]`}},
	{name: tDestructive, cmd: `find ./data -print0 | xargs -0 rm -rf`, want: `find[./data][-print0] | xargs -0 › rm[-rf]`},
	{name: tDestructive, cmd: "psql <<'SQL'\nDROP TABLE users;\nSQL", want: `psql«<<SQL» ⏎ ø`, bodies: []string{"DROP TABLE users;"}},
	{name: tDestructive, cmd: `sqlite3 app.db 'SELECT 1; /* maintenance */ DROP TABLE users'`, want: `sqlite3[app.db]«SELECT 1; /* maintenance */ DROP TABLE users»`},
	{name: tDestructive, cmd: `timeout 30 bash -lc 'rm -r ./data'`, want: `timeout 30 › bash[-lc]«rm -r ./data»`,
		nested: map[string]string{`rm -r ./data`: `rm[-r][./data]`}},
	{name: tDestructive, cmd: `echo ready || (rm -r ./data)`, want: `echo[ready] || ø ( rm[-r][./data] ) ø`},
	{name: tDestructive, cmd: `rm -r /var/app/data`, want: `rm[-r][/var/app/data]`},
	{name: tDestructive, cmd: `git -C /repo reset --hard HEAD`, want: `git[-C][/repo][reset][--hard][HEAD]`},
	{name: tDestructive, cmd: `git clean -fd`, want: `git[clean][-fd]`},
	{name: tDestructive, cmd: `git push --force-with-lease origin main`, want: `git[push][--force-with-lease][origin][main]`},
	{name: tDestructive, cmd: `git branch -D old`, want: `git[branch][-D][old]`},
	{name: tDestructive, cmd: `git restore .`, want: `git[restore][.]`},
	{name: tDestructive, cmd: `sh -c "psql -c \"DROP TABLE users\""`, want: `sh[-c]«psql -c "DROP TABLE users"»`,
		nested: map[string]string{`psql -c "DROP TABLE users"`: `psql[-c]«DROP TABLE users»`}},
	{name: tDestructive, cmd: `bash -lc "rm -r \"./data\""`, want: `bash[-lc]«rm -r "./data"»`,
		nested: map[string]string{`rm -r "./data"`: `rm[-r]«./data»`}},
	{name: tDestructive, cmd: `psql -c 'DELETE FROM "where"'`, want: `psql[-c]«DELETE FROM "where"»`},
	{name: tDestructive, cmd: "mysql -e 'DELETE FROM `where`'", want: "mysql[-e]«DELETE FROM `where`»"},
	{name: tDestructive, cmd: `sqlite3 app.db 'DELETE FROM [where]'`, want: `sqlite3[app.db]«DELETE FROM [where]»`},
	{name: tDestructive, cmd: `psql -c 'DROP TABLE "where"'`, want: `psql[-c]«DROP TABLE "where"»`},
	{name: tDestructive, cmd: `find cache -exec echo {} \; -exec rm -r {} \;`, want: `find[cache][-exec][echo][{}]«;»[-exec][rm][-r][{}]«;»`,
		nested: map[string]string{`echo {}`: `echo[{}]`, `rm -r {}`: `rm[-r][{}]`}},
	{name: tDestructive, cmd: `find cache -execdir echo {} \; -execdir rm -r {} \;`, want: `find[cache][-execdir][echo][{}]«;»[-execdir][rm][-r][{}]«;»`,
		nested: map[string]string{`rm -r {}`: `rm[-r][{}]`}},
	{name: tDestructive, cmd: `sudo -n rm -r ./data`, want: `sudo -n › rm[-r][./data]`},
	{name: tDestructive, cmd: `command -p psql -c 'DROP TABLE users'`, want: `command -p › psql[-c]«DROP TABLE users»`},
	{name: tDestructive, cmd: `env -u MODE sudo -u postgres psql -c 'DROP TABLE users'`, want: `env -u MODE sudo -u postgres › psql[-c]«DROP TABLE users»`},

	{name: tOrdinary, cmd: `pnpm test && pnpm run build`, want: `pnpm[test] && pnpm[run][build]`},
	{name: tOrdinary, cmd: `git status`, want: `git[status]`},
	{name: tOrdinary, cmd: `git push origin main`, want: `git[push][origin][main]`},
	{name: tOrdinary, cmd: `psql -c 'SELECT * FROM users'`, want: `psql[-c]«SELECT * FROM users»`},
	{name: tOrdinary, cmd: `sqlite3 app.db 'DELETE FROM users WHERE id=7'`, want: `sqlite3[app.db]«DELETE FROM users WHERE id=7»`},
	{name: tOrdinary, cmd: `psql -c "SELECT 'DROP TABLE users'"`, want: `psql[-c]«SELECT 'DROP TABLE users'»`},
	{name: tOrdinary, cmd: `echo 'rm -rf ./data; DROP TABLE users'`, want: `echo«rm -rf ./data; DROP TABLE users»`},
	{name: tOrdinary, cmd: `printf '%s' 'TRUNCATE TABLE users'`, want: `printf«%s»«TRUNCATE TABLE users»`},
	{name: tOrdinary, cmd: `rg 'DROP TABLE' docs`, want: `rg«DROP TABLE»[docs]`},
	{name: tOrdinary, cmd: `rm ./one-file`, want: `rm[./one-file]`},
	{name: tOrdinary, cmd: `find . -name '*.ts'`, want: `find[.][-name]«*.ts»`},
	{name: tOrdinary, cmd: "psql <<'SQL'\nSELECT 'DROP TABLE users';\nSQL", want: `psql«<<SQL» ⏎ ø`, bodies: []string{"SELECT 'DROP TABLE users';"}},
	{name: tOrdinary, cmd: `git log --oneline`, want: `git[log][--oneline]`},
	{name: tOrdinary, cmd: `env X=1 echo 'rm -r ./data'`, want: `env X=1 › echo«rm -r ./data»`},
	{name: tOrdinary, cmd: `find . -exec echo 'DROP TABLE users' {} +`, want: `find[.][-exec][echo]«DROP TABLE users»[{}][+]`,
		nested: map[string]string{`echo 'DROP TABLE users' {}`: `echo«DROP TABLE users»[{}]`}},
	{name: tOrdinary, cmd: `git push origin main && printf '%s' '-f'`, want: `git[push][origin][main] && printf«%s»«-f»`},
	{name: tOrdinary, cmd: `echo ';' rm -r cache`, want: `echo«;»[rm][-r][cache]`},
	{name: tOrdinary, cmd: `echo \; rm -r cache`, want: `echo«;»[rm][-r][cache]`},
	{name: tOrdinary, cmd: `printf '%s ' ';' rm -r ./data`, want: `printf«%s »«;»[rm][-r][./data]`},
	{name: tOrdinary, cmd: `echo '|' rm -r cache`, want: `echo«|»[rm][-r][cache]`},
	{name: tOrdinary, cmd: `echo '&&' rm -r cache`, want: `echo«&&»[rm][-r][cache]`},
	{name: tOrdinary, cmd: `echo ')' rm -r cache`, want: `echo«)»[rm][-r][cache]`},
	{name: tOrdinary, cmd: `psql -c 'DELETE FROM "where" WHERE id=7'`, want: `psql[-c]«DELETE FROM "where" WHERE id=7»`},
	{name: tOrdinary, cmd: `psql -c "SELECT \"where\", 'DROP TABLE users'"`, want: `psql[-c]«SELECT "where", 'DROP TABLE users'»`},
	{name: tOrdinary, cmd: `find cache -exec echo {} \; -exec echo 'rm -r data' {} \;`, want: `find[cache][-exec][echo][{}]«;»[-exec][echo]«rm -r data»[{}]«;»`,
		nested: map[string]string{`echo 'rm -r data' {}`: `echo«rm -r data»[{}]`}},

	{name: tCompound, cmd: `echo 'rm -rf /'; env X=1 sh -c 'rm --recursive ./data'`, want: `echo«rm -rf /» ; env X=1 › sh[-c]«rm --recursive ./data»`,
		nested: map[string]string{`rm --recursive ./data`: `rm[--recursive][./data]`}},

	{name: tHard, cmd: `rm -fr /`, want: `rm[-fr][/]`},
	{name: tHard, cmd: `rm -r "$HOME"`, want: `rm[-r]«$HOME»`},
	{name: tHard, cmd: `git -C /repo reset --hard`, want: `git[-C][/repo][reset][--hard]`},
	{name: tHard, cmd: `git push -f`, want: `git[push][-f]`},
	{name: tHard, cmd: `git push ';' -f main`, want: `git[push]«;»[-f][main]`},
	{name: tHard, cmd: `rm -r ';' /`, want: `rm[-r]«;»[/]`},
	{name: tHard, cmd: `rm -rf /tmp/tmp.abcdef1234 ~/foo`, want: `rm[-rf][/tmp/tmp.abcdef1234][~/foo]`},
	{name: tHard, cmd: `rm -rf /tmp/tmp.abcdef1234 /`, want: `rm[-rf][/tmp/tmp.abcdef1234][/]`},

	{name: tReserved, cmd: `if true; then rm -rf data; fi`, want: `if › true ; then › rm[-rf][data] ; fi`},
	{name: tReserved, cmd: `for d in a b; do rm -rf "$d"; done`, want: `for[d][in][a][b] ; do › rm[-rf]«$d» ; done`},
	{name: tReserved, cmd: "echo `rm -rf data`", want: "echo[`rm][-rf][data`] ‹rm -rf data›",
		nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: `eval 'rm -rf data'`, want: `eval«rm -rf data»`, nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: `if false; then :; else rm -rf data; fi`, want: `if › false ; then › : ; else › rm[-rf][data] ; fi`},
	{name: tReserved, cmd: `if false; then :; elif rm -rf data; then :; fi`, want: `if › false ; then › : ; elif › rm[-rf][data] ; then › : ; fi`},
	{name: tReserved, cmd: `while rm -rf data; do :; done`, want: `while › rm[-rf][data] ; do › : ; done`},
	{name: tReserved, cmd: `until rm -rf data; do :; done`, want: `until › rm[-rf][data] ; do › : ; done`},
	{name: tReserved, cmd: `if rm -rf data; then :; fi`, want: `if › rm[-rf][data] ; then › : ; fi`},
	{name: tReserved, cmd: `{ rm -rf data; }`, want: `{ › rm[-rf][data] ; }`},
	{name: tReserved, cmd: `! rm -rf data`, want: `! › rm[-rf][data]`},
	{name: tReserved, cmd: `if true; then sudo rm -rf data; fi`, want: `if › true ; then sudo › rm[-rf][data] ; fi`},
	{name: tReserved, cmd: "echo \"now: `rm -rf data`\"", want: "echo«now: `rm -rf data`» ‹rm -rf data›",
		nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: "echo `true; rm -rf data`", want: "echo[`true] ; rm[-rf][data`] ‹true; rm -rf data›",
		nested: map[string]string{`true; rm -rf data`: `true ; rm[-rf][data]`}},
	{name: tReserved, cmd: `eval "rm -rf data"`, want: `eval«rm -rf data»`, nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: `eval rm -rf data`, want: `eval[rm][-rf][data]`, nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: `eval -- 'rm -rf data'`, want: `eval[--]«rm -rf data»`, nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: `command eval 'rm -rf data'`, want: `command › eval«rm -rf data»`, nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: tReserved, cmd: `eval 'if true; then rm -rf data; fi'`, want: `eval«if true; then rm -rf data; fi»`,
		nested: map[string]string{`if true; then rm -rf data; fi`: `if › true ; then › rm[-rf][data] ; fi`}},
	{name: tReserved, cmd: `eval 'git reset --hard'`, want: `eval«git reset --hard»`, nested: map[string]string{`git reset --hard`: `git[reset][--hard]`}},

	{name: t2285, cmd: `if true; then rm -rf data; fi`, want: `if › true ; then › rm[-rf][data] ; fi`},
	{name: t2285, cmd: `for d in a b; do rm -rf "$d"; done`, want: `for[d][in][a][b] ; do › rm[-rf]«$d» ; done`},
	{name: t2285, cmd: "echo `rm -rf data`", want: "echo[`rm][-rf][data`] ‹rm -rf data›", nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},
	{name: t2285, cmd: `eval 'rm -rf data'`, want: `eval«rm -rf data»`, nested: map[string]string{`rm -rf data`: `rm[-rf][data]`}},

	{name: tHardNested, cmd: `if true; then rm -rf ~; fi`, want: `if › true ; then › rm[-rf][~] ; fi`},
	{name: tHardNested, cmd: `for d in a; do rm -rf /; done`, want: `for[d][in][a] ; do › rm[-rf][/] ; done`},
	{name: tHardNested, cmd: `{ rm -rf "$HOME"; }`, want: `{ › rm[-rf]«$HOME» ; }`},
	{name: tHardNested, cmd: `! rm -rf ..`, want: `! › rm[-rf][..]`},
	{name: tHardNested, cmd: "echo `rm -rf ~`", want: "echo[`rm][-rf][~`] ‹rm -rf ~›", nested: map[string]string{`rm -rf ~`: `rm[-rf][~]`}},
	{name: tHardNested, cmd: `eval 'rm -rf /'`, want: `eval«rm -rf /»`, nested: map[string]string{`rm -rf /`: `rm[-rf][/]`}},
	{name: tHardNested, cmd: `while true; do rm -rf ~/foo; done`, want: `while › true ; do › rm[-rf][~/foo] ; done`},

	{name: tOrdCompound, cmd: `if [ -f x ]; then echo ok; fi`, want: `if › [[-f][x][]] ; then › echo[ok] ; fi`},
	{name: tOrdCompound, cmd: `for f in *; do cat "$f"; done`, want: `for[f][in][*] ; do › cat«$f» ; done`},
	{name: tOrdCompound, cmd: "echo `date`", want: "echo[`date`] ‹date›"},
	{name: tOrdCompound, cmd: `eval "$(ssh-agent -s)"`, want: `eval«$(ssh-agent -s)»`,
		nested: map[string]string{`$(ssh-agent -s)`: `$ ( ssh-agent[-s] ) ø`}},
	{name: tOrdCompound, cmd: `grep "then rm -rf" x`, want: `grep«then rm -rf»[x]`},
	{name: tOrdCompound, cmd: `echo 'then rm -rf data'`, want: `echo«then rm -rf data»`},
	{name: tOrdCompound, cmd: "echo '`rm -rf data`'", want: "echo«`rm -rf data`»"},
	{name: tOrdCompound, cmd: "echo \\`rm -rf data\\`", want: "echo«`rm»[-rf]«data`»"},
	{name: tOrdCompound, cmd: `eval 'echo rm -rf data'`, want: `eval«echo rm -rf data»`, nested: map[string]string{`echo rm -rf data`: `echo[rm][-rf][data]`}},
	{name: tOrdCompound, cmd: `eval "$cmd"`, want: `eval«$cmd»`, nested: map[string]string{`$cmd`: `$cmd`}},
	{name: tOrdCompound, cmd: `while read -r line; do echo "$line"; done < x`, want: `while › read[-r][line] ; do › echo«$line» ; done[<][x]`},
	{name: tOrdCompound, cmd: `if git diff --quiet; then git push origin main; fi`, want: `if › git[diff][--quiet] ; then › git[push][origin][main] ; fi`},
	{name: tOrdCompound, cmd: "echo 'unterminated `rm -rf data'", want: "echo«unterminated `rm -rf data»"},

	{name: tTargets, cmd: `rm -rf /tmp/tmp.abcdef1234 /tmp/x.log; git log -1`, want: `rm[-rf][/tmp/tmp.abcdef1234][/tmp/x.log] ; git[log][-1]`},
	{name: tTargets, cmd: `rm -r -f -- /tmp/tmp.abcdef1234`, want: `rm[-r][-f][--][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: "rm -rf /tmp/a && rm -r /tmp/b\n\nrm -r /tmp/c || true", want: `rm[-rf][/tmp/a] && rm[-r][/tmp/b] ⏎ ø ⏎ rm[-r][/tmp/c] || true`},
	{name: tTargets, cmd: `rm -rf /tmp/a; mv x /tmp/b; rm -rf /tmp/b`, want: `rm[-rf][/tmp/a] ; mv[x][/tmp/b] ; rm[-rf][/tmp/b]`},
	{name: tTargets, cmd: `sudo rm -rf /tmp/tmp.abcdef1234`, want: `sudo › rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `env rm -rf /tmp/tmp.abcdef1234`, want: `env › rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `X=1 rm -rf /tmp/tmp.abcdef1234`, want: `X=1 › rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `xargs rm -rf /tmp/tmp.abcdef1234`, want: `xargs › rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `/bin/rm -rf /tmp/tmp.abcdef1234`, want: `rm</bin/rm>[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `sh -c 'rm -rf /tmp/tmp.abcdef1234'`, want: `sh[-c]«rm -rf /tmp/tmp.abcdef1234»`,
		nested: map[string]string{`rm -rf /tmp/tmp.abcdef1234`: `rm[-rf][/tmp/tmp.abcdef1234]`}},
	{name: tTargets, cmd: `find /tmp -name tmp.abcdef1234 -exec rm -rf {} +`, want: `find[/tmp][-name][tmp.abcdef1234][-exec][rm][-rf][{}][+]`,
		nested: map[string]string{`rm -rf {}`: `rm[-rf][{}]`}},
	{name: tTargets, cmd: `rm -rf "$TMPDIR/x"`, want: `rm[-rf]«$TMPDIR/x»`},
	{name: tTargets, cmd: `rm -rf '/tmp/tmp.abcdef1234'`, want: `rm[-rf]«/tmp/tmp.abcdef1234»`},
	{name: tTargets, cmd: `rm -rf --no-preserve-root /tmp/tmp.abcdef1234`, want: `rm[-rf][--no-preserve-root][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `rm -rf`, want: `rm[-rf]`},
	{name: tTargets, cmd: `mv x /tmp/tmp.abcdef1234 && rm -rf /tmp/tmp.abcdef1234`, want: `mv[x][/tmp/tmp.abcdef1234] && rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `cp -r x /tmp/tmp.abcdef1234; rm -rf /tmp/tmp.abcdef1234`, want: `cp[-r][x][/tmp/tmp.abcdef1234] ; rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `(rm -rf /tmp/tmp.abcdef1234)`, want: `ø ( rm[-rf][/tmp/tmp.abcdef1234] ) ø`},
	{name: tTargets, cmd: `rm -rf /tmp/tmp.abcdef1234 & true`, want: `rm[-rf][/tmp/tmp.abcdef1234] & true`},
	{name: tTargets, cmd: `rm -rf /tmp/tmp.abcdef1234 | cat`, want: `rm[-rf][/tmp/tmp.abcdef1234] | cat`},
	{name: tTargets, cmd: `{ rm -rf /tmp/tmp.abcdef1234; }`, want: `{ › rm[-rf][/tmp/tmp.abcdef1234] ; }`},
	{name: tTargets, cmd: `! rm -rf /tmp/tmp.abcdef1234`, want: `! › rm[-rf][/tmp/tmp.abcdef1234]`},
	{name: tTargets, cmd: `if true; then rm -rf /tmp/tmp.abcdef1234; fi`, want: `if › true ; then › rm[-rf][/tmp/tmp.abcdef1234] ; fi`},
	{name: tTargets, cmd: "echo `rm -rf /tmp/tmp.abcdef1234`", want: "echo[`rm][-rf][/tmp/tmp.abcdef1234`] ‹rm -rf /tmp/tmp.abcdef1234›",
		nested: map[string]string{`rm -rf /tmp/tmp.abcdef1234`: `rm[-rf][/tmp/tmp.abcdef1234]`}},
	{name: tTargets, cmd: `eval 'rm -rf /tmp/tmp.abcdef1234'`, want: `eval«rm -rf /tmp/tmp.abcdef1234»`,
		nested: map[string]string{`rm -rf /tmp/tmp.abcdef1234`: `rm[-rf][/tmp/tmp.abcdef1234]`}},
	{name: tTargets, cmd: `eval rm -rf /tmp/tmp.abcdef1234`, want: `eval[rm][-rf][/tmp/tmp.abcdef1234]`,
		nested: map[string]string{`rm -rf /tmp/tmp.abcdef1234`: `rm[-rf][/tmp/tmp.abcdef1234]`}},

	// Tokenizer-level edge cases beyond the TS suite (expectations checked against the TS original).
	{name: "tokenizer: heredoc body is data, the next line is a command", cmd: "cat <<EOF\nrm -rf /\nEOF\nrm -rf x",
		want: `cat[<<EOF] ⏎ ø ⏎ rm[-rf][x]`, bodies: []string{"rm -rf /"}},
	{name: "tokenizer: <<- and double-quoted delimiter", cmd: "cat <<-\"END\" > f\n\trm -rf /\nEND\necho done",
		want: `cat«<<-END»[>][f] ⏎ ø ⏎ echo[done]`, bodies: []string{"\trm -rf /"}},
	{name: "tokenizer: unterminated heredoc is not blanked, and opaque", cmd: "cat <<EOF\nrm -rf /",
		want: `cat[<<EOF] ⏎ rm[-rf][/]`, opaque: true},
	{name: "tokenizer: Heredocs may close on a prefix line (JS backtracking), bash does not: unterminated, not blanked", cmd: "cat <<EOF\nrm -rf /\nEO\nls",
		want: `cat[<<EOF] ⏎ rm[-rf][/] ⏎ EO ⏎ ls`, opaque: true},
	{name: "tokenizer: a second heredoc on the same line is blanked", cmd: "cat <<A <<'B'\na\nA\nb\nB\nls",
		want: `cat[<<A]«<<B» ⏎ ø ⏎ ø ⏎ ls`, bodies: []string{"a", "b"}},
	{name: "tokenizer: unterminated quote is skipped, its text is tokenized", cmd: `echo "; rm -rf /`,
		want: `echo ; rm[-rf][/]`},
	{name: "tokenizer: backslash-newline inside double quotes joins the word", cmd: "echo \"a\\\nb\"",
		want: `echo«ab»`},
	{name: "tokenizer: $(...) stays inside one word", cmd: `echo $(rm -rf x) done`,
		want: `echo[$] ( rm[-rf][x] ) done`},
	{name: "tokenizer: non-ASCII words", cmd: "echo café naïve; rm -rf über",
		want: `echo[café][naïve] ; rm[-rf][über]`},
	{name: "tokenizer: JS \\s splits on NBSP", cmd: "rm -rf /", want: `rm[-rf][/]`},
	{name: "tokenizer: timeout with flags and duration", cmd: `timeout -s KILL -k 5 10 nice rm x`,
		want: `timeout -s KILL -k 5 10 nice › rm[x]`},
	{name: "tokenizer: wrapper without command has no head", cmd: `sudo -u`, want: `sudo -u › ø`},
	{name: "tokenizer: assignments only", cmd: `A=1 B=2`, want: `A=1 B=2 › ø`},
	{name: "tokenizer: append and subscript assignments", cmd: `A+=1 b[0]=2 c[i+1]+=3 rm -rf x`, want: `A+=1 b[0]=2 c[i+1]+=3 › rm[-rf][x]`},
	{name: "tokenizer: quoted reserved word is a head", cmd: `'if' rm`, want: `if<'if'>[rm]`},
	{name: "tokenizer: escaped backtick inside backticks", cmd: "echo `echo \\`date\\``",
		want: "echo[`echo]«`date``» ‹echo `date`›"},
	{name: "tokenizer: empty input", cmd: ``, want: `ø`},
	{name: "tokenizer: CRLF", cmd: "ls\r\nrm -r x\r\n", want: `ls ⏎ rm[-r][x] ⏎ ø`},

	// Review (a): only a `<<` bash reads as a heredoc operator blanks lines.
	{name: "heredoc: << inside double quotes is not a heredoc", cmd: "echo \"<<EOF\"\nrm -rf x\nEOF",
		want: `echo«<<EOF» ⏎ rm[-rf][x] ⏎ EOF`},
	{name: "heredoc: << inside single quotes is not a heredoc", cmd: "echo 'a <<EOF'; rm -rf x\nrm -rf y\nEOF",
		want: `echo«a <<EOF» ; rm[-rf][x] ⏎ rm[-rf][y] ⏎ EOF`},
	{name: "heredoc: << inside a comment is not a heredoc", cmd: "ls # <<EOF\nrm -rf x\nEOF",
		want: `ls ⏎ rm[-rf][x] ⏎ EOF`},
	{name: "heredoc: # after a redirection starts a comment", cmd: "ls >#<<EOF\nrm -rf x\nEOF",
		want: `ls[>] ⏎ rm[-rf][x] ⏎ EOF`},
	{name: "heredoc: <<< is a here-string", cmd: "cat <<<EOF\nrm -rf x\nEOF",
		want: `cat[<<<EOF] ⏎ rm[-rf][x] ⏎ EOF`},
	{name: "heredoc: << in arithmetic is a shift", cmd: "echo $((x<<y))\nrm -rf z\ny",
		want: `echo[$] ( ø ( x[<<y] ) ø ) ø ⏎ rm[-rf][z] ⏎ y`},
	{name: "heredoc: closes only on the exact delimiter line", cmd: "cat <<EOF\nx\nEO\n<<Z\nEOF\nrm -rf /\nZ",
		want: `cat[<<EOF] ⏎ ø ⏎ rm[-rf][/] ⏎ Z`, bodies: []string{"x\nEO\n<<Z"}},
	{name: "heredoc: an unquoted delimiter closes on a backslash-joined line", cmd: "cat <<EOF\nE\\\nOF\nrm -rf x\nEOF",
		want: `cat[<<EOF] ⏎ ø ⏎ rm[-rf][x] ⏎ EOF`, bodies: []string{""}},
	{name: "heredoc: a quoted delimiter does not join lines", cmd: "cat <<'EOF'\nE\\\nOF\nrm -rf x\nEOF",
		want: `cat«<<EOF» ⏎ ø`, bodies: []string{"E\\\nOF\nrm -rf x"}},
	{name: "heredoc: an escaped backslash does not join lines", cmd: "cat <<EOF\nfoo\\\\\nEOF\nrm -rf x",
		want: `cat[<<EOF] ⏎ ø ⏎ rm[-rf][x]`, bodies: []string{"foo\\\\"}},
	{name: "heredoc: EOF) ends a heredoc in $(...) (bash 5.3)", cmd: "x=$(cat <<'EOF'\nit's\nEOF)\nrm -rf x; echo 'q'",
		want: "x=$ › ø ( cat«<<EOF» ⏎ ø ) ø ⏎ rm[-rf][x] ; echo«q»", bodies: []string{"it's"}},
	{name: "heredoc: a heredoc opened in $(...) reads the following lines", cmd: "x=$(cat <<EOF)\nrm -rf x\nEOF\nls",
		want: `x=$ › ø ( cat[<<EOF] ) ø ⏎ ø ⏎ ls`, bodies: []string{"rm -rf x"}},
	{name: "heredoc: mid-word # is not a comment", cmd: "echo a#<<EOF\nrm -rf x\nEOF\nls",
		want: `echo[a#][<<EOF] ⏎ ø ⏎ ls`, bodies: []string{"rm -rf x"}},
	{name: "heredoc: body starts after the command line's unquoted newline", cmd: "cat <<EOF; echo \"q\nw\"\nrm -rf x\nEOF\nls",
		want: "cat[<<EOF] ; echo«q\nw» ⏎ ø ⏎ ls", bodies: []string{"rm -rf x"}},
	{name: "heredoc: quoted delimiter forms are literal", cmd: "cat <<\\EOF\n$(rm -rf x)\nEOF\ncat <<E\"O\"F\n`rm x`\nEOF",
		want: "cat«<<EOF» ⏎ ø ⏎ cat«<<EOF» ⏎ ø", bodies: []string{"$(rm -rf x)", "`rm x`"}},
	{name: "heredoc: in a double-quoted command substitution", cmd: "git commit -m \"$(cat <<'EOF'\nfix: x\nEOF\n)\"; rm y",
		want: "git[commit][-m]«$(cat <<'EOF'\n          \n)» ; rm[y]", bodies: []string{"fix: x"}},
	{name: "heredoc: $(...) in an unquoted-delimiter body is opaque", cmd: "cat <<EOF\n$(rm -rf x)\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"$(rm -rf x)"}, opaque: true},
	{name: "heredoc: backticks in an unquoted-delimiter body are opaque", cmd: "cat <<-EOF\n\t`rm -rf x`\n\tEOF",
		want: `cat[<<-EOF] ⏎ ø`, bodies: []string{"\t`rm -rf x`"}, opaque: true},
	{name: "heredoc: unterminated unquoted heredoc with $(...) is opaque", cmd: "cat <<EOF\n'\n$(rm -rf x)\n'",
		want: "cat[<<EOF] ⏎ \n$(rm -rf x)\n<'\n$(rm -rf x)\n'>", opaque: true},
	{name: "heredoc: escaped $( in an unquoted-delimiter body is literal", cmd: "cat <<EOF\n\\$(rm -rf x) \\`ls\\`\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"\\$(rm -rf x) \\`ls\\`"}},
	{name: "heredoc: ${ cmd; } in an unquoted-delimiter body is opaque", cmd: "cat <<EOF\n${ rm -rf x; }\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"${ rm -rf x; }"}, opaque: true},
	{name: "heredoc: ${|cmd; } in an unquoted-delimiter body is opaque", cmd: "cat <<EOF\n${|rm -rf x; }\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"${|rm -rf x; }"}, opaque: true},
	{name: "heredoc: ${<tab>cmd; } in an unquoted-delimiter body is opaque", cmd: "cat <<EOF\n${\trm -rf x; }\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"${\trm -rf x; }"}, opaque: true},
	{name: "heredoc: ${<newline>cmd; } in an unquoted-delimiter body is opaque", cmd: "cat <<EOF\n${\nrm -rf x; }\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"${\nrm -rf x; }"}, opaque: true},
	{name: "heredoc: ${ cmd; } split by continued lines is opaque", cmd: "cat <<EOF\n$\\\n{\\\n rm -rf x; }\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"$\\\n{\\\n rm -rf x; }"}, opaque: true},
	{name: "heredoc: escaped ${ and parameters in an unquoted-delimiter body are literal", cmd: "cat <<EOF\n\\${ rm -rf x; } ${x} ${#x} ${x:-y}\nEOF",
		want: `cat[<<EOF] ⏎ ø`, bodies: []string{"\\${ rm -rf x; } ${x} ${#x} ${x:-y}"}},
	{name: "heredoc: ${ cmd; } in a quoted-delimiter body is literal", cmd: "cat <<'EOF'\n${ rm -rf x; }\nEOF",
		want: `cat«<<EOF» ⏎ ø`, bodies: []string{"${ rm -rf x; }"}},
	{name: "heredoc: quoted-delimiter body with $(...) is not opaque", cmd: "cat <<'EOF'\n$(rm -rf x)\nEOF",
		want: `cat«<<EOF» ⏎ ø`, bodies: []string{"$(rm -rf x)"}},

	// Review (b): wrapper options never move the head onto a flag value.
	{name: "wrapper: xargs -L", cmd: `xargs -L 1 rm`, want: `xargs -L 1 › rm`},
	{name: "wrapper: xargs attached and long", cmd: `xargs -n5 --max-procs=2 -I {} rm {}`, want: `xargs -n5 --max-procs=2 -I {} › rm[{}]`},
	{name: "wrapper: xargs --replace takes no separate value", cmd: `xargs --replace rm {}`, want: `xargs --replace › rm[{}]`},
	{name: "wrapper: sudo -T", cmd: `sudo -T 60 rm x`, want: `sudo -T 60 › rm[x]`},
	{name: "wrapper: sudo clusters and attached values", cmd: `sudo -nu root -uroot --user=root --chdir /tmp rm x`, want: `sudo -nu root -uroot --user=root --chdir /tmp › rm[x]`},
	{name: "wrapper: sudo -e is sudoedit, unresolved", cmd: `sudo -e /etc/hosts`, want: `sudo -e /etc/hosts › ø`},
	{name: "wrapper: exec -a", cmd: `exec -a n rm x`, want: `exec -a n › rm[x]`},
	{name: "wrapper: env -S is unresolved", cmd: `env -S "rm -rf x"`, want: `env -S "rm -rf x" › ø`},
	{name: "wrapper: env --split-string is unresolved", cmd: `env --split-string='rm -rf' x`, want: `env --split-string='rm -rf' x › ø`},
	{name: "wrapper: env - is -i", cmd: `env - rm x`, want: `env - › rm[x]`},
	{name: "wrapper: env takes any word with = as assignment", cmd: `env -i 'a b=2' 'X%=1' rm x`, want: `env -i 'a b=2' 'X%=1' › rm[x]`},
	{name: "prefix assignment keeps the identifier rule", cmd: `X%=1 rm x`, want: `X%=1[rm][x]`},
	{name: "wrapper: unknown flag is unresolved", cmd: `sudo --frobnicate rm x`, want: `sudo --frobnicate rm x › ø`},
	{name: "wrapper: unknown short flag in a cluster is unresolved", cmd: `nohup -q rm x`, want: `nohup -q rm x › ø`},
	{name: "wrapper: lone - is unresolved", cmd: `sudo - rm x`, want: `sudo - rm x › ø`},
	{name: "wrapper: nice", cmd: `nice -n 5 rm x; nice -10 rm y; nice --adjustment=3 rm z`, want: `nice -n 5 › rm[x] ; nice -10 › rm[y] ; nice --adjustment=3 › rm[z]`},
	{name: "wrapper: time", cmd: `time -p rm x; time -f %e -o out rm y`, want: `time -p › rm[x] ; time -f %e -o out › rm[y]`},
	{name: "wrapper: stdbuf", cmd: `stdbuf -o L -eL --input=0 rm x`, want: `stdbuf -o L -eL --input=0 › rm[x]`},
	{name: "wrapper: setsid", cmd: `setsid -fw rm x`, want: `setsid -fw › rm[x]`},
	{name: "wrapper: doas", cmd: `doas -n -u root rm x`, want: `doas -n -u root › rm[x]`},
	{name: "wrapper: ionice", cmd: `ionice -c 3 -n7 -t rm x`, want: `ionice -c 3 -n7 -t › rm[x]`},
	{name: "wrapper: timeout long options", cmd: `timeout --signal=KILL --foreground -v 5 rm x`, want: `timeout --signal=KILL --foreground -v 5 › rm[x]`},
	{name: "wrapper: -- ends options", cmd: `sudo -- -rm x`, want: `sudo -- › -rm[x]`},

	// Review: backslash-newline joins words outside single quotes.
	{name: "continuation: before a word", cmd: "rm -rf \\\n/", want: `rm[-rf][/]`},
	{name: "continuation: before a flag", cmd: "git push \\\n--force", want: `git[push][--force]`},
	{name: "continuation: inside the head", cmd: "gi\\\nt push --force", want: "git<gi\\\nt>[push][--force]"},
	{name: "continuation: inside an argument", cmd: "cat .e\\\nnv", want: `cat«.env»`},
	{name: "continuation: alone between words", cmd: "ls \\\n -l", want: `ls[-l]`},
	{name: "continuation: single quotes keep it", cmd: "echo 'a\\\nb'", want: "echo«a\\\nb»"},
	{name: "continuation: a comment ends at the newline", cmd: "echo a # b \\\nrm x", want: `echo[a] ⏎ rm[x]`},
	// Review: $'...' and $"..." are quotes.
	{name: "ansi-c: flag", cmd: `rm $'-rf' /`, want: `rm«-rf»[/]`},
	{name: "ansi-c: head", cmd: `$'git' push --force`, want: `git<$'git'>[push][--force]`},
	{name: "ansi-c: escapes", cmd: `echo $'a\x41\101é\t\'q\z' $"loc" a$'\cA'`, want: "echo«aAAé\t'q\\z»«loc»«a\x01»"},
	{name: "ansi-c: invalid UTF-8 becomes U+FFFD", cmd: `echo $'\xff'`, want: "echo«�»"},
	{name: "dynamic head: variable", cmd: `$G push --force`, want: `$G[push][--force]`},
	{name: "dynamic head: substitution", cmd: `$(echo git) push --force`, want: `$ ( echo[git] ) push[--force]`},
	// Review: heredoc delimiters and closings bash reads differently.
	{name: "heredoc: $'EOF' delimiter is EOF", cmd: "cat <<$'EOF'\nx\nEOF\ngit push --force\n$EOF",
		want: "cat«<<EOF» ⏎ ø ⏎ git[push][--force] ⏎ $EOF", bodies: []string{"x"}},
	{name: "heredoc: a $( delimiter is opaque", cmd: "cat <<$(x)\na\n$(x)\ncat .env\n$",
		want: `cat[<<$] ( x ) ø ⏎ a ⏎ $ ( x ) ø ⏎ cat[.env] ⏎ $`, opaque: true},
	{name: "heredoc: EOF) closes in $(...)", cmd: "x=$(cat <<'EOF'\nhi\nEOF)\ngit push --force\nEOF",
		want: "x=$ › ø ( cat«<<EOF» ⏎ ø ) ø ⏎ git[push][--force] ⏎ EOF", bodies: []string{"hi"}},
	{name: "heredoc: EOFX) closes at EOF in $(...)", cmd: "x=$(cat <<EOF\nhi\nEOFX)\nls",
		want: "x=$ › ø ( cat[<<EOF] ⏎ X ) ø ⏎ ls", bodies: []string{"hi"}},
	{name: "heredoc: a prefix close after a continuation is opaque", cmd: "x=$(cat <<EOF\nE\\\nOFX)\nls",
		want: "x=$ › ø ( cat[<<EOF] ⏎ EOFX<E\\\nOFX> ) ø ⏎ ls", opaque: true},
	{name: "heredoc: in backticks", cmd: "x=`cat <<'EOF'\nrm -rf /\nEOF`",
		want: "x=`cat << 'EOF' › ø ⏎ ` ‹cat <<'EOF'\n            ›", bodies: []string{"rm -rf /"}},
	// Review round 2: bash 5.3 closes a heredoc in $(...) on a delimiter
	// prefix only with a `)` later on the line, in backticks at the first
	// unescaped backtick; comments run to the newline there.
	{name: "heredoc: EOFX is body text in $(...)", cmd: "x=$(cat <<EOF\nEOFX '\nEOF\n)\nrm -rf /\n#'",
		want: "x=$ › ø ( cat[<<EOF] ⏎ ø ⏎ ø ) ø ⏎ rm[-rf][/] ⏎ ø", bodies: []string{"EOFX '"}},
	{name: "heredoc: a delimiter-prefixed line is body text in $(...)", cmd: "x=$(cat <<'EOF'\nEOF is the marker\nEOF\n)",
		want: "x=$ › ø ( cat«<<EOF» ⏎ ø ⏎ ø ) ø", bodies: []string{"EOF is the marker"}},
	{name: "heredoc: EOF ) closes in $(...)", cmd: "x=$(cat <<EOF\nhi\nEOF )x\nls",
		want: "x=$ › ø ( cat[<<EOF] ⏎ ø ) x ⏎ ls", bodies: []string{"hi"}},
	{name: "heredoc: EOF ) is body text in backticks", cmd: "x=`cat <<EOF\nEOF )\nEOF\n`",
		want: "x=`cat << EOF › ø ⏎ ø ⏎ ` ‹cat <<EOF\n         \n›", bodies: []string{"EOF )"}},
	{name: "heredoc: a backtick ends the body in backticks", cmd: "x=`cat <<EOF\nab`; rm -rf /\nEOF\n`",
		want: "x=`cat << EOF › ø ⏎ ` ; rm[-rf][/] ⏎ EOF ⏎ ` ‹cat <<EOF\n  ›", bodies: []string{"ab"}},
	{name: "heredoc: an escaped backtick stays in the body", cmd: "x=`cat <<'EOF'\na\\`b\nEOF\n`",
		want: "x=`cat << 'EOF' › ø ⏎ ø ⏎ ` ‹cat <<'EOF'\n        \n›", bodies: []string{"a\\`b"}},
	{name: "heredoc: a backtick in $(...) in backticks is opaque", cmd: "x=`echo $(cat <<EOF\nab`; rm x\nEOF\n)`",
		want: "x=`echo › $ ( cat[<<EOF] ⏎ ab` ; rm[x] ⏎ EOF ⏎ ø ) ` ‹echo $(cat <<EOF\nab›", opaque: true},
	{name: "comment: runs to the newline in $(...)", cmd: "echo $(# ) '\nrm -rf /\n#'\n)", want: "echo[$] ( ø ⏎ rm[-rf][/] ⏎ ø ⏎ ø ) ø"},
	{name: "comment: runs to the newline in backticks", cmd: "x=`# ) '\nrm -rf /\n#'\n`", want: "x=` › ø ⏎ rm[-rf][/] ⏎ ø ⏎ ` ‹     \nrm -rf /\n  \n›"},
	{name: "comment: ends at a backtick in $(...) in backticks", cmd: "x=`echo $(echo a # b`; rm x\n)`", want: "x=`echo › $ ( echo[a][`] ; rm[x] ⏎ ø ) ` ‹echo $(echo a    ›"},
	// Review: redirections end words; their targets are not operands.
	{name: "redirect: attached", cmd: `git push --force>/dev/null; rm -rf />/dev/null; cat<.env`,
		want: `git[push][--force][>/dev/null] ; rm[-rf][/][>/dev/null] ; cat[<.env]`},
	{name: "redirect: fd and kinds", cmd: `go test 2>&1 &>f >>g <<<w >&2 2>>e <>rw >|c`,
		want: `go[test][2>&1][&>f][>>g][<<<w][>&2][2>>e][<>rw][>|c]`},
	{name: "redirect: before the head", cmd: `>/dev/null 2>&1 rm -rf x`, want: `> /dev/null 2>& 1 › rm[-rf][x]`},
	{name: "redirect: a word with digits is no fd", cmd: `echo a2>f`, want: `echo[a2][>f]`},
	{name: "redirect: process substitution is a word", cmd: `bash <(curl x)`, want: `bash[<] ( curl[x] ) ø`},
	// Review: comments run nothing.
	{name: "comment: parenthesis", cmd: `echo ok # see (mkfs docs)`, want: `echo[ok]`},
	{name: "comment: whole line", cmd: "# note (rm -rf ~ is blocked)\nls", want: `ø ⏎ ls`},
	{name: "comment: separator", cmd: `echo hi # ; rm -rf /`, want: `echo[hi]`},
	{name: "comment: ends at a backtick inside backticks", cmd: "echo `ls # x`; rm y", want: "echo[`ls][`] ; rm[y] ‹ls    ›"},
	{name: "comment: mid-word # is no comment", cmd: `echo a#b $# ${#x}`, want: `echo[a#b][$#][${#x}]`},
	// Review: more prefixes and wrappers.
	{name: "prefix: function keyword", cmd: `function f { git push --force; }; f`, want: `function f { › git[push][--force] ; } ; f`},
	{name: "prefix: coproc", cmd: `coproc git push; coproc N { rm x; }`, want: `coproc › git[push] ; coproc N { › rm[x] ; }`},
	{name: "wrapper: builtin and busybox", cmd: `builtin eval x; busybox rm -rf y`, want: `builtin › eval[x] ; busybox › rm[-rf][y]`},
	{name: "wrapper: flock and taskset", cmd: `flock -n /tmp/l git push; taskset -c 0 rm x; flock /tmp/l -c 'rm y'`,
		want: `flock -n /tmp/l › git[push] ; taskset -c 0 › rm[x] ; flock /tmp/l › -c«rm y»`},
	// A wrapper whose options end the segment with --help/--version only prints: the wrapper is the head.
	{name: "wrapper: info flag alone", cmd: `flock --version; flock -V; timeout --help; env -i --version`,
		want: `flock[--version] ; flock[-V] ; timeout[--help] ; env[-i][--version]`},
}

func TestVectors(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name+": "+v.cmd, func(t *testing.T) {
			checkInvariants(t, v.cmd)
			if got := render(v.cmd); got != v.want {
				t.Errorf("render(%q)\n got: %s\nwant: %s", v.cmd, got, v.want)
			}
			ps := payloads(v.cmd)
			for payload, want := range v.nested {
				if !slices.Contains(ps, payload) {
					t.Errorf("payload %q is not an argument, argument run or backtick body of %q", payload, v.cmd)
				}
				if got := render(payload); got != want {
					t.Errorf("render(%q)\n got: %s\nwant: %s", payload, got, want)
				}
			}
			var bodies []string
			for _, h := range Heredocs(v.cmd) {
				bodies = append(bodies, v.cmd[h.BodyStart:h.BodyEnd])
			}
			if !slices.Equal(bodies, v.bodies) {
				t.Errorf("heredoc bodies of %q = %q, want %q", v.cmd, bodies, v.bodies)
			}
			if got := Opaque(v.cmd); got != v.opaque {
				t.Errorf("Opaque(%q) = %v, want %v", v.cmd, got, v.opaque)
			}
		})
	}
}

func TestTokenize(t *testing.T) {
	cmd := `a "b\"c\x" 'd\'e\ f&&g||h|i&j;k(l)` + "\nm"
	want := []Token{
		{Value: "a", Raw: "a", Index: 0},
		{Value: `b"c\x`, Raw: `"b\"c\x"`, Index: 2},
		{Value: `d\e f`, Raw: `'d\'e\ f`, Index: 11},
		{Value: "&&", Raw: "&&", Operator: true, Index: 19},
		{Value: "g", Raw: "g", Index: 21},
		{Value: "||", Raw: "||", Operator: true, Index: 22},
		{Value: "h", Raw: "h", Index: 24},
		{Value: "|", Raw: "|", Operator: true, Index: 25},
		{Value: "i", Raw: "i", Index: 26},
		{Value: "&", Raw: "&", Operator: true, Index: 27},
		{Value: "j", Raw: "j", Index: 28},
		{Value: ";", Raw: ";", Operator: true, Index: 29},
		{Value: "k", Raw: "k", Index: 30},
		{Value: "(", Raw: "(", Operator: true, Index: 31},
		{Value: "l", Raw: "l", Index: 32},
		{Value: ")", Raw: ")", Operator: true, Index: 33},
		{Value: "\n", Raw: "\n", Operator: true, Index: 34},
		{Value: "m", Raw: "m", Index: 35},
	}
	if got := Tokenize(cmd, true); !slices.Equal(got, want) {
		t.Errorf("Tokenize(%q)\n got: %+v\nwant: %+v", cmd, got, want)
	}
	// blank=false keeps heredoc bodies as tokens.
	heredoc := "cat <<E\nrm x\nE"
	if got := len(Tokenize(heredoc, false)); got != 8 {
		t.Errorf("Tokenize(%q, false) = %d tokens, want 8", heredoc, got)
	}
	if got := len(Tokenize(heredoc, true)); got != 4 {
		t.Errorf("Tokenize(%q, true) = %d tokens, want 4", heredoc, got)
	}
}

func TestBlankHeredocs(t *testing.T) {
	for cmd, want := range map[string]string{
		"cat <<'EOF'\nrm -rf /\nEOF\nls": "cat <<'EOF'\n            \nls",
		"cat <<EOF\nx":                   "cat <<EOF\nx",
		"cat <<EOF\nEOF":                 "cat <<EOF\n   ", // an empty body
		"cat <<EOF\n\nEOF":               "cat <<EOF\n    ",
		"cat <<EOF x\nb\nEOF\n":          "cat <<EOF x\n     \n",
		"cat <<'EOF x'\nb\nEOF x":        "cat <<'EOF x'\n       ", // a quoted delimiter may hold a space
		"cat <<\nEOF\nb\nEOF":            "cat <<\nEOF\nb\nEOF",    // no delimiter word: a syntax error, not a heredoc
	} {
		if got := BlankHeredocs(cmd); got != want {
			t.Errorf("BlankHeredocs(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestBacktickBodies(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want []BacktickBody
	}{
		{"echo `a` \"`b`\" '`c`' \\`d\\` `e", []BacktickBody{{"a", 5}, {"b", 10}}},
		{"x `a\\`b\\$c\\\\d\\e`", []BacktickBody{{"a`b$c\\d\\e", 2}}},
		{"cat <<E\n`rm x`\nE\necho `ls`", []BacktickBody{{"ls", 22}}},
	} {
		if got := BacktickBodies(c.cmd); !slices.Equal(got, c.want) {
			t.Errorf("BacktickBodies(%q) = %+v, want %+v", c.cmd, got, c.want)
		}
	}
}

func TestSets(t *testing.T) {
	for name, want := range map[string]bool{"grep": true, "sed": false, "cat": true, "sh": false} {
		if DataCommands[name] != want {
			t.Errorf("DataCommands[%q] = %v", name, !want)
		}
	}
	if got := Executable("/usr/bin/psql"); got != "psql" {
		t.Errorf("Executable = %q", got)
	}
}

// checkInvariants holds for every input: segments and their separators tile
// the input in order, tokens lie inside their segment and match the
// heredoc-blanked text, and every returned range or index is in bounds.
// separators end a segment when unquoted.
var separators = map[string]bool{";": true, "&&": true, "||": true, "|": true, "&": true, "\n": true, "(": true, ")": true}

func checkInvariants(t *testing.T, command string) {
	t.Helper()
	blanked := BlankHeredocs(command)
	if len(blanked) != len(command) {
		t.Fatalf("BlankHeredocs changed length: %d -> %d", len(command), len(blanked))
	}
	for i := range len(command) {
		if blanked[i] != command[i] && blanked[i] != ' ' {
			t.Fatalf("BlankHeredocs changed byte %d to %q", i, blanked[i])
		}
	}
	segs := Segments(command)
	if len(segs) == 0 {
		t.Fatal("no segments")
	}
	pos, operators := 0, 0
	for i, s := range segs {
		if s.Start != pos || s.Start > s.End || s.End > len(command) || s.Raw != command[s.Start:s.End] {
			t.Fatalf("segment %d [%d,%d) breaks the tiling at %d", i, s.Start, s.End, pos)
		}
		if (s.Separator == "") != (i == len(segs)-1) || (s.Separator != "" && !separators[s.Separator]) {
			t.Fatalf("segment %d separator %q", i, s.Separator)
		}
		if s.Separator != "" {
			operators++
			if blanked[s.End:s.End+len(s.Separator)] != s.Separator {
				t.Fatalf("segment %d separator %q not at %d", i, s.Separator, s.End)
			}
		}
		pos = s.End + len(s.Separator)
		if s.Cursor < 0 || s.Cursor > len(s.Tokens) {
			t.Fatalf("segment %d cursor %d of %d", i, s.Cursor, len(s.Tokens))
		}
		at := s.Start
		for _, tok := range s.Tokens {
			if tok.Operator || tok.Raw == "" || tok.Index < at || tok.Index+len(tok.Raw) > s.End || blanked[tok.Index:tok.Index+len(tok.Raw)] != tok.Raw {
				t.Fatalf("segment %d token %+v out of place (from %d)", i, tok, at)
			}
			if utf8.ValidString(command) && !utf8.ValidString(tok.Value) {
				t.Fatalf("token %+v value is not valid UTF-8", tok)
			}
			at = tok.Index + len(tok.Raw)
		}
	}
	if pos != len(command) {
		t.Fatalf("segments end at %d, input at %d", pos, len(command))
	}
	ops := 0
	for _, tok := range Tokenize(command, true) {
		if tok.Operator {
			ops++
		}
	}
	if ops != operators {
		t.Fatalf("%d operators, %d separators", ops, operators)
	}
	end := 0
	for _, h := range Heredocs(command) {
		if h.BodyStart < end || !(h.Index < h.BodyStart && h.BodyStart <= h.BodyEnd && h.BodyEnd <= len(command)) ||
			command[h.Index:h.Index+2] != "<<" {
			t.Fatalf("heredoc %+v out of place", h)
		}
		end = h.BodyEnd
	}
	for _, b := range BacktickBodies(command) {
		if b.Index < 0 || b.Index >= len(command) || command[b.Index] != '`' {
			t.Fatalf("backtick body %+v out of place", b)
		}
	}
}

func FuzzTokenize(f *testing.F) {
	for _, v := range vectors {
		f.Add(v.cmd)
		for p := range v.nested {
			f.Add(p)
		}
	}
	f.Fuzz(func(t *testing.T, command string) {
		checkInvariants(t, command)
		Opaque(command)
		Unread(command)
		BacktickBodies(command)
		SubstEnd(command, 0)
	})
}

func TestUnread(t *testing.T) {
	for command, want := range map[string]bool{
		`echo ${ x; }`:                        true,
		`echo "${ x; }"`:                      true,
		"echo ${\tx; }":                       true,
		`echo ${|x; }`:                        true,
		"echo $\\\n{ x; }":                    true,
		`echo "$(echo "'")"${ x; }"`:          true,
		`echo "${x:-"'"${ x; }"'"}"`:          true,
		`echo $$'\'${ x; }''`:                 true,
		`echo "${x#'a'}"`:                     true, // quotes or not by the operator
		`echo ${x:-$'\'' ${ x; } $'\''}`:      true,
		`echo $(( ' )) ${ x; }`:               true, // stopped at the quote: the rest counts
		"cat <<EOF\n${ x; }":                  true, // unterminated heredoc
		`echo '${ x; }' \${ x; } $'${ x; }'`:  false,
		`echo ${x} ${#x} "${x:-y}" ${x:-'y'}`: false,
		`echo $${ x; }`:                       false,
		"echo hi # ${ x; }":                   false,
		"cat <<'EOF'\n${ x; }\nEOF":           false,
		`echo '${{ github.sha }}'`:            false,
	} {
		if got := Unread(command); got != want {
			t.Errorf("Unread(%q) = %v, want %v", command, got, want)
		}
	}
}

func TestSubstEnd(t *testing.T) {
	for s, want := range map[string]string{
		`a) b`:                   `a`,
		`a (b) c) d`:             `a (b) c`,
		`echo ')' "(" x) y`:      `echo ')' "(" x`,
		`echo \) $'\')' x) y`:    `echo \) $'\')' x`,
		`echo 'a) b`:             `echo 'a) b`, // unterminated quote
		`echo ${x:-)} "a)" b) c`: `echo ${x:-)} "a)" b`,
		`a (b`:                   `a (b`,
	} {
		if got := s[:SubstEnd(s, 0)]; got != want {
			t.Errorf("SubstEnd(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestDollarDollar(t *testing.T) {
	tokens := Tokenize(`echo $$'\'; ls ''`, false)
	var raws []string
	for _, tok := range tokens {
		raws = append(raws, tok.Raw)
	}
	if want := []string{"echo", `$$'\'`, ";", "ls", "''"}; !slices.Equal(raws, want) {
		t.Fatalf("got %q, want %q", raws, want)
	}
	if tokens[1].Value != `$$\` {
		t.Errorf("value %q", tokens[1].Value)
	}
}
