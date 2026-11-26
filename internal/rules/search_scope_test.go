package rules

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/hook"
)

var ssGit = sync.OnceValue(func() string { p, _ := exec.LookPath("git"); return p })

// ssRepo builds a git repo with vendor/ ignored, vendor/acme/ and app/.
func ssRepo(t *testing.T, gitignore string) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repo := t.TempDir()
	if out, err := exec.Command(ssGit(), "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	for _, d := range []string{"vendor/acme", "app"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if gitignore != "" {
		os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(gitignore), 0o644)
	}
	return repo
}

func ssApply(ctx context.Context, cwd, cmd string) *hook.Decision {
	ti, _ := json.Marshal(map[string]string{"command": cmd})
	in := &hook.Input{HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: ti, Cwd: cwd}
	return searchScope{}.Apply(ctx, in, suiteCfg(), nil)
}

func TestSearchScope(t *testing.T) {
	repo := ssRepo(t, "vendor/\n")
	fire := []string{
		"grep -rn x .",
		"grep -rn x",
		"grep -R x",
		"grep --recursive x .",
		"grep --dereference-recursive x .",
		"grep -d recurse x .",
		"grep --directories=recurse x",
		"grep -nr x .",
		"grep -e foo -r .",
		"grep -rn --include=*.php x .",
		"grep -rn --exclude-dir node_modules x .",
		"grep -rn x . app",
		"time grep -rn x .",
		"time -p grep -rn x .",
		"( grep -rn x . )",
		"{ grep -rn x .; }",
		"! grep -rn x .",
		"VAR=1 grep -rn x .",
		`"grep" -rn x .`,
		`\grep -rn x .`,
		"echo a && grep -rn x .",
		"cd app && grep -rn x ..",
		"cd . && grep -rn x .",
		"rg x",
		"rg -n x .",
		"rg -e x -t php .",
		"rg -r repl x",
		"git grep x",
		"git grep -n x",
		"git -C " + repo + " grep x",
		"git -c color.ui=never grep x",
		"command git grep x",
		"cd /nonexistent && cd " + repo + " && grep -rn x .",
		"grep -rn x " + repo,
		// review: ugrep value options, depth forms, git long values, git ignores stdin
		"grep -rn -t php x",
		"grep -rn -g '*.php' x",
		"grep -rn -J 4 x",
		"grep -rn -O php x",
		"grep -rn -M text x",
		"grep -rn -N y x",
		"grep -rn --glob '*.php' x",
		"grep -rn --file-type php x",
		"grep -3 x .",
		"grep -10 x .",
		"grep --depth=2 x .",
		"rg --dfa-size-limit 1M x",
		"git grep --context 3 x",
		"git grep --max-count 1 x",
		"cat f | git grep x",
		// the ugrep shim recurses the cwd even when stdin is a pipe or a file
		"cat f | grep -r x",
		"grep -r x < in",
		"rg x > out",
		// real rg skips ignored dirs too: wrappers and paths keep it
		"/usr/bin/rg x",
		"command rg x",
		"env rg -n x .",
		"sudo rg x",
		"timeout 5 rg x",
		// Soak: only a downstream grep -v naming the dir, or --exclude-dir matching it, silences
		"grep -rn x . | grep vendor",
		"grep -rn x . | grep -v node_modules",
		"grep -rn x .; grep -v vendor f",
		"grep -rn x . && grep -v vendor f",
		"grep -rn --exclude-dir=vend x .",
		"grep -rn --exclude-dir={generated,pub} x .",
	}
	for _, c := range fire {
		d := ssApply(context.Background(), repo, c)
		if d == nil || d.AdditionalContext == "" || d.Permission != "" || d.UpdatedInput != nil {
			t.Errorf("want fire: %q got %+v", c, d)
			continue
		}
		if len(d.AdditionalContext) > 200 || !strings.Contains(d.AdditionalContext, "vendor/ is gitignored") {
			t.Errorf("%q message: %q", c, d.AdditionalContext)
		}
	}
	silent := []string{
		"grep -n x file",
		"grep x .",
		"cat f | grep x",
		"cat f | rg x",
		"grep -rn x app vendor",
		"grep -rn x . vendor",
		"grep -rn x vendor",
		"grep -rn x vendor/acme",
		"cd vendor && grep -rn x .",
		"cd vendor/acme && grep -rn x .",
		"cd $X && grep -r x .",
		"cd && grep -r x .",
		"cd - && grep -r x .",
		"pushd app && grep -r x .",
		"cd app; popd; grep -r x ..",
		"grep -r x $DIR",
		"grep -r x *",
		"grep -r x ~",
		"grep -r x {a,b}",
		"grep -r x vend?r",
		"$G -r x .",
		"command grep -rn x .",
		"exec grep -rn x .",
		"builtin grep -rn x .",
		"env grep -rn x .",
		"sudo grep -rn x .",
		"nice grep -rn x .",
		"timeout 5 grep -rn x .",
		"xargs grep -r x .",
		"/usr/bin/grep -rn x .",
		"./grep -rn x .",
		"find . -exec grep -r x {} +",
		"bash -c 'grep -rn x .'",
		"grep -rn x . --no-ignore-files",
		"grep -rnz x .",
		"grep -rZ x .",
		"grep -r --null x .",
		"grep -r --null-data x .",
		"grep -r --filter=x x .",
		"grep -r --config=x x .",
		"grep -r --pager x .",
		"grep -r -@ x .",
		"grep -r --all x .",
		"grep -r --format-open=x x .",
		"rg -uu x",
		"rg -u x",
		"rg -uuu x",
		"rg --no-ignore x",
		"rg --no-ignore-vcs x",
		"rg x vendor",
		"rg --files vendor",
		"git grep --no-index x",
		"git grep --untracked --no-exclude-standard x",
		"git grep x vendor",
		"git grep x -- vendor",
		"git log",
		"echo grep -r x .",
		"git -C /nonexistent-dir grep x",
		// review: -u inside a cluster, --unrestricted, stdin redirect, depth 1
		"rg -nu x",
		"rg -un x",
		"rg -lu x .",
		"rg --unrestricted x",
		"rg x < in",
		"rg x 0< in",
		"grep -1 x .",
		"grep --depth=1 x .",
		// Soak: the command drops the dir on purpose (live false positives)
		"grep -rn --exclude-dir=vendor x .",
		"grep -rn --exclude-dir vendor x .",
		"grep -rn --exclude-dir=vendor/ x .",
		"grep -rn --exclude-dir='vend*' x .",
		`grep -rlI "12345" --exclude-dir={generated,vendor,pub,var,node_modules} . 2>/dev/null | head`,
		"grep -rn x . | grep -v vendor",
		`grep -rn x . 2>/dev/null | grep -v "^./vendor\\|^./node_modules\\|CHANGELOG"`,
		"grep -rn -i x . 2>/dev/null | grep -v -E 'node_modules|vendor|public/b' | head",
		"grep -rn x . | grep -v node_modules | grep -v vendor | head -8",
		"grep -rn x . | grep -ve vendor",
		"grep -rn x . | grep --invert-match vendor",
	}
	for _, c := range silent {
		if d := ssApply(context.Background(), repo, c); d != nil {
			t.Errorf("want silent: %q got %+v", c, d)
		}
	}
	// --no-index with --exclude-standard still skips ignored files
	if d := ssApply(context.Background(), repo, "git grep --no-index --exclude-standard x"); d == nil {
		t.Error("git grep --no-index --exclude-standard should fire")
	}
	// value options: -e makes every positional a path
	if d := ssApply(context.Background(), repo, "grep -r -e x vendor"); d != nil {
		t.Errorf("-e then vendor path: %+v", d)
	}
	if d := ssApply(context.Background(), repo, "rg -g '*.php' x vendor"); d != nil {
		t.Errorf("rg -g then vendor path: %+v", d)
	}
}

func TestSearchScopeRepoState(t *testing.T) {
	repo := ssRepo(t, "vendor/\n")
	if d := ssApply(context.Background(), "", "grep -rn x ."); d != nil {
		t.Errorf("empty cwd: %+v", d)
	}
	// vendor absent
	os.RemoveAll(filepath.Join(repo, "vendor"))
	if d := ssApply(context.Background(), repo, "grep -rn x ."); d != nil {
		t.Errorf("vendor absent: %+v", d)
	}
	// vendor not ignored
	repo2 := ssRepo(t, "")
	if d := ssApply(context.Background(), repo2, "grep -rn x ."); d != nil {
		t.Errorf("not ignored: %+v", d)
	}
	// not a repo
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(t.TempDir()))
	plain := filepath.Join(t.TempDir(), "plain")
	os.MkdirAll(filepath.Join(plain, "vendor"), 0o755)
	if d := ssApply(context.Background(), plain, "grep -rn x ."); d != nil {
		t.Errorf("not a repo: %+v", d)
	}
}

func TestSearchScopeTrackedStillFires(t *testing.T) {
	repo := ssRepo(t, "vendor/\n")
	os.WriteFile(filepath.Join(repo, "vendor/acme/a.php"), []byte("x"), 0o644)
	if out, err := exec.Command(ssGit(), "-C", repo, "add", "-f", "vendor/acme/a.php").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if d := ssApply(context.Background(), repo, "grep -rn x ."); d == nil {
		t.Error("tracked but gitignored vendor should still fire")
	}
}

func TestSearchScopeMessage(t *testing.T) {
	repo := ssRepo(t, "vendor/\n")
	d := ssApply(context.Background(), repo, "grep -rn x .")
	want := "search_scope: vendor/ is gitignored and skipped by this grep; name it as a path (e.g. vendor) or use `command grep -r` to include it."
	if d == nil || d.AdditionalContext != want {
		t.Fatalf("got %+v", d)
	}
	d = ssApply(context.Background(), repo, "cd app && grep -rn x ..")
	if d == nil || !strings.Contains(d.AdditionalContext, "(e.g. ../vendor)") {
		t.Fatalf("got %+v", d)
	}
	d = ssApply(context.Background(), repo, "rg x")
	if d == nil || !strings.Contains(d.AdditionalContext, "this rg;") {
		t.Fatalf("got %+v", d)
	}
	d = ssApply(context.Background(), repo, "git grep x")
	if d == nil || !strings.Contains(d.AdditionalContext, "this git grep;") {
		t.Fatalf("got %+v", d)
	}
	long := strings.Repeat("sub/", 40)
	os.MkdirAll(filepath.Join(repo, long, "vendor"), 0o755)
	d = ssApply(context.Background(), repo, "grep -rn x "+filepath.Join(repo, long))
	if d == nil || len(d.AdditionalContext) > 200 || !strings.Contains(d.AdditionalContext, "(e.g. vendor)") {
		t.Fatalf("long root: %+v", d)
	}
}

func TestSearchScopeLimits(t *testing.T) {
	repo := ssRepo(t, "vendor/\n")
	big := "grep -rn x . # " + strings.Repeat("a", 17<<10)
	if d := ssApply(context.Background(), repo, big); d != nil {
		t.Errorf("oversized: %+v", d)
	}
	n := 0
	old := checkIgnore
	checkIgnore = func(ctx context.Context, root, dir string) bool { n++; return old(ctx, root, dir) }
	defer func() { checkIgnore = old }()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if d := ssApply(ctx, repo, "grep -rn x ."); d != nil || n != 0 {
		t.Errorf("expired ctx: %+v execs=%d", d, n)
	}
	if d := ssApply(context.Background(), repo, "grep -rn x . ; rg x ; git grep x"); d == nil || n != 1 {
		t.Errorf("one hit, cached: %+v execs=%d", d, n)
	}
}

func TestSearchScopeTildeCd(t *testing.T) {
	repo := ssRepo(t, "vendor/\n")
	t.Setenv("HOME", filepath.Dir(repo))
	if d := ssApply(context.Background(), "/", "cd ~/"+filepath.Base(repo)+" && grep -rn x ."); d == nil {
		t.Error("cd ~/<repo> should resolve through HOME and fire")
	}
	for _, c := range []string{"cd ~other/x && grep -rn x .", "cd ~ && grep -rn x " + filepath.Base(repo) + "/vendor"} {
		if d := ssApply(context.Background(), "/", c); d != nil {
			t.Errorf("want silent: %q got %+v", c, d)
		}
	}
}
