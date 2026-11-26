package rules

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
)

func lintIn(file string) *hook.Input {
	b, _ := json.Marshal(map[string]string{"file_path": file})
	return &hook.Input{HookEventName: "PostToolUse", ToolName: "Edit", ToolInput: b}
}

func lintRun(t *testing.T, name, body string, mut func(*config.Lint)) *hook.Decision {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := suiteCfg()
	if mut != nil {
		mut(&cfg.Rules.Lint)
	}
	return lint{}.Apply(context.Background(), lintIn(p), cfg, nil)
}

func need(t *testing.T, bin string) {
	t.Helper()
	if err := exec.Command(bin, "--version").Run(); err != nil {
		t.Skip(bin + " not usable")
	}
}

func TestLintPHP(t *testing.T) {
	need(t, "php")
	if d := lintRun(t, "ok.php", "<?php echo 1;\n", nil); d != nil {
		t.Fatalf("valid php: %+v", d)
	}
	d := lintRun(t, "bad.php", "<?php echo ;\n", nil)
	if d == nil || !d.Block || d.Hard || !strings.HasPrefix(d.Reason, "BLOCK: php -l failed: ") {
		t.Fatalf("bad php: %+v", d)
	}
	if d := lintRun(t, "bad.php", "<?php echo ;\n", func(l *config.Lint) { l.PHP = false }); d != nil {
		t.Fatalf("php off: %+v", d)
	}
}

func TestLintNode(t *testing.T) {
	need(t, "node")
	if d := lintRun(t, "ok.js", "let a = 1;\n", nil); d != nil {
		t.Fatalf("valid js: %+v", d)
	}
	for _, f := range []string{"bad.js", "bad.mjs", "bad.cjs"} {
		d := lintRun(t, f, "let = ;\n", nil)
		if d == nil || !d.Block || !strings.HasPrefix(d.Reason, "BLOCK: node --check failed: ") {
			t.Fatalf("%s: %+v", f, d)
		}
	}
	if d := lintRun(t, "bad.js", "let = ;\n", func(l *config.Lint) { l.Node = false }); d != nil {
		t.Fatalf("node off: %+v", d)
	}
}

func TestLintBoundsOutput(t *testing.T) {
	need(t, "node")
	d := lintRun(t, "big.js", "let x = '"+strings.Repeat("a", 20000)+";\n", nil)
	if d == nil || len(d.Reason) > 5000 {
		t.Fatalf("unbounded: %v", d)
	}
}

func TestLintStaticAnalysis(t *testing.T) {
	need(t, "php")
	root := t.TempDir()
	bin := filepath.Join(root, "vendor", "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(root, "composer.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(root, "phpstan.neon"), nil, 0o644)
	os.WriteFile(filepath.Join(bin, "phpstan"), []byte("#!/bin/sh\necho stan-says-no\nexit 1\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "phpcs"), []byte("#!/bin/sh\necho cs-says-no\nexit 1\n"), 0o755)
	f := filepath.Join(root, "src", "a.php")
	os.MkdirAll(filepath.Dir(f), 0o755)
	os.WriteFile(f, []byte("<?php echo 1;\n"), 0o644)

	run := func(mut func(*config.Lint)) *hook.Decision {
		cfg := suiteCfg()
		if mut != nil {
			mut(&cfg.Rules.Lint)
		}
		return lint{}.Apply(context.Background(), lintIn(f), cfg, nil)
	}
	d := run(nil)
	if d == nil || d.Block || !strings.Contains(d.AdditionalContext, "[php-lint] phpstan warnings:\nstan-says-no") ||
		!strings.Contains(d.AdditionalContext, "[php-lint] phpcs warnings:\ncs-says-no") {
		t.Fatalf("both: %+v", d)
	}
	d = run(func(l *config.Lint) { l.PHPStan = false })
	if d == nil || strings.Contains(d.AdditionalContext, "phpstan") || !strings.Contains(d.AdditionalContext, "phpcs") {
		t.Fatalf("stan off: %+v", d)
	}
	if d = run(func(l *config.Lint) { l.PHPStan, l.PHPCS = false, false }); d != nil {
		t.Fatalf("both off: %+v", d)
	}
	os.Remove(filepath.Join(root, "phpstan.neon"))
	d = run(nil)
	if d == nil || strings.Contains(d.AdditionalContext, "phpstan") {
		t.Fatalf("no neon: %+v", d)
	}
}

func TestLintNoOpinion(t *testing.T) {
	if d := lintRun(t, "a.txt", "x", nil); d != nil {
		t.Fatalf("txt: %+v", d)
	}
	cfg := suiteCfg()
	for _, in := range []*hook.Input{
		{HookEventName: "PostToolUse", ToolName: "Edit"},
		lintIn("/nonexistent/x.php"),
	} {
		if d := (lint{}).Apply(context.Background(), in, cfg, nil); d != nil {
			t.Fatalf("%+v", d)
		}
	}
}

func TestLintRelativePathUsesCwd(t *testing.T) {
	need(t, "php")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.php"), []byte("<?php echo ;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := lintIn("bad.php")
	in.Cwd = dir
	if d := (lint{}).Apply(context.Background(), in, suiteCfg(), nil); d == nil || !d.Block {
		t.Fatalf("got %+v", d)
	}
}

func TestLintOrphanedGrandchildDoesNotHang(t *testing.T) {
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "php"), []byte("#!/bin/sh\nsleep 12 &\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+":"+os.Getenv("PATH"))
	start := time.Now()
	lintRun(t, "ok.php", "<?php echo 1;\n", nil)
	if el := time.Since(start); el > 6*time.Second {
		t.Fatalf("lint waited %v for an orphaned grandchild", el)
	}
}
