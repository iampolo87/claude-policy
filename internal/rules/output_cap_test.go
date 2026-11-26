package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
)

func ocCfg(mode string) *config.Config {
	c := suiteCfg()
	c.Rules.OutputCap.Mode = mode
	return c
}

func ocIn(tool string, resp any, scratch string) *hook.Input {
	b, _ := json.Marshal(resp)
	return &hook.Input{HookEventName: "PostToolUse", ToolName: tool, ToolResponse: b, ToolUseID: "toolu_01", ScratchpadDir: scratch}
}

func ocBashResp(so, se string) map[string]any {
	return map[string]any{"stdout": so, "stderr": se, "interrupted": false, "isImage": false, "noOutputExpected": false}
}

func ocApply(in *hook.Input, mode string) *hook.Decision {
	return outputCap{}.Apply(context.Background(), in, ocCfg(mode), nil)
}

func TestOutputCapBashOverCap(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "200001")
	dir := t.TempDir()
	so := strings.Repeat("a", 100000) + strings.Repeat("b", 100000)
	d := ocApply(ocIn("Bash", ocBashResp(so, ""), dir), "enforce")
	if d == nil || d.UpdatedToolOutput == nil {
		t.Fatalf("want rewrite, got %+v", d)
	}
	if len(d.UpdatedToolOutput) >= 10000 {
		t.Fatalf("replacement %d bytes", len(d.UpdatedToolOutput))
	}
	var m map[string]any
	if err := json.Unmarshal(d.UpdatedToolOutput, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"stdout", "stderr", "interrupted", "isImage", "noOutputExpected"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %s lost", k)
		}
	}
	got := m["stdout"].(string)
	path := filepath.Join(dir, "policy-spill", "toolu_01.txt")
	ptr := func(n int) string {
		return fmt.Sprintf("\n… %d chars omitted; full output: %s (grep/sed -n it)\n", n, path)
	}
	bud := 8000 - len(ptr(200000)) // the pointer counts against the budget
	h := bud * 30 / 100
	if want := strings.Repeat("a", h) + ptr(200000-bud) + strings.Repeat("b", bud-h); got != want {
		t.Fatalf("got %d chars, want %d: %q", len(got), len(want), got[h-20:h+120])
	}
	if !strings.Contains(d.Reason, "Bash 200000 → 8000") || !strings.Contains(d.Reason, path) {
		t.Fatalf("reason %q", d.Reason)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != so {
		t.Fatalf("spill wrong: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestOutputCapBashUnderCapAndImage(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	dir := t.TempDir()
	if d := ocApply(ocIn("Bash", ocBashResp(strings.Repeat("x", 8000), ""), dir), "enforce"); d != nil {
		t.Fatalf("at cap: %+v", d)
	}
	r := ocBashResp(strings.Repeat("x", 20000), "")
	r["isImage"] = true
	if d := ocApply(ocIn("Bash", r, dir), "enforce"); d != nil {
		t.Fatalf("image: %+v", d)
	}
}

func TestOutputCapBashStderrBudget(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	dir := t.TempDir()
	so, se := strings.Repeat("o", 20000), strings.Repeat("e", 5000)
	d := ocApply(ocIn("Bash", ocBashResp(so, se), dir), "enforce")
	var m map[string]string
	var raw map[string]json.RawMessage
	json.Unmarshal(d.UpdatedToolOutput, &raw)
	json.Unmarshal(raw["stdout"], new(string))
	m = map[string]string{}
	for _, k := range []string{"stdout", "stderr"} {
		var s string
		json.Unmarshal(raw[k], &s)
		m[k] = s
	}
	if n := strings.Count(m["stderr"], "e"); n < 1800 || n > 2010 { // 2000 budget incl. pointer; "e" also in the pointer text
		t.Fatalf("stderr kept %d", n)
	}
	if len(m["stdout"]) > 6000 || !strings.HasPrefix(m["stdout"], strings.Repeat("o", 1700)) || !strings.HasSuffix(m["stdout"], strings.Repeat("o", 4000)) {
		t.Fatal("stdout budget wrong")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "policy-spill", "toolu_01.txt"))
	if string(b) != so+"\n--- stderr ---\n"+se {
		t.Fatal("spill content wrong")
	}
	// small stderr stays whole
	d = ocApply(ocIn("Bash", ocBashResp(so, "boom"), dir), "enforce")
	json.Unmarshal(d.UpdatedToolOutput, &raw)
	if string(raw["stderr"]) != `"boom"` {
		t.Fatalf("stderr %s", raw["stderr"])
	}
}

func TestOutputCapMultibyte(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "150000")
	dir := t.TempDir()
	so := strings.Repeat("é€😀", 20000)
	d := ocApply(ocIn("Bash", ocBashResp(so, ""), dir), "enforce")
	var m map[string]any
	if err := json.Unmarshal(d.UpdatedToolOutput, &m); err != nil {
		t.Fatal(err)
	}
	got := m["stdout"].(string)
	if !utf8.ValidString(got) || strings.ContainsRune(got, utf8.RuneError) || len(got) > 8300 {
		t.Fatalf("invalid or too long: %d", len(got))
	}
}

func TestOutputCapMCP(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	dir := t.TempDir()
	blocks := []map[string]any{
		{"type": "image", "data": "zzz", "mimeType": "image/png"},
		{"type": "text", "text": strings.Repeat("a", 6000), "annotations": 1},
		{"type": "text", "text": strings.Repeat("b", 6000)},
	}
	d := ocApply(ocIn("mcp__srv__tool", blocks, dir), "enforce")
	if d == nil || d.UpdatedToolOutput == nil {
		t.Fatalf("got %+v", d)
	}
	var out []map[string]any
	if err := json.Unmarshal(d.UpdatedToolOutput, &out); err != nil || len(out) != 2 {
		t.Fatalf("%v %s", err, d.UpdatedToolOutput)
	}
	if out[0]["type"] != "image" || out[0]["data"] != "zzz" || out[1]["type"] != "text" {
		t.Fatalf("blocks %v", out)
	}
	txt := out[1]["text"].(string)
	if !strings.Contains(txt, " chars omitted; full output: ") || len(txt) > 8000 {
		t.Fatalf("text %d: %q", len(txt), txt[2390:2500])
	}
	b, _ := os.ReadFile(filepath.Join(dir, "policy-spill", "toolu_01.txt"))
	if string(b) != strings.Repeat("a", 6000)+"\n"+strings.Repeat("b", 6000) {
		t.Fatal("spill wrong")
	}
	// under cap, non-array
	if d := ocApply(ocIn("mcp__srv__tool", []map[string]any{{"type": "text", "text": "hi"}}, dir), "enforce"); d != nil {
		t.Fatal("under cap")
	}
	if d := ocApply(ocIn("mcp__srv__tool", map[string]any{"text": strings.Repeat("a", 20000)}, dir), "enforce"); d != nil {
		t.Fatal("non-array")
	}
}

func TestOutputCapExemptAndOtherTools(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	dir := t.TempDir()
	big := []map[string]any{{"type": "text", "text": strings.Repeat("a", 20000)}}
	if d := ocApply(ocIn("mcp__browser-b__take_screenshot", big, dir), "enforce"); d != nil {
		t.Fatal("exempt")
	}
	if d := ocApply(ocIn("Grep", ocBashResp(strings.Repeat("a", 20000), ""), dir), "enforce"); d != nil {
		t.Fatal("other tool")
	}
}

func TestOutputCapReadLogOnly(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	resp := map[string]any{"type": "text", "file": map[string]any{"content": strings.Repeat("a", 9000)}}
	d := ocApply(ocIn("Read", resp, t.TempDir()), "enforce")
	if d == nil || d.UpdatedToolOutput != nil || d.Reason != "read log-only: 9000 chars" {
		t.Fatalf("got %+v", d)
	}
	c := ocCfg("enforce")
	c.Rules.OutputCap.Read = "off"
	if d := (outputCap{}).Apply(context.Background(), ocIn("Read", resp, ""), c, nil); d != nil {
		t.Fatal("read off")
	}
}

func TestOutputCapLogModeWritesNothing(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	dir := t.TempDir()
	d := ocApply(ocIn("Bash", ocBashResp(strings.Repeat("a", 20000), ""), dir), "log")
	if d == nil || d.UpdatedToolOutput != nil || !strings.Contains(d.Reason, "log mode") {
		t.Fatalf("got %+v", d)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("wrote %v", ents)
	}
}

func TestOutputCapSpillFailsOpen(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	big := ocBashResp(strings.Repeat("a", 20000), "")
	for _, sp := range []string{"", "relative/dir"} {
		if d := ocApply(ocIn("Bash", big, sp), "enforce"); d != nil {
			t.Fatalf("scratch %q: %+v", sp, d)
		}
	}
	dir := t.TempDir()
	in := ocIn("Bash", big, dir)
	in.ToolUseID = ""
	if d := ocApply(in, "enforce"); d != nil {
		t.Fatal("empty tool_use_id")
	}
	in.ToolUseID = "../x"
	if d := ocApply(in, "enforce"); d != nil {
		t.Fatal("unsafe tool_use_id")
	}
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0o600)
	if d := ocApply(ocIn("Bash", big, file), "enforce"); d != nil {
		t.Fatalf("unwritable: %+v", d)
	}
}

// A Bash result that reached CC's read-back window was cut by CC, which then
// spills the full output itself and ignores updatedToolOutput: no opinion.
func TestOutputCapBashAtCeiling(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	dir := t.TempDir()
	for _, c := range []struct {
		env  string
		n    int
		want bool
	}{
		{"12000", 12000, false}, {"12000", 11999, true}, {"", 30000, false}, {"", 29999, true}, {"junk", 30000, false},
	} {
		t.Setenv("BASH_MAX_OUTPUT_LENGTH", c.env)
		d := ocApply(ocIn("Bash", ocBashResp(strings.Repeat("é", c.n-10), strings.Repeat("e", 10)), dir), "enforce")
		if got := d != nil && d.UpdatedToolOutput != nil; got != c.want {
			t.Errorf("env %q n %d: rewrite %v, want %v", c.env, c.n, got, c.want)
		}
	}
}

func ocUnitsT(s string) int { return len(utf16.Encode([]rune(s))) }

// Review fixes: budget, 10k bound, symlink, UTF-16 ceiling, MCP
// block fields, HTML escaping.
func TestOutputCapReviewFixes(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "")
	dir := t.TempDir()
	out := func(d *hook.Decision) map[string]string {
		t.Helper()
		if d == nil || d.UpdatedToolOutput == nil {
			t.Fatalf("want rewrite, got %+v", d)
		}
		var m map[string]string
		var raw map[string]json.RawMessage
		json.Unmarshal(d.UpdatedToolOutput, &raw)
		m = map[string]string{}
		for _, k := range []string{"stdout", "stderr"} {
			var s string
			json.Unmarshal(raw[k], &s)
			m[k] = s
		}
		return m
	}

	// stderr takes what stdout leaves
	m := out(ocApply(ocIn("Bash", ocBashResp("", strings.Repeat("e", 20000)), dir), "enforce"))
	if n := len(m["stderr"]); n < 7000 || n > 8000 {
		t.Errorf("stderr only: %d chars", n)
	}

	// pointer counted inside the budget, even with a long scratchpad path
	long := filepath.Join(dir, strings.Repeat("d", 200), strings.Repeat("d", 200), strings.Repeat("d", 200), strings.Repeat("d", 200), strings.Repeat("d", 200))
	os.MkdirAll(long, 0o700) // CC creates scratchpad_dir
	m = out(ocApply(ocIn("Bash", ocBashResp(strings.Repeat("o", 20000), strings.Repeat("e", 9000)), long), "enforce"))
	if n := ocUnitsT(m["stdout"]) + ocUnitsT(m["stderr"]); n > 8000 {
		t.Errorf("long path: %d units", n)
	}
	m = out(ocApply(ocIn("Bash", ocBashResp(strings.Repeat("a", 8001), ""), dir), "enforce"))
	if n := len(m["stdout"]); n > 8000 {
		t.Errorf("8001 grew to %d", n)
	}

	// no HTML escaping inflation
	d := ocApply(ocIn("Bash", ocBashResp(strings.Repeat("<a&b>", 5000), ""), dir), "enforce")
	if d == nil || strings.Contains(string(d.UpdatedToolOutput), "\\u003c") {
		t.Errorf("html escaped: %v", d)
	}

	// ceiling counted in UTF-16 units: 200 emoji + 29600 a = 30000 units
	if d := ocApply(ocIn("Bash", ocBashResp(strings.Repeat("😀", 200)+strings.Repeat("a", 29600), ""), dir), "enforce"); d != nil {
		t.Errorf("astral text at ceiling rewritten: %s", d.Reason)
	}

	// MCP keeps the first text block's extra fields
	blocks := []map[string]any{{"type": "text", "text": strings.Repeat("a", 9000), "annotations": map[string]any{"audience": []string{"user"}}}}
	d = ocApply(ocIn("mcp__srv__tool", blocks, dir), "enforce")
	var mb []map[string]any
	if d == nil || json.Unmarshal(d.UpdatedToolOutput, &mb) != nil || mb[0]["annotations"] == nil {
		t.Errorf("annotations lost: %v", d)
	}

	// policy-spill symlinked out of scratchpad_dir: no write outside, no opinion
	sp, other := t.TempDir(), t.TempDir()
	os.Symlink(other, filepath.Join(sp, "policy-spill"))
	if d := ocApply(ocIn("Bash", ocBashResp(strings.Repeat("a", 20000), ""), sp), "enforce"); d != nil {
		t.Errorf("symlinked spill dir: %+v", d)
	}
	if ents, _ := os.ReadDir(other); len(ents) != 0 {
		t.Errorf("wrote outside scratchpad: %v", ents)
	}
}

// Two pointers with a long scratchpad path must still fit a small bash_chars.
func TestOutputCapTwoPointersFitSmallBudget(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "")
	sp := filepath.Join(t.TempDir(), strings.Repeat("p", 150), strings.Repeat("q", 100))
	os.MkdirAll(sp, 0o700)
	cfg := ocCfg("enforce")
	cfg.Rules.OutputCap.BashChars = 1000
	in := ocIn("Bash", ocBashResp(strings.Repeat("o", 5000), strings.Repeat("e", 5000)), sp)
	in.ToolUseID = "toolu_01ABCDEFGHIJKLMNOPQRSTUVWX"
	d := outputCap{}.Apply(context.Background(), in, cfg, nil)
	if d == nil {
		t.Fatal("no rewrite")
	}
	var m map[string]any
	json.Unmarshal(d.UpdatedToolOutput, &m)
	so, se := m["stdout"].(string), m["stderr"].(string)
	if n := ocUnitsT(so) + ocUnitsT(se); n > 1000 || !strings.Contains(so, "full output: ") || !strings.Contains(se, "full output: ") {
		t.Fatalf("%d units; stdout %q; stderr %q", n, so[:40], se[:40])
	}
}

// output_cap decisions carry chars_in/chars_out in both modes.
func TestOutputCapChars(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "") // fixtures must not depend on the caller's shell
	resp := ocBashResp(strings.Repeat("a", 20000), strings.Repeat("e", 1000))
	if d := ocApply(ocIn("Bash", resp, t.TempDir()), "log"); d == nil || d.CharsIn != 21000 || d.CharsOut != 8000 {
		t.Fatalf("log: %v", d != nil && d.CharsIn == 21000)
	}
	d := ocApply(ocIn("Bash", resp, t.TempDir()), "enforce")
	var m struct{ Stdout, Stderr string }
	if d == nil || json.Unmarshal(d.UpdatedToolOutput, &m) != nil {
		t.Fatalf("enforce: nil or bad output (reason %q)", d.Reason)
	}
	if d.CharsIn != 21000 || d.CharsOut != len(m.Stdout)+len(m.Stderr) || d.CharsOut > 8000 {
		t.Fatalf("enforce: in=%d out=%d, delivered %d", d.CharsIn, d.CharsOut, len(m.Stdout)+len(m.Stderr))
	}
	mcp := []map[string]any{{"type": "text", "text": strings.Repeat("m", 30000)}}
	if d := ocApply(ocIn("mcp__x__y", mcp, t.TempDir()), "log"); d == nil || d.CharsIn != 30000 || d.CharsOut == 0 {
		t.Fatalf("mcp: %v", d)
	}
	read := map[string]any{"type": "text", "file": map[string]any{"content": strings.Repeat("a", 9000)}}
	if d := ocApply(ocIn("Read", read, t.TempDir()), "enforce"); d == nil || d.CharsIn != 9000 || d.CharsOut != 9000 {
		t.Fatalf("read: %+v", d)
	}
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), `"chars_in":21000`) || !strings.Contains(string(b), `"chars_out":`) {
		t.Fatalf("not logged: %s", b)
	}
}

// Some MCP servers hand the hook a JSON
// string, not content blocks.
func TestOutputCapMCPString(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "")
	dir := t.TempDir()
	big := strings.Repeat("j", 20000)
	d := ocApply(ocIn("mcp__srv__search", big, dir), "enforce")
	if d == nil || d.UpdatedToolOutput == nil {
		t.Fatalf("got %+v", d)
	}
	var out string
	if err := json.Unmarshal(d.UpdatedToolOutput, &out); err != nil {
		t.Fatalf("%v %s", err, d.UpdatedToolOutput[:80])
	}
	if !strings.Contains(out, " chars omitted; full output: ") || len(out) > 8000 {
		t.Fatalf("text %d", len(out))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "policy-spill", "toolu_01.txt")); string(b) != big {
		t.Fatal("spill wrong")
	}
	if d := ocApply(ocIn("mcp__srv__x", "short", dir), "enforce"); d != nil {
		t.Fatal("under cap")
	}
}

func ocReadResp(path, content string, start int) map[string]any {
	return map[string]any{"type": "text", "file": map[string]any{"filePath": path, "content": content,
		"numLines": strings.Count(content, "\n") + 1, "startLine": start, "totalLines": 9999}}
}

// Read is capped only on read_paths (spill and scratchpad files), head only
// and on whole lines so CC's line numbers stay true.
func TestOutputCapReadPaths(t *testing.T) {
	t.Setenv("BASH_MAX_OUTPUT_LENGTH", "")
	home, _ := os.UserHomeDir()
	spill := filepath.Join(home, ".claude/projects/-p/s1/tool-results/b1.txt")
	var lines []string
	for i := range 2000 {
		lines = append(lines, fmt.Sprintf("line %04d xxxxxxxx", i+1))
	}
	content := strings.Join(lines, "\n")
	c := ocCfg("enforce")
	c.Rules.OutputCap.Read = "enforce"
	apply := func(path string, start int) *hook.Decision {
		return (outputCap{}).Apply(context.Background(), ocIn("Read", ocReadResp(path, content, start), t.TempDir()), c, nil)
	}
	d := apply(spill, 1)
	if d == nil || d.UpdatedToolOutput == nil {
		t.Fatalf("got %+v", d)
	}
	var out struct {
		Type string `json:"type"`
		File struct {
			FilePath   string `json:"filePath"`
			Content    string `json:"content"`
			NumLines   int    `json:"numLines"`
			StartLine  int    `json:"startLine"`
			TotalLines int    `json:"totalLines"`
		} `json:"file"`
	}
	if err := json.Unmarshal(d.UpdatedToolOutput, &out); err != nil {
		t.Fatal(err)
	}
	f := out.File
	if out.Type != "text" || f.FilePath != spill || f.StartLine != 1 || f.TotalLines != 9999 || len(f.Content) > 8000 {
		t.Fatalf("shape %+v len %d", f, len(f.Content))
	}
	got := strings.Split(f.Content, "\n")
	last := got[len(got)-1]
	if f.NumLines != len(got) || !strings.Contains(last, " chars omitted") || !strings.Contains(last, spill) {
		t.Fatalf("numLines %d of %d, last %q", f.NumLines, len(got), last)
	}
	for i, l := range got[:len(got)-1] { // whole lines, in order
		if l != lines[i] {
			t.Fatalf("line %d = %q", i+1, l)
		}
	}
	if !strings.Contains(last, fmt.Sprintf("lines 1-%d of 9999 shown", len(got)-1)) {
		t.Fatalf("pointer %q", last)
	}
	// ranged read keeps the file's numbering in the pointer
	if d := apply(spill, 501); d == nil || !strings.Contains(string(d.UpdatedToolOutput), "lines 501-") {
		t.Fatalf("ranged %+v", d)
	}
	for _, p := range []string{"/tmp/claude-1000/-p/s1/scratchpad/full.diff"} {
		if d := apply(p, 1); d == nil || d.UpdatedToolOutput == nil {
			t.Fatalf("%s not capped", p)
		}
	}
	// project file: log-only
	if d := apply(filepath.Join(home, "projects/x/main.go"), 1); d == nil || d.UpdatedToolOutput != nil || !strings.HasPrefix(d.Reason, "read log-only") {
		t.Fatalf("project file %+v", d)
	}
	// read = log, or rule in log mode: log-only
	c.Rules.OutputCap.Read = "log"
	if d := apply(spill, 1); d == nil || d.UpdatedToolOutput != nil {
		t.Fatalf("read=log %+v", d)
	}
	c.Rules.OutputCap.Read = "enforce"
	c.Rules.OutputCap.Mode = "log"
	if d := apply(spill, 1); d == nil || d.UpdatedToolOutput != nil {
		t.Fatalf("mode=log %+v", d)
	}
}
