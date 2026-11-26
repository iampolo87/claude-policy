package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/iampolo87/claude-policy/internal/config"
	"github.com/iampolo87/claude-policy/internal/hook"
	"github.com/iampolo87/claude-policy/internal/state"
)

// outputCap replaces an oversized Bash or MCP tool result with head + pointer
// + tail and spills the full text under scratchpad_dir (PostToolUse
// updatedToolOutput). Read is capped on read_paths, otherwise only logged.
// Every failure is no opinion.
// ponytail: lengths are bytes, cuts are rune-aligned; bytes >= CC's UTF-16
// char count, so the cap is never exceeded (multibyte text is capped early).
type outputCap struct{}

func init() { Registry = append(Registry, outputCap{}) }

func (outputCap) Name() string     { return "output_cap" }
func (outputCap) Events() []string { return []string{"PostToolUse"} } // no Tools(): MCP names vary

// Timeout: decoding a 15 MB MCP result alone took ~220 ms.
func (outputCap) Timeout() time.Duration { return time.Second }

// ocUnits is len(s) in UTF-16 code units, the unit CC counts chars in.
func ocUnits(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// ocHead / ocTail cut s to n bytes on a rune boundary.
func ocHead(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func ocTail(s string, n int) string {
	if n >= len(s) {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

// ocCap keeps head 30 % + pointer line + tail 70 % within budget bytes (the
// pointer counts against the budget).
func ocCap(s string, budget int, path string) string {
	if len(s) <= budget {
		return s
	}
	b := max(budget-len(ocPtr(len(s), path)), 0)
	h := ocHead(s, b*30/100)
	t := ocTail(s, b-b*30/100)
	return h + ocPtr(ocUnits(s[len(h):len(s)-len(t)]), path) + t
}

func ocPtr(n int, path string) string {
	return fmt.Sprintf("\n… %d chars omitted; full output: %s (grep/sed -n it)\n", n, path)
}

// ocJSON marshals without HTML escaping (\u003c would triple "<").
func ocJSON(v any) json.RawMessage {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// ocSpill writes full to <scratchpad>/policy-spill/<tool_use_id>.txt through
// os.Root, so a symlink cannot carry the write out of scratchpad_dir.
func ocSpill(in *hook.Input, full string) (string, bool) {
	name := state.SafeName(in.ToolUseID, "")
	if name == "" || !filepath.IsAbs(in.ScratchpadDir) {
		return "", false
	}
	root, err := os.OpenRoot(in.ScratchpadDir)
	if err != nil {
		return "", false
	}
	defer root.Close()
	rel := filepath.Join("policy-spill", name+".txt")
	tmp := fmt.Sprintf("%s.%d.tmp", rel, os.Getpid())
	if root.MkdirAll("policy-spill", 0o700) != nil || root.WriteFile(tmp, []byte(full), 0o600) != nil {
		root.Remove(tmp)
		return "", false
	}
	if root.Rename(tmp, rel) != nil {
		root.Remove(tmp)
		return "", false
	}
	return filepath.Join(filepath.Clean(in.ScratchpadDir), rel), true
}

func (outputCap) Apply(ctx context.Context, in *hook.Input, cfg *config.Config, st *state.Store) *hook.Decision {
	oc := cfg.Rules.OutputCap
	if ctx.Err() != nil || slices.Contains(oc.Exempt, in.ToolName) {
		return nil
	}
	switch {
	case in.ToolName == "Bash":
		return ocBash(ctx, in, cfg)
	case strings.HasPrefix(in.ToolName, "mcp__"):
		return ocMCP(ctx, in, cfg)
	case in.ToolName == "Read":
		return ocRead(in, cfg)
	}
	return nil
}

// ocRead keeps the head of a Read result on read_paths, cut on a line end:
// CC numbers the lines it renders from startLine, so a kept tail would carry
// wrong numbers. The pointer names the file itself; nothing is spilled.
func ocRead(in *hook.Input, cfg *config.Config) *hook.Decision {
	oc := cfg.Rules.OutputCap
	var m map[string]json.RawMessage
	var f map[string]json.RawMessage
	var typ, path, content string
	var start int
	if oc.Read == "off" || json.Unmarshal(in.ToolResponse, &m) != nil || json.Unmarshal(m["type"], &typ) != nil || typ != "text" ||
		json.Unmarshal(m["file"], &f) != nil || json.Unmarshal(f["content"], &content) != nil || len(content) <= oc.BashChars {
		return nil
	}
	n := len(content)
	json.Unmarshal(f["filePath"], &path)
	if json.Unmarshal(f["startLine"], &start) != nil || start < 1 {
		start = 1
	}
	if oc.Read != "enforce" || cfg.Mode("output_cap") != "enforce" || !ocReadPath(oc.ReadPaths, path) {
		return &hook.Decision{Reason: fmt.Sprintf("read log-only: %d chars", n), CharsIn: n, CharsOut: n}
	}
	last := start + strings.Count(content, "\n")
	var fileLines int
	if json.Unmarshal(f["totalLines"], &fileLines) == nil && fileLines > last {
		last = fileLines // a ranged Read: name the file's last line
	}
	ptr := func(omitted, end int) string {
		return fmt.Sprintf("… %d chars omitted (lines %d-%d of %d shown); full file: %s (grep/sed -n it, or Read with offset)",
			omitted, start, end, last, path)
	}
	// both numbers at their maximum bound the pointer's length
	head := ocHead(content, max(oc.BashChars-len(ptr(ocUnits(content), last))-1, 0))
	if i := strings.LastIndexByte(head, '\n'); i >= 0 {
		head = head[:i]
	}
	capped := head + "\n" + ptr(ocUnits(content[len(head):]), start+strings.Count(head, "\n"))
	f["content"] = ocJSON(capped)
	f["numLines"] = ocJSON(strings.Count(capped, "\n") + 1)
	m["file"] = ocJSON(f)
	out := ocJSON(m)
	if f["content"] == nil || out == nil {
		return nil
	}
	return &hook.Decision{UpdatedToolOutput: out, Reason: fmt.Sprintf("Read %d → %d chars; head of %s", n, len(capped), path), CharsIn: n, CharsOut: len(capped)}
}

func ocReadPath(globs []string, p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	p = filepath.Clean(p)
	home, _ := os.UserHomeDir()
	for _, g := range globs {
		if strings.HasPrefix(g, "~/") {
			if home == "" {
				continue
			}
			g = home + g[1:]
		}
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
	}
	return false
}

// ocFinish spills full (enforce) and returns the decision built by mk(path),
// which also returns the text chars it delivers.
func ocFinish(ctx context.Context, in *hook.Input, cfg *config.Config, label string, total, limit int, full string, mk func(path string) (json.RawMessage, int)) *hook.Decision {
	if cfg.Mode("output_cap") != "enforce" {
		return &hook.Decision{Reason: fmt.Sprintf("%s %d → %d chars; log mode, no spill", label, total, limit), CharsIn: total, CharsOut: limit}
	}
	if ctx.Err() != nil {
		return nil
	}
	path, ok := ocSpill(in, full)
	if !ok {
		return nil
	}
	out, n := mk(path)
	if out == nil {
		return nil
	}
	return &hook.Decision{UpdatedToolOutput: out, Reason: fmt.Sprintf("%s %d → %d chars; spill %s", label, total, limit, path), CharsIn: total, CharsOut: n}
}

func ocText(b map[string]json.RawMessage) (string, bool) {
	var typ, txt string
	ok := json.Unmarshal(b["type"], &typ) == nil && typ == "text" && json.Unmarshal(b["text"], &txt) == nil
	return txt, ok
}

// ocBashCeiling is CC's Bash read-back window. A result that reached it was
// cut by CC, which spills the full output itself and ignores
// updatedToolOutput (observed live). ponytail: the bashOutputMaxChars
// setting, which overrides the env var, is not read.
func ocBashCeiling() int {
	if n, err := strconv.Atoi(os.Getenv("BASH_MAX_OUTPUT_LENGTH")); err == nil && n > 0 {
		return n
	}
	return 30000
}

func ocBash(ctx context.Context, in *hook.Input, cfg *config.Config) *hook.Decision {
	limit := cfg.Rules.OutputCap.BashChars
	var m map[string]json.RawMessage
	if json.Unmarshal(in.ToolResponse, &m) != nil {
		return nil
	}
	var img bool
	var so, se string
	if json.Unmarshal(m["isImage"], &img) == nil && img {
		return nil
	}
	if json.Unmarshal(m["stdout"], &so) != nil {
		return nil
	}
	json.Unmarshal(m["stderr"], &se) // absent or null: empty
	if limit <= 0 || len(so)+len(se) <= limit ||
		ocUnits(so)+ocUnits(se) >= ocBashCeiling() {
		return nil
	}
	full := so
	if se != "" {
		full += "\n--- stderr ---\n" + se
	}
	seBudget := min(len(se), max(limit/4, limit-len(so))) // stderr takes what stdout leaves
	return ocFinish(ctx, in, cfg, "Bash", len(so)+len(se), limit, full, func(path string) (json.RawMessage, int) {
		seB := seBudget
		if len(se) > seB { // room for stderr's pointer, leaving stdout room for its own.
			// ponytail: the bound holds while two pointers fit in bash_chars (path < ~bash_chars/2).
			p := len(ocPtr(len(se), path))
			seB = min(len(se), max(seB, p+max(limit-2*p, 0)/4))
		}
		cso, cse := ocCap(so, limit-seB, path), ""
		m["stdout"] = ocJSON(cso)
		if se != "" {
			cse = ocCap(se, seB, path)
			m["stderr"] = ocJSON(cse)
		}
		return ocJSON(m), len(cso) + len(cse)
	})
}

// ponytail: text inside resource blocks is neither counted nor capped.
func ocMCP(ctx context.Context, in *hook.Input, cfg *config.Config) *hook.Decision {
	limit := cfg.Rules.OutputCap.MCPChars
	var str string
	if json.Unmarshal(in.ToolResponse, &str) == nil { // some servers hand the hook a plain string
		if limit <= 0 || len(str) <= limit {
			return nil
		}
		return ocFinish(ctx, in, cfg, "MCP", len(str), limit, str, func(path string) (json.RawMessage, int) {
			capped := ocCap(str, limit, path)
			return ocJSON(capped), len(capped)
		})
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(in.ToolResponse, &blocks) != nil || limit <= 0 {
		return nil
	}
	var texts []string
	first := -1
	total := 0
	for i, b := range blocks {
		txt, ok := ocText(b)
		if !ok {
			continue
		}
		if first < 0 {
			first = i
		}
		texts = append(texts, txt)
		total += len(txt)
	}
	if total <= limit {
		return nil
	}
	full := strings.Join(texts, "\n")
	return ocFinish(ctx, in, cfg, "MCP", total, limit, full, func(path string) (json.RawMessage, int) {
		capped := ocCap(full, limit, path)
		out := make([]map[string]json.RawMessage, 0, len(blocks))
		for i, b := range blocks {
			_, isText := ocText(b)
			switch {
			case i == first: // keeps the block's other fields (annotations, _meta)
				nb := maps.Clone(b)
				nb["text"] = ocJSON(capped)
				out = append(out, nb)
			case !isText:
				out = append(out, b)
			}
		}
		return ocJSON(out), len(capped)
	})
}
