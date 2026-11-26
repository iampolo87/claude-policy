// Ported from the tokenizer layer of gentle-shell
// lib/destructive-command-guard.ts
// (https://github.com/Gentleman-Programming/gentle-shell, commit
// 51b766de731a69b1e6af7f269375107b9fd29736). The destructive recognizer is
// not ported here. JS regular expressions with backreferences and lookahead
// are hand-written matchers with the same backtracking result; \s keeps its
// JS (Unicode) meaning.
//
// MIT License
//
// Copyright (c) 2025 Mario Zechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package shell is the lexical layer of the Bash guards: it splits a command
// into separator-delimited segments, finds each segment's executable after
// reserved words, assignments and familiar wrappers, blanks the heredoc
// bodies and comments bash reads, and locates `$(...)` and backtick
// substitutions.
// Opaque reports commands whose executed text Segments cannot expose.
// Recognizable
// executable forms only; deliberately not a shell interpreter: no expansion,
// script loading or remote inspection. Offsets are byte offsets.
package shell

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Token is a shell word, an unquoted separator or an unquoted redirection
// operator. A backslash-newline is a line continuation: inside a word Raw
// keeps it and Value drops it; between words it is skipped.
type Token struct {
	Value    string // quotes and escapes removed, $'...' decoded; the operator itself for separators and redirections
	Raw      string // exact source text
	Operator bool   // an unquoted separator; quoted or escaped operators are words
	Redirect bool   // an unquoted redirection operator (`>`, `2>>`, `&>`, `<<<`, `<<-` ...); the next word is its target
	Index    int    // byte offset of Raw in the input
}

// Bare is Raw without backslash-newline continuations, which bash removes
// before it reads a word: a reserved word split across lines is still that
// word, and a quoted or escaped one still is not.
func (t Token) Bare() string { return strings.ReplaceAll(t.Raw, "\\\n", "") }

// wrappers run their command argument (all stop parsing options at the first
// non-option word). wrapperValueOptions are their options that take a value:
// the next word, attached to a short option (`-n5`, also last in a cluster
// `-nu root`) or after `=` on a long one. wrapperFlags take none; a long flag
// may carry `=value` (optional arguments). Any other option leaves the head
// unresolved, and so do the deliberately absent env -S/--split-string (the
// value is itself a command line) and sudo -e/--edit (sudoedit: files, not a
// command). Long options must be spelled out; GNU abbreviations are
// unresolved. `timeout` also consumes a duration, `flock` its lock file
// (`flock FILE -c CMD` leaves `-c` as the head) and `taskset` its mask;
// `nice -N` is a legacy adjustment.
var wrappers = map[string]bool{
	"env": true, "sudo": true, "doas": true, "command": true, "exec": true, "nohup": true, "timeout": true,
	"xargs": true, "nice": true, "time": true, "stdbuf": true, "setsid": true, "ionice": true,
	"builtin": true, "busybox": true, "flock": true, "taskset": true,
}

// positionals are the words a wrapper consumes after its options.
var positionals = map[string]int{"timeout": 1, "flock": 1, "taskset": 1}

var wrapperValueOptions = map[string][]string{
	"env": {"-u", "-C", "--unset", "--chdir"},
	"sudo": {"-a", "-C", "-c", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-U", "-u",
		"--close-from", "--login-class", "--chdir", "--group", "--host", "--prompt", "--chroot", "--role",
		"--command-timeout", "--type", "--other-user", "--user"},
	"doas":    {"-a", "-C", "-u"},
	"exec":    {"-a"},
	"timeout": {"-s", "-k", "--signal", "--kill-after"},
	"xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s",
		"--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"},
	"nice":   {"-n", "--adjustment"},
	"time":   {"-f", "-o", "--format", "--output"},
	"stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
	"ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"},
	"flock":  {"-w", "-E", "--wait", "--timeout", "--conflict-exit-code"},
}

var wrapperFlags = map[string][]string{
	"env": {"-", "-0", "-i", "-v", "--null", "--ignore-environment", "--debug", "--block-signal", "--default-signal",
		"--ignore-signal", "--list-signal-handling", "--help", "--version"},
	"sudo": {"-A", "-B", "-b", "-E", "-H", "-i", "-K", "-k", "-l", "-N", "-n", "-P", "-S", "-s", "-V", "-v",
		"--askpass", "--bell", "--background", "--preserve-env", "--set-home", "--login", "--remove-timestamp",
		"--reset-timestamp", "--list", "--no-update", "--non-interactive", "--preserve-groups", "--stdin", "--shell",
		"--version", "--validate", "--help"},
	"doas":    {"-L", "-n", "-s"},
	"command": {"-p", "-v", "-V"},
	"exec":    {"-c", "-l"},
	"nohup":   {"--help", "--version"},
	"timeout": {"-v", "--verbose", "--foreground", "--preserve-status", "--help", "--version"},
	// ponytail: -e/-i/-l take an optional value only attached (`-i{}`); attached, it reads as an unknown cluster: unresolved.
	"xargs": {"-0", "-e", "-i", "-l", "-o", "-p", "-r", "-t", "-x", "--null", "--eof", "--replace", "--max-lines",
		"--open-tty", "--interactive", "--no-run-if-empty", "--show-limits", "--verbose", "--exit", "--help", "--version"},
	"nice":   {"--help", "--version"},
	"time":   {"-a", "-p", "-q", "-v", "-V", "--append", "--portability", "--quiet", "--verbose", "--version", "--help"},
	"stdbuf": {"--help", "--version"},
	"setsid": {"-c", "-f", "-w", "-h", "-V", "--ctty", "--fork", "--wait", "--help", "--version"},
	"ionice": {"-t", "-h", "-V", "--ignore", "--help", "--version"},
	"flock": {"-s", "-x", "-e", "-u", "-n", "-o", "-F", "-h", "-V", "--shared", "--exclusive", "--unlock", "--nonblock", "--nb",
		"--close", "--no-fork", "--verbose", "--help", "--version"},
	"taskset": {"-a", "-c", "-p", "-h", "-V", "--all-tasks", "--cpu-list", "--pid", "--help", "--version"},
}

// reservedWords open a compound body or a condition when unquoted; the next
// word is in command position (gentle-pi#2285).
var reservedWords = map[string]bool{"then": true, "else": true, "elif": true, "do": true, "{": true, "!": true, "if": true, "while": true, "until": true}

// DataCommands only search, print or view their arguments, never execute
// them (gentle-shell#2174). `sed` is absent on purpose: GNU sed executes
// scripts through `e`. A missing entry costs a dialog, never a bypass.
var DataCommands = map[string]bool{
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true, "echo": true, "printf": true,
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "wc": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "jq": true, "diff": true, "ls": true, "file": true, "stat": true,
}

// isSpace is JS \s: Unicode White_Space without U+0085, plus U+FEFF.
func isSpace(r rune) bool { return r == '\ufeff' || r != '\u0085' && unicode.IsSpace(r) }

// isLineTerminator is what JS `.` does not match.
func isLineTerminator(r rune) bool { return r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' }

// wordEnd is the end of the word starting at i: a run of "..." (with
// backslash escapes), '...', $'...' (with backslash escapes),
// backslash-escaped characters and characters other than whitespace,
// ;&|()<> and quotes; a backslash-newline continues the word. It returns i
// when no word starts there; an unterminated quote ends the word before it.
func wordEnd(s string, i int) int { return scanWord(s, i, ";&|()<>") }

// scanWord is wordEnd with stops as the unquoted word-ending characters.
func scanWord(s string, i int, stops string) int {
	for i < len(s) {
		switch s[i] {
		case '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] != '\\' {
					j++
					continue
				}
				if j+1 >= len(s) {
					return i
				}
				r, w := utf8.DecodeRuneInString(s[j+1:])
				if r != '\n' && isLineTerminator(r) {
					return i
				}
				j += 1 + w
			}
			if j >= len(s) {
				return i
			}
			i = j + 1
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return i
			}
			i += j + 2
		case '$':
			if i+1 < len(s) && s[i+1] == '$' { // `$$`, the PID: a quote after it is not $'...'
				i += 2
				continue
			}
			if i+1 >= len(s) || s[i+1] != '\'' {
				i++
				continue
			}
			j := i + 2
			for j < len(s) && s[j] != '\'' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return i
			}
			i = j + 1
		case '\\':
			if i+1 >= len(s) {
				return i
			}
			r, w := utf8.DecodeRuneInString(s[i+1:])
			if r != '\n' && isLineTerminator(r) {
				return i
			}
			i += 1 + w
		default:
			r, w := utf8.DecodeRuneInString(s[i:])
			if isSpace(r) || strings.IndexByte(stops, s[i]) >= 0 {
				return i
			}
			i += w
		}
	}
	return i
}

// unquote removes the quoting of a raw word produced by wordEnd: quotes and
// backslash-newlines go, $'...' is decoded and $"..." is a double-quoted
// string.
func unquote(raw string) string {
	if !strings.ContainsAny(raw, `"'\$`) {
		return raw
	}
	var b strings.Builder
	for i := 0; i < len(raw); {
		switch raw[i] {
		case '"':
			i++
			for raw[i] != '"' {
				if raw[i] == '\\' && strings.IndexByte("\"\\$`\n", raw[i+1]) >= 0 {
					if raw[i+1] != '\n' {
						b.WriteByte(raw[i+1])
					}
					i += 2
					continue
				}
				// A backslash before anything else stays, and so does that
				// character, which wordEnd guarantees is not a closing quote.
				b.WriteByte(raw[i])
				i++
			}
			i++
		case '\'':
			j := strings.IndexByte(raw[i+1:], '\'')
			b.WriteString(raw[i+1 : i+1+j])
			i += j + 2
		case '$':
			switch {
			case strings.HasPrefix(raw[i:], "$$"):
				b.WriteString("$$")
				i += 2
			case i+1 < len(raw) && raw[i+1] == '\'':
				i = ansiC(&b, raw, i+2)
			case i+1 < len(raw) && raw[i+1] == '"':
				i++
			default:
				b.WriteByte('$')
				i++
			}
		case '\\':
			_, w := utf8.DecodeRuneInString(raw[i+1:])
			if raw[i+1] != '\n' {
				b.WriteString(raw[i+1 : i+1+w])
			}
			i += 1 + w
		default:
			b.WriteByte(raw[i])
			i++
		}
	}
	return b.String()
}

// ansiC writes the decoded body of the $'...' string whose text starts at i
// and returns the offset after its closing quote. Decoded: \a \b \e \E \f
// \n \r \t \v \\ \' \" \? \cX (X no backslash or quote), octal \nnn, \xHH, \uHHHH and \UHHHHHHHH;
// another escape stays as written, invalid UTF-8 becomes U+FFFD.
func ansiC(b *strings.Builder, raw string, i int) int {
	var out []byte
	for raw[i] != '\'' {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			i++
			continue
		}
		c := raw[i+1]
		i += 2
		if k := strings.IndexByte(`abeEfnrtv\'"?`, c); k >= 0 {
			out = append(out, "\a\b\x1b\x1b\f\n\r\t\v\\'\"?"[k])
			continue
		}
		digits, base, n := "0123456789abcdefABCDEF", 16, 0
		switch {
		case c == 'c' && raw[i] != '\'' && raw[i] != '\\': // scanWord pairs a backslash with the next byte
			out = append(out, raw[i]&0x1f)
			i++
			continue
		case c == 'x':
			n = 2
		case c == 'u':
			n = 4
		case c == 'U':
			n = 8
		case '0' <= c && c <= '7':
			digits, base, n, i = "01234567", 8, 3, i-1
		}
		j := i
		for j < i+n && strings.IndexByte(digits, raw[j]) >= 0 {
			j++
		}
		if j == i {
			out = append(out, '\\', c)
			continue
		}
		v, _ := strconv.ParseUint(raw[i:j], base, 32)
		if c == 'u' || c == 'U' {
			out = utf8.AppendRune(out, rune(v))
		} else {
			out = append(out, byte(v))
		}
		i = j
	}
	b.WriteString(strings.ToValidUTF8(string(out), "\uFFFD"))
	return i + 1
}

// redirOps are the redirection operators, longest first.
var redirOps = []string{"<<<", "<<-", "<<", "<>", "<&", "<", ">>", ">|", ">&", ">", "&>>", "&>"}

// redirection is the length of the redirection operator at the start of s
// (an optional fd number or bash {NAME}/{NAME[SUB]}, then one of redirOps;
// &> takes none), or 0. A lone < or > before ( is process substitution: a word, not a
// redirection.
func redirection(s string) (n int, redirect bool) {
	k := 0
	for k < len(s) && '0' <= s[k] && s[k] <= '9' {
		k++
	}
	if j := fdNameEnd(s); j > 0 && j < len(s) {
		switch s[j] {
		case '}':
			k = j + 1
		case '[': // {NAME[SUB]}: bash evaluates SUB; one with an expansion stays a word (fdArrayWord)
			if end := wordEnd(s, 0); strings.HasSuffix(s[:end], "]}") && !strings.ContainsAny(s[:end], "$`") {
				k = end
			}
		}
	}
	for _, op := range redirOps {
		if strings.HasPrefix(s[k:], op) && (k == 0 || op[0] != '&') {
			if k == 0 && len(op) == 1 && strings.HasPrefix(s[1:], "(") {
				return 1, false
			}
			return k + len(op), true
		}
	}
	return 0, false
}

// fdNameEnd is the index after NAME when s starts with bash's `{NAME` of a
// named-fd redirection, else 0.
func fdNameEnd(s string) int {
	if !strings.HasPrefix(s, "{") || len(s) < 2 || '0' <= s[1] && s[1] <= '9' {
		return 0
	}
	j := 1
	for j < len(s) && (s[j] == '_' || 'a' <= s[j] && s[j] <= 'z' || 'A' <= s[j] && s[j] <= 'Z' || '0' <= s[j] && s[j] <= '9') {
		j++
	}
	if j == 1 {
		return 0
	}
	return j
}

// fdArrayWord is a `{NAME[` word redirection() did not take (`{a[1>0]}>x`,
// `{a[$i]}>x`): bash may still read a redirection, so no head is resolved.
func fdArrayWord(t Token) bool {
	j := fdNameEnd(t.Raw)
	return !t.Redirect && j > 0 && j < len(t.Raw) && t.Raw[j] == '['
}

// Tokenize splits command into words, unquoted separators and unquoted
// redirection operators, keeping quoted arguments intact so harmless prose
// is never treated as a command. With blank, heredoc bodies and comments are
// blanked first (offsets are preserved). Characters that start no token
// (whitespace, an unterminated quote, a backslash-newline between words, a
// backslash before another line terminator) are skipped.
func Tokenize(command string, blank bool) []Token {
	if blank {
		command = BlankHeredocs(command)
	}
	var tokens []Token
	for i := 0; i < len(command); {
		if strings.HasPrefix(command[i:], "\\\n") {
			i += 2
			continue
		}
		if n, redirect := redirection(command[i:]); n > 0 {
			raw := command[i : i+n]
			tokens = append(tokens, Token{Value: raw, Raw: raw, Redirect: redirect, Index: i})
			i += n
			continue
		}
		if end := wordEnd(command, i); end > i {
			raw := command[i:end]
			tokens = append(tokens, Token{Value: unquote(raw), Raw: raw, Index: i})
			i = end
			continue
		}
		op := ""
		switch {
		case strings.HasPrefix(command[i:], "&&"), strings.HasPrefix(command[i:], "||"):
			op = command[i : i+2]
		case strings.IndexByte(";&|()\n", command[i]) >= 0:
			op = command[i : i+1]
		}
		if op != "" {
			tokens = append(tokens, Token{Value: op, Raw: op, Operator: true, Index: i})
			i += len(op)
			continue
		}
		_, w := utf8.DecodeRuneInString(command[i:])
		i += w
	}
	return tokens
}

// Executable is the last path component of a command word.
func Executable(value string) string { return value[strings.LastIndexByte(value, '/')+1:] }

// isAssignment: NAME=, NAME+=, NAME[SUBSCRIPT]= or NAME[SUBSCRIPT]+=, the
// words bash takes as assignments before a command. ponytail: any text
// between [ and the last ]= counts as a subscript, so a[x]y]=v does too; the
// word after it is then read as the command, which errs strict.
func isAssignment(value string) bool {
	i := 0
	for ; i < len(value); i++ {
		if c := value[i]; c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9' || i == 0) {
			break
		}
	}
	rest := value[i:]
	if i == 0 {
		return false
	}
	for strings.HasPrefix(rest, "[") { // up to a ] that = or += follows
		k := strings.IndexByte(rest[1:], ']')
		if k < 0 {
			return false
		}
		if rest = rest[k+2:]; !strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "+=") {
			rest = "[" + rest
		}
	}
	return strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "+=")
}

// HeadCursor is the index of the executable token after unquoted reserved
// words, `function NAME`, `coproc [NAME]`, assignments, redirections with
// their targets and familiar wrappers with their options; len(segment) when
// there is none or it is unresolved (a wrapper option outside
// wrapperValueOptions and wrapperFlags).
func HeadCursor(segment []Token) int {
	cursor, prefix := 0, true // prefix: still before any assignment or wrapper
	for cursor < len(segment) {
		t := segment[cursor]
		value := t.Value
		if fdArrayWord(t) {
			return len(segment)
		}
		switch {
		case t.Redirect:
			cursor = skipRedirects(segment, cursor)
			continue
		case prefix && reservedWords[value] && t.Bare() == value:
			cursor++
			continue
		case prefix && t.Bare() == "function":
			cursor += 2
			continue
		case prefix && t.Bare() == "coproc":
			cursor++
			if cursor+1 < len(segment) && segment[cursor+1].Bare() == "{" {
				cursor++
			}
			continue
		case isAssignment(value):
			prefix = false
			cursor++
			continue
		}
		name := Executable(value)
		if !wrappers[name] {
			break
		}
		// bash's own `time` is a reserved word: `time { ...; }`, `time ! cmd`.
		prefix = prefix && t.Bare() == "time"
		// The shell removes redirections before the wrapper parses its
		// arguments: none is an option, a value or a positional.
		wrapper, info := cursor, false
		take := func() bool { // consume one wrapper argument
			if cursor < len(segment) && fdArrayWord(segment[cursor]) {
				return false
			}
			cursor = skipRedirects(segment, cursor+1)
			return true
		}
		cursor = skipRedirects(segment, cursor+1)
		for cursor < len(segment) && strings.HasPrefix(segment[cursor].Value, "-") {
			flag := segment[cursor].Value
			cursor = skipRedirects(segment, cursor+1)
			if flag == "--" {
				break
			}
			values, ok := optionValues(name, flag)
			if !ok {
				return len(segment)
			}
			info = info || infoFlag(name, flag)
			for range values {
				if !take() {
					return len(segment)
				}
			}
		}
		// `flock --version`: options that end the segment with an info flag
		// only print, so the wrapper itself is the head.
		if info && cursor >= len(segment) {
			return wrapper
		}
		for range positionals[name] {
			if !take() {
				return len(segment)
			}
		}
		// GNU env takes every leading word with `=` as an assignment, not
		// only identifier ones (`env 'X%=1' rm`).
		for name == "env" && cursor < len(segment) {
			if segment[cursor].Redirect {
				cursor = skipRedirects(segment, cursor)
			} else if strings.Contains(segment[cursor].Value, "=") {
				cursor++
			} else {
				break
			}
		}
	}
	return min(cursor, len(segment))
}

// skipRedirects moves cursor past redirections and their targets.
func skipRedirects(segment []Token, cursor int) int {
	for cursor < len(segment) && segment[cursor].Redirect {
		cursor++
		if cursor < len(segment) && !segment[cursor].Redirect {
			cursor++
		}
	}
	return cursor
}

// infoFlag reports a wrapper option that prints help or version and exits.
func infoFlag(name, flag string) bool {
	return flag == "--help" || flag == "--version" || (name == "flock" || name == "taskset") && (flag == "-h" || flag == "-V")
}

// optionValues is how many following words the wrapper option consumes; ok
// is false for an option the wrapper is not known to accept.
func optionValues(name, flag string) (values int, ok bool) {
	known, flags := wrapperValueOptions[name], wrapperFlags[name]
	if name == "nice" { // -N, --N, -+N
		t := flag[1:]
		if t != "" && (t[0] == '-' || t[0] == '+') {
			t = t[1:]
		}
		if t != "" && '0' <= t[0] && t[0] <= '9' {
			return 0, true
		}
	}
	if strings.HasPrefix(flag, "--") {
		opt, _, attached := strings.Cut(flag, "=")
		switch {
		case slices.Contains(known, opt) && !attached:
			return 1, true
		case slices.Contains(known, opt), slices.Contains(flags, opt):
			return 0, true
		}
		return 0, false
	}
	if flag == "-" {
		return 0, slices.Contains(flags, flag)
	}
	for k := 1; k < len(flag); k++ {
		opt := "-" + flag[k:k+1]
		switch {
		case slices.Contains(known, opt) && k+1 == len(flag):
			return 1, true
		case slices.Contains(known, opt):
			return 0, true
		case !slices.Contains(flags, opt):
			return 0, false
		}
	}
	return 0, true
}

// Segment is the run of tokens between two unquoted separators.
type Segment struct {
	Tokens    []Token // words only; the separator is excluded
	Cursor    int     // HeadCursor(Tokens)
	Separator string  // operator ending the segment; "" at the end of the command
	// Start and End delimit the segment in the input, surrounding whitespace
	// included: segments and their separators tile the whole input. End is
	// the separator's offset (len(command) for the last segment).
	Start, End int
	Raw        string // command[Start:End], heredoc bodies NOT blanked
}

// Head is the segment's executable token, if any.
func (s Segment) Head() (Token, bool) {
	if s.Cursor < len(s.Tokens) {
		return s.Tokens[s.Cursor], true
	}
	return Token{}, false
}

// Name is Executable(head value), "" without a head.
func (s Segment) Name() string {
	head, ok := s.Head()
	if !ok {
		return ""
	}
	return Executable(head.Value)
}

// ArgTokens are the tokens after the head, redirection operators and their
// targets excluded.
func (s Segment) ArgTokens() []Token {
	var args []Token
	for i := s.Cursor + 1; i < len(s.Tokens); i++ {
		if s.Tokens[i].Redirect {
			i++
			continue
		}
		args = append(args, s.Tokens[i])
	}
	return args
}

// Args are the values of ArgTokens.
func (s Segment) Args() []string {
	var args []string
	for _, t := range s.ArgTokens() {
		args = append(args, t.Value)
	}
	return args
}

// Segments tokenizes command with heredoc bodies and comments blanked and
// splits it at every separator. Empty segments are kept, so there is always
// one more segment than separators.
func Segments(command string) []Segment {
	tokens := Tokenize(command, true)
	var segments []Segment
	start, from := 0, 0
	for end := 0; end <= len(tokens); end++ {
		if end < len(tokens) && !tokens[end].Operator {
			continue
		}
		s := Segment{Tokens: tokens[start:end:end], Start: from, End: len(command)}
		if end < len(tokens) {
			s.Separator = tokens[end].Raw
			s.End = tokens[end].Index
			from = s.End + len(s.Separator)
		}
		s.Cursor = HeadCursor(s.Tokens)
		s.Raw = command[s.Start:s.End]
		segments = append(segments, s)
		start = end + 1
	}
	return segments
}

// Heredoc is a terminated here-document as bash reads it (see hereDocs):
// Index is the offset of its `<<` and the body is [BodyStart, BodyEnd).
// Expands: the delimiter is unquoted, so bash expands the body and removes
// the backslash before `$`, a backtick, a backslash and a newline.
type Heredoc struct {
	Index, BodyStart, BodyEnd int
	Expands                   bool
}

// Heredocs are the terminated here-documents bash reads, in operator order.
// One linear scan.
func Heredocs(command string) []Heredoc {
	var out []Heredoc
	for _, d := range hereDocs(command).docs {
		if d.closed {
			out = append(out, Heredoc{Index: d.op, BodyStart: d.start, BodyEnd: max(d.close-1, d.start), Expands: d.expands})
		}
	}
	return out
}

// BlankHeredocs replaces the lines of every terminated heredoc bash reads
// (see hereDocs), body and closing delimiter, and every comment with
// spaces: they are not executable segments. An unquoted delimiter's body
// still undergoes substitution: see Opaque. The command line holding the
// operator stays, and so do the newlines around the blanked lines; offsets
// are preserved.
func BlankHeredocs(command string) string {
	l := hereDocs(command)
	var b []byte
	blank := func(from, to int) {
		if b == nil {
			b = []byte(command)
		}
		for i := from; i < to; i++ {
			b[i] = ' '
		}
	}
	for _, d := range l.docs {
		if d.closed {
			blank(d.start, d.end)
		}
	}
	for _, c := range l.comments {
		blank(c[0], c[1])
	}
	if b == nil {
		return command
	}
	return string(b)
}

// Opaque reports that bash may execute text of command that Segments does
// not expose: a `$(...)`, backtick or function (`${ cmd; }`) substitution (not backslash-escaped) in
// the blanked body of a heredoc whose delimiter is unquoted, a heredoc with
// no closing line, or a heredoc operator hereDocs cannot model (a delimiter
// word holding `$(`, a closing line that is only a prefix match after a
// line continuation or before another pending heredoc). Such a body is left
// unblanked, yet a quote in it can swallow what follows. A guard must treat
// an opaque command as unresolved, like a segment without a head.
func Opaque(command string) bool {
	l := hereDocs(command)
	if l.opaque {
		return true
	}
	for _, d := range l.docs {
		if !d.closed {
			return true
		}
		if !d.expands {
			continue
		}
		body := command[d.start:d.end]
		for i := 0; i < len(body); i++ {
			switch {
			case body[i] == '\\':
				i++
			case body[i] == '`', strings.HasPrefix(body[i:], "$("), body[i] == '$' && FunSubst(body[i+1:]):
				return true
			}
		}
	}
	return false
}

// FunSubst: s, the text after a `$`, opens a bash 5.3 function substitution:
// `{` and then a space, tab, newline or `|`, backslash-newline continuations
// skipped before each.
func FunSubst(s string) bool {
	if s == "" || s[0] != '{' && s[0] != '\\' {
		return false
	}
	joined := func() {
		for strings.HasPrefix(s, "\\\n") {
			s = s[2:]
		}
	}
	if joined(); !strings.HasPrefix(s, "{") {
		return false
	}
	s = s[1:]
	joined()
	return s != "" && strings.IndexByte(" \t\n|", s[0]) >= 0
}

// Unread reports text bash may run that the scans read as literal: a
// function substitution outside single quotes, $'...', comments and heredoc
// bodies (see Opaque for those), or a single quote inside `"${...}"`, where
// it quotes or not by the operator (`"${V#'x'}"` against `"${V:-'x'}"`) and
// the `"` and `}` after it close or not. Where hereDocs stops early, a
// function substitution anywhere in the rest counts.
func Unread(command string) bool { return hereDocs(command).unread }

// Quoting follows bash's quoting through a raw word or a command for the
// scans that look for substitutions in it; the zero value starts unquoted.
type Quoting struct {
	open []byte // enclosing `"` and `${`, innermost last
	dq   int    // `"` in open
}

// Skip is how many bytes at text[i:] hold nothing for the caller to read: a
// single-quoted or $'...' string (to the end of text when unterminated), a
// backslash and the byte it escapes, `$$`, or a `"`, `${` or `}` that changes
// the state; 0 when text[i] is the caller's. A `"` after `${` inside double
// quotes nests, and single quotes anywhere inside double quotes are plain
// characters (see Unread).
func (q *Quoting) Skip(text string, i int) int {
	if strings.IndexByte("\\'\"$}", text[i]) < 0 {
		return 0
	}
	rest, top := text[i:], byte(0)
	if len(q.open) > 0 {
		top = q.open[len(q.open)-1]
	}
	pop := func() {
		if q.open = q.open[:len(q.open)-1]; top == '"' {
			q.dq--
		}
	}
	switch {
	case rest[0] == '\\':
		return min(2, len(rest))
	case q.dq == 0 && rest[0] == '\'':
		if k := strings.IndexByte(rest[1:], '\''); k >= 0 {
			return k + 2
		}
		return len(rest)
	case q.dq == 0 && strings.HasPrefix(rest, "$'"):
		j := 2
		for j < len(rest) && rest[j] != '\'' {
			if rest[j] == '\\' {
				j++
			}
			j++
		}
		return min(j+1, len(rest))
	case strings.HasPrefix(rest, "$$"):
		return 2
	case rest[0] == '"' && top == '"':
		pop()
		return 1
	case rest[0] == '"':
		q.open, q.dq = append(q.open, '"'), q.dq+1
		return 1
	case strings.HasPrefix(rest, "${"):
		q.open = append(q.open, '{')
		return 2
	case rest[0] == '}' && top == '{':
		pop()
		return 1
	}
	return 0
}

// SubstEnd is the offset of the `)` that closes the command substitution
// whose body starts at i; len(s) when there is none. Parentheses that are
// quoted, escaped or inside `${...}` do not count (Quoting).
func SubstEnd(s string, i int) int {
	var q Quoting
	for depth := 0; i < len(s); i++ {
		switch n := q.Skip(s, i); {
		case n > 0:
			i += n - 1
		case len(q.open) > 0:
		case s[i] == '(':
			depth++
		case s[i] == ')' && depth == 0:
			return i
		case s[i] == ')':
			depth--
		}
	}
	return len(s)
}

// hereDoc is a here-document as bash reads it: op is the offset of its
// `<<`; the lines [start, end) run from the line after the operator's
// command line through the closing delimiter (close is the closing line's
// offset), or to the end of the input when unterminated. expands is an
// unquoted delimiter.
type hereDoc struct {
	op, start, close, end int
	closed, expands       bool
}

// lexed is what hereDocs finds: heredocs, comment ranges [from, to), and
// whether it met a heredoc it cannot model.
type lexed struct {
	docs     []hereDoc
	comments [][2]int
	opaque   bool
	unread   bool // see Unread
}

// hereDocs finds the heredocs and comments bash reads, in one linear pass:
// a `<<` or `<<-` in command text (top level, `$(...)` or backticks at any
// depth, also inside double quotes) that is not quoted, escaped, in a
// comment, in arithmetic or a `<<<` here-string, followed by a delimiter
// word (quotes removed, $'...' decoded). Bodies start after the next
// unquoted newline, in operator order, and close on a line equal to the
// delimiter (leading tabs stripped for `<<-`; for an unquoted delimiter,
// after joining backslash-newline continuations). As bash 5.3 does, inside
// `$(...)` a line that starts with the delimiter and holds a `)` later on
// (`EOF)`, `EOFX )`, not `EOFX`) closes it there, and inside backticks
// (at any depth, bash cuts their text first) the first unescaped backtick
// does, mid-line too; the rest of the line is command text again. A
// comment is an unquoted `#` at a word start up to the newline, inside
// backticks also up to the first unescaped backtick. Scanning stops at an
// unterminated heredoc or quote.
//
// ponytail: no case-pattern `)` in `$(...)`, `${...}` treats single quotes
// as literal inside double quotes only, no heredocs inside arithmetic or
// nested (escaped) backticks; a missed heredoc is left unblanked
// (over-exposed).
func hereDocs(s string) (l lexed) {
	type pend struct {
		op            int
		delim         string
		dash, expands bool
	}
	const (
		cmd = iota
		sub
		arith
		dq
		param
		tick
	)
	type frame struct{ kind, depth int }
	var pending []pend
	stack := []frame{{kind: cmd}}
	wordStart := true
	ticks := 0 // tick frames on the stack
	push := func(kind int) {
		stack = append(stack, frame{kind: kind})
		if kind == tick {
			ticks++
		}
	}
	pop := func() {
		if stack[len(stack)-1].kind == tick {
			ticks--
		}
		stack, wordStart = stack[:len(stack)-1], false
	}
	i := 0
	defer func() { // stopped early: the rest is unscanned
		for k := i; k < len(s) && !l.unread; k++ {
			l.unread = s[k] == '$' && FunSubst(s[k+1:])
		}
	}()
	for i < len(s) {
		top := &stack[len(stack)-1]
		rest := s[i:]
		c := s[i]
		if c == '\\' {
			if !strings.HasPrefix(rest, "\\\n") { // a line continuation keeps the word state
				wordStart = false
			}
			i += 2
			continue
		}
		if c == '$' {
			l.unread = l.unread || FunSubst(rest[1:])
			if strings.HasPrefix(rest, "$$") { // the PID: a quote after it is not $'...'
				i, wordStart = i+2, false
				continue
			}
		}
		switch {
		case top.kind == tick && c == '`':
			pop()
			i++
			continue
		case strings.HasPrefix(rest, "$(("):
			push(arith)
			i += 3
			continue
		case strings.HasPrefix(rest, "$("):
			push(sub)
			i, wordStart = i+2, true
			continue
		case strings.HasPrefix(rest, "${"):
			push(param)
			i += 2
			continue
		case c == '`':
			push(tick)
			i, wordStart = i+1, true
			continue
		}
		code := top.kind == cmd || top.kind == sub || top.kind == tick
		quoteOK := code || top.kind == arith || top.kind == param && stack[len(stack)-2].kind != dq
		switch {
		case top.kind == dq && c == '"', top.kind == param && c == '}':
			pop()
			i++
		case top.kind != dq && c == '"':
			push(dq)
			i++
		case (code || top.kind == param && quoteOK) && strings.HasPrefix(rest, "$'"):
			j := i + 2
			for j < len(s) && s[j] != '\'' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return l
			}
			i, wordStart = j+1, false
		case quoteOK && c == '\'':
			k := strings.IndexByte(s[i+1:], '\'')
			if k < 0 {
				return l
			}
			i, wordStart = i+k+2, false
		case !code && top.kind != arith:
			l.unread = l.unread || c == '\'' && top.kind == param
			i++
		case top.kind == arith && c == '(':
			top.depth++
			i++
		case top.kind == arith && c == ')':
			if top.depth > 0 {
				top.depth--
				i++
				break
			}
			pop()
			i++
			if i < len(s) && s[i] == ')' {
				i++
			}
		case top.kind == arith:
			i++
		case c == '#' && wordStart:
			k := lineEnd(s, i)
			if e := tickAt(s[i:k]); ticks > 0 && e >= 0 {
				k = i + e
			}
			l.comments = append(l.comments, [2]int{i, k})
			i = k
		case strings.HasPrefix(rest, "<<<"):
			i, wordStart = i+3, true
		case strings.HasPrefix(rest, "<<"):
			j := i + 2
			dash := j < len(s) && s[j] == '-'
			if dash {
				j++
			}
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			end := scanWord(s, j, ";&|()<>")
			if end < len(s) && s[end] == '(' { // `<<$(x)`: bash's delimiter is the whole word
				l.opaque = true
				return l
			}
			if end > j {
				raw := s[j:end]
				pending = append(pending, pend{i, unquote(raw), dash, !strings.ContainsAny(raw, `'"\\`)})
			}
			i, wordStart = end, end == j
		case wordStart && strings.HasPrefix(rest, "(("):
			push(arith)
			i += 2
		case c == '(':
			top.depth++
			i, wordStart = i+1, true
		case c == ')' && top.kind == sub && top.depth == 0:
			pop()
			i++
		case c == '\n' && len(pending) > 0:
			pos := i + 1
			for k, p := range pending {
				d := hereDoc{op: p.op, start: pos, expands: p.expands}
				for !d.closed {
					next := lineEnd(s, pos)
					phys := s[pos:next]
					line := phys
					if p.dash {
						line = strings.TrimLeft(line, "\t")
					}
					tabs, joined := len(phys)-len(line), false
					// An unquoted delimiter's body joins lines at a
					// backslash-newline before the comparison (`E\` + `OF`
					// closes on EOF); `\\` is an escaped backslash. The
					// parity of the joined line's trailing backslashes is the
					// last physical line's; a line already longer than the
					// delimiter can only keep its prefix (linear).
					for p.expands && next < len(s) && (len(phys)-len(strings.TrimRight(phys, `\`)))%2 == 1 {
						end := lineEnd(s, next+1)
						phys, joined = s[next+1:end], true
						if len(line) <= len(p.delim)+1 {
							line = line[:len(line)-1] + phys
						}
						next = end
					}
					// cut: where command text resumes on this line, which
					// closes the body (see the doc comment).
					cut, tickCut := -1, false
					if ticks > 0 {
						cut = tickAt(s[pos:next])
						tickCut = cut >= 0
					}
					if cut < 0 && top.kind == sub && strings.HasPrefix(line, p.delim) && strings.Contains(s[min(pos+tabs+len(p.delim), next):next], ")") {
						cut = tabs + len(p.delim)
					}
					switch {
					case cut >= 0:
						if joined || k < len(pending)-1 || tickCut && top.kind != tick {
							l.opaque = true
							return l
						}
						d.close, d.end, d.closed = pos, pos+cut, true
						if line[:cut-tabs] != p.delim { // `ab` + backtick: the body ends mid-line
							d.close = pos + cut + 1
						}
					case line == p.delim:
						d.close, d.end, d.closed = pos, next, true
					case next == len(s):
						d.end = len(s)
						l.docs = append(l.docs, d)
						return l
					default:
						pos = next + 1
					}
				}
				l.docs = append(l.docs, d)
				pos = min(d.end+1, len(s))
			}
			pending = nil
			i = l.docs[len(l.docs)-1].end
		default:
			if c == ')' {
				top.depth = max(top.depth-1, 0)
			}
			wordStart = c == ' ' || c == '\t' || c == '\n' || strings.IndexByte(";&|()<>", c) >= 0
			i++
		}
	}
	return l
}

// tickAt is the offset of the first backtick in s not escaped by a
// backslash, or -1.
func tickAt(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '`':
			return i
		}
	}
	return -1
}

// lineEnd is the offset of the newline ending the line at pos, or len(s).
func lineEnd(s string, pos int) int {
	if k := strings.IndexByte(s[pos:], '\n'); k >= 0 {
		return pos + k
	}
	return len(s)
}

// BacktickBody is the body of a backtick command substitution and the
// offset of its opening backtick.
type BacktickBody struct {
	Body  string
	Index int
}

// BacktickBodies are the bodies of backtick command substitutions outside
// single quotes and $'...' (Quoting; also inside double quotes), with the backslash escapes that
// backticks remove. An unterminated substitution is a shell syntax error and
// runs nothing, so it yields no body and ends the scan. Blanked heredoc
// bodies and comments yield none (see Opaque).
func BacktickBodies(command string) []BacktickBody {
	var bodies []BacktickBody
	text := BlankHeredocs(command)
	var q Quoting
	for index := 0; index < len(text); index++ {
		n := q.Skip(text, index)
		switch {
		case n > 0:
			index += n - 1
		case text[index] == '`':
			end := index + 1
			for end < len(text) && text[end] != '`' {
				if text[end] == '\\' {
					end += 2
				} else {
					end++
				}
			}
			if end >= len(text) {
				return bodies
			}
			var b strings.Builder
			for i := index + 1; i < end; i++ {
				if text[i] == '\\' && i+1 < end && strings.IndexByte("\\$`", text[i+1]) >= 0 {
					i++
				}
				b.WriteByte(text[i])
			}
			bodies = append(bodies, BacktickBody{Body: b.String(), Index: index})
			index = end
		}
	}
	return bodies
}
