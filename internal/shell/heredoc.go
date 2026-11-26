package shell

import "strings"

// InertHeredocWrite recognizes a command that starts with an inert file
// write from a quoted here-document: its whole first line is an optional
// `mkdir -p DIR && ` then `cat > F <<'DELIM'`, `cat >> F <<'DELIM'` or
// `tee [-a] F <<'DELIM' >/dev/null` (redirections in any order, "DELIM"
// too), every other word a plain unquoted literal. The body ends at the
// first line equal to DELIM. stripped is command without the body lines:
// the first line, then the closing line and whatever follows it, for the
// caller to scan under its normal rules.
//
// ponytail: no `<<-`, no wrappers, no other redirections; anything else is
// not recognized.
func InertHeredocWrite(command string) (stripped string, ok bool) {
	line, body, found := strings.Cut(command, "\n")
	if !found {
		return "", false
	}
	toks := Tokenize(line, false)
	at := 0
	for _, t := range toks { // every non-blank byte of the line is a token
		if strings.Trim(line[at:t.Index], " \t") != "" {
			return "", false
		}
		at = t.Index + len(t.Raw)
	}
	if strings.Trim(line[at:], " \t") != "" {
		return "", false
	}
	if len(toks) > 4 && toks[0].Raw == "mkdir" && toks[1].Raw == "-p" && plainWord(toks[2]) && toks[3].Operator && toks[3].Raw == "&&" {
		toks = toks[4:]
	}
	var words []string
	var delim, out, target string
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.Operator:
			return "", false
		case !t.Redirect:
			if !plainWord(t) {
				return "", false
			}
			words = append(words, t.Raw)
			continue
		case i+1 == len(toks):
			return "", false
		}
		i++
		switch w := toks[i]; {
		case t.Raw == "<<" && delim == "":
			if delim = quotedDelim(w); delim == "" {
				return "", false
			}
		case (t.Raw == ">" || t.Raw == ">>") && out == "" && plainWord(w):
			out, target = t.Raw, w.Raw
		default:
			return "", false
		}
	}
	cat := len(words) == 1 && words[0] == "cat" && out != ""
	tee := len(words) > 1 && words[0] == "tee" && (len(words) == 2 && !strings.HasPrefix(words[1], "-") || len(words) == 3 && words[1] == "-a") &&
		out == ">" && target == "/dev/null"
	if delim == "" || !cat && !tee {
		return "", false
	}
	for rest := body; ; {
		l, after, more := strings.Cut(rest, "\n")
		if l == delim {
			return line + "\n" + rest, true
		}
		if !more {
			return "", false
		}
		rest = after
	}
}

// plainWord is a word with no quoting, escape, expansion or glob.
func plainWord(t Token) bool {
	return !t.Operator && !t.Redirect && t.Raw != "" && t.Raw == t.Value && !strings.ContainsAny(t.Raw, "$`\\'\"*?[{")
}

// quotedDelim is DELIM of a heredoc word 'DELIM' or "DELIM" made of
// [A-Za-z0-9_]; "" otherwise.
func quotedDelim(t Token) string {
	r := t.Raw
	if len(r) < 3 || r[0] != '\'' && r[0] != '"' || r[len(r)-1] != r[0] {
		return ""
	}
	for _, c := range r[1 : len(r)-1] {
		if c != '_' && !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return ""
		}
	}
	return r[1 : len(r)-1]
}
