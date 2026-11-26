package shell

import "testing"

func TestInertHeredocWrite(t *testing.T) {
	for in, want := range map[string]string{
		"cat > f <<'EOF'\nbody\n'x\nEOF":                  "cat > f <<'EOF'\nEOF",
		"cat >> f <<\"END\"\nbody\nEND\n  ":               "cat >> f <<\"END\"\nEND\n  ",
		"mkdir -p ~/d && cat > ~/d/f <<'EOF'\nb\nEOF\nls": "mkdir -p ~/d && cat > ~/d/f <<'EOF'\nEOF\nls",
		"tee f <<'EOF' >/dev/null\nb\nEOF":                "tee f <<'EOF' >/dev/null\nEOF",
		"tee -a f >/dev/null <<'EOF'\nb\nEOFX\nEOF":       "tee -a f >/dev/null <<'EOF'\nEOF",
		"cat > f <<'EOF'\nb\n EOF\nEOF\n":                 "cat > f <<'EOF'\nEOF\n",
		"cat >f <<'EOF'\n\nEOF":                           "cat >f <<'EOF'\nEOF",
	} {
		if got, ok := InertHeredocWrite(in); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"cat > f <<EOF\nb\nEOF",        // unquoted: the body expands
		"cat > f <<-'EOF'\nb\n\tEOF",   // <<- is not modeled
		"cat > f <<'EOF'\nb",           // unterminated
		"cat > f <<'EOF' '\nb\nEOF",    // a quote runs into the body
		"cat > f <<'EOF' && x\nb\nEOF", // more on the operator line
		"cat > f <<'EOF' <<'E2'\nb\nEOF\nE2",
		"cat > $f <<'EOF'\nb\nEOF",
		"cat > `f <<'EOF'\nb\nEOF",
		"cat > 'f' <<'EOF'\nb\nEOF",
		"cat f <<'EOF'\nb\nEOF",
		"tee f <<'EOF'\nb\nEOF", // tee prints the body
		"mkdir x && cat > f <<'EOF'\nb\nEOF",
		"echo; cat > f <<'EOF'\nb\nEOF",
		"cat > f <<'E F'\nb\nE F",
		"cat > f <<'EOF' \\\nb\nEOF",
		"sudo cat > f <<'EOF'\nb\nEOF",
		"cat > f 2>&1 <<'EOF'\nb\nEOF",
		"cat > f > g <<'EOF'\nb\nEOF",
	} {
		if got, ok := InertHeredocWrite(in); ok {
			t.Errorf("%q: accepted as %q", in, got)
		}
	}
}
