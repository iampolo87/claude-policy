#!/usr/bin/env bash
# Fails when a tracked file, or a commit's author, committer or message,
# contains a home-directory path or a private term.
#
# Terms come from .private-terms at the repository root: one extended regex
# per line, matched case-insensitively; blank lines and lines starting with #
# are skipped. That file is gitignored on purpose (the list is itself
# private), so without it only the path patterns are checked.
#
# usage: scripts/check-private.sh [terms-file]
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2
terms=${1:-.private-terms}
pats=$(mktemp) || exit 2
trap 'rm -f "$pats"' EXIT

# Bracketed so this file does not match itself.
printf '%s\n' '/ho[m]e/' '-ho[m]e-' '/Us[e]rs/[A-Za-z]' >"$pats"
if [ -f "$terms" ]; then
	grep -Ev '^[[:space:]]*(#|$)' "$terms" >>"$pats"
else
	echo "check-private: no $terms, checking path patterns only" >&2
fi

fail=0
if git grep --cached -n -I -i -E -f "$pats" -- . ; then
	echo "check-private: private text in the tracked files above" >&2
	fail=1
fi
# Binary files are skipped by -I above; none may slip in unseen.
if [ -n "$(git grep --cached -l -i -E -f "$pats" -- . | head -1)" ] && [ "$fail" = 0 ]; then
	echo "check-private: private text in a tracked binary file:" >&2
	git grep --cached -l -i -E -f "$pats" -- . >&2
	fail=1
fi
if git ls-files | grep -n -i -E -f "$pats"; then
	echo "check-private: private text in a tracked file name" >&2
	fail=1
fi
if git rev-parse -q --verify HEAD >/dev/null; then
	if git log --all --format='%H %an <%ae> %cn <%ce>%n%B' | grep -n -i -E -f "$pats"; then
		echo "check-private: private text in commit metadata" >&2
		fail=1
	fi
fi
[ "$fail" = 0 ] && echo "check-private: ok ($(git ls-files | wc -l) tracked files)"
exit "$fail"
