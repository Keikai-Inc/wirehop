#!/usr/bin/env bash
# check-style.sh — enforce the mechanical half of site/STYLE.md.
#
# The taste rules (lead with the reader's problem, define terms before use)
# need a human. These don't, and every one of them has already shipped to
# production at least once: em-dashes the style guide forbids, a CSS class
# defined on only one of the three pages that used it, and anchors with no
# colour falling back to browser-default blue on a near-black background.
#
# Usage: ./site/check-style.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

FAIL=0
fail() { printf '  FAIL  %s\n' "$*"; FAIL=1; }
pass() { printf '  ok    %s\n' "$*"; }

echo "== STYLE.md rule 8: no em-dashes =="
if hits=$(grep -nE '—|&mdash;' ./*.html 2>/dev/null) && [ -n "$hits" ]; then
  fail "em-dashes present:"; printf '%s\n' "$hits" | sed 's/^/          /'
else
  pass "no em-dashes"
fi

echo "== markup: balanced divs =="
DIV_BAD=0
for f in ./*.html; do
  o=$(grep -o '<div' "$f" | wc -l | tr -d ' ')
  c=$(grep -o '</div>' "$f" | wc -l | tr -d ' ')
  [ "$o" = "$c" ] || { fail "$f: $o <div> vs $c </div>"; DIV_BAD=1; }
done
[ "$DIV_BAD" = 0 ] && pass "all pages balanced"

echo "== internal links resolve =="
for p in $(grep -ohE 'href="[a-z0-9-]+\.html' ./*.html | sed 's/href="//' | sort -u); do
  [ -f "$p" ] || fail "dead internal link: $p"
done
pass "checked internal links"

echo "== CSS classes are defined =="
python3 - <<'PY' || FAIL=1
import re, glob, sys
shared = open("shared.css").read()
bad = False
for page in sorted(glob.glob("*.html")):
    html = open(page).read()
    local = "\n".join(re.findall(r"<style>(.*?)</style>", html, re.S))
    defined = set(re.findall(r"\.([a-zA-Z][\w-]*)", shared + local))
    # Classes used only as a JS/document.getElementById handle, never styled.
    defined |= {"builder-advanced"}
    used = set()
    for m in re.finditer(r'class="([^"]+)"', html):
        used.update(m.group(1).split())
    missing = sorted(used - defined)
    if missing:
        print(f"  FAIL  {page}: undefined CSS classes {missing}")
        bad = True
if not bad:
    print("  ok    every class used is defined")
sys.exit(1 if bad else 0)
PY

echo "== STYLE.md rule 9: colour palette and WCAG AA =="
python3 - <<'PY' || FAIL=1
import re, sys

css = open("shared.css").read()

def lum(c):
    def f(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])

def ratio(a, b):
    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)

def hx(s):
    s = s.lstrip("#")
    if len(s) == 3:
        s = "".join(ch * 2 for ch in s)
    return tuple(int(s[i:i + 2], 16) for i in (0, 2, 4))

def var(name, default):
    m = re.search(rf"{re.escape(name)}:\s*(#[0-9a-fA-F]{{3,6}})", css)
    return hx(m.group(1)) if m else hx(default)

bg = var("--color-bg", "#09090b")
bad = False

# A base `a` rule is what stops an unclassed anchor rendering browser-blue.
if not re.search(r"(^|\n)a\s*\{[^}]*color", css):
    print("  FAIL  shared.css has no base `a { color: ... }` rule; unclassed "
          "anchors will fall back to browser-default blue")
    bad = True
else:
    print("  ok    base `a` colour rule present")

# Text colours that must clear AA. Buttons are excluded: there the brand red is
# a BACKGROUND with white on it, which is a different (passing) pairing.
TEXT_VARS = ["--color-link", "--color-link-hover", "--color-text",
             "--color-text-secondary", "--color-text-tertiary"]
for name in TEXT_VARS:
    m = re.search(rf"{re.escape(name)}:\s*(#[0-9a-fA-F]{{3,6}})", css)
    if not m:
        continue
    r = ratio(hx(m.group(1)), bg)
    if r < 4.5:
        print(f"  FAIL  {name} ({m.group(1)}) is {r:.2f}:1 on the page "
              f"background, below WCAG AA 4.5:1")
        bad = True
if not bad:
    print("  ok    text colour variables clear WCAG AA")

# --color-primary is a button background, not a text colour (4.12:1).
prim = re.search(r"--color-primary:\s*(#[0-9a-fA-F]{3,6})", css)
if prim and ratio(hx(prim.group(1)), bg) < 4.5:
    import glob
    offenders = []
    for page in sorted(glob.glob("*.html")):
        for i, line in enumerate(open(page), 1):
            if "color: var(--color-primary)" in line and "background" not in line:
                offenders.append(f"{page}:{i}")
    if offenders:
        print(f"  FAIL  --color-primary used as TEXT (only "
              f"{ratio(hx(prim.group(1)), bg):.2f}:1). Use --color-link: "
              + ", ".join(offenders))
        bad = True
    else:
        print("  ok    --color-primary used only as a background")

sys.exit(1 if bad else 0)
PY

echo
if [ "$FAIL" = 0 ]; then
  echo "STYLE: PASS"
else
  echo "STYLE: FAIL"
fi
exit "$FAIL"
