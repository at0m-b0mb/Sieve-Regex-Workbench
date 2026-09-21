<div align="center">

<img src="docs/mark-light.svg#gh-light-mode-only" width="96" alt="">
<img src="docs/mark-dark.svg#gh-dark-mode-only" width="96" alt="">

# SIEVE

**A regex workbench for security work.**

Build a pattern out of *find*, *require* and *exclude* rules. Prove it against
cases that must match and cases that must never. Check it for catastrophic
backtracking. Then ship it to whichever of 19 tools will actually
run it — with an honest warning when that engine cannot do what you built.

Cross-platform: macOS, Windows and Linux. Python and PyQt6, nothing else.

</div>

---

## The problem this solves

A regex that works in a tester is not a regex that works in production.

- The pattern you validated in Python goes into a **Go** service, where RE2
  has no lookaround at all, and your `Exclude` rules silently vanish.
- The detection you wrote with `\d` goes into **POSIX grep**, which has never
  heard of `\d`, and quietly matches nothing for six months.
- The email validator you copied from a blog post turns out to backtrack
  **exponentially**, and a forty-character request takes the service down.
- Six months later nobody can tell whether the pattern still does what its
  name claims, because it is one unbroken line of punctuation.

Sieve is built around those four failures.

---

## How it works

<div align="center">
<img src="docs/flow-light.svg#gh-light-mode-only" width="860" alt="Sample text passes through Find, Require and Exclude gates to produce kept lines; the Library feeds the gates, Proof cases hold them in place, Safety checks the pattern and Ship exports it.">
<img src="docs/flow-dark.svg#gh-dark-mode-only" width="860" alt="Sample text passes through Find, Require and Exclude gates to produce kept lines; the Library feeds the gates, Proof cases hold them in place, Safety checks the pattern and Ship exports it.">
</div>

Text goes in on the left and passes three named gates. Everything else hangs
off that spine.

| Gate | What it is |
|---|---|
| **Find** | What the match itself is made of. Several Find rules join one after another, as alternatives, or as an unordered set — your choice, stated once rather than encoded in punctuation. |
| **Require** | A condition on the *line*, not on the match. "Only when the word failure is also present." Becomes a lookahead, or a second pass where the target engine has none. |
| **Exclude** | The noise you already know about: your own scanner, your health checks, the service that logs an error every minute and always has. This is the rule kind that turns a demo into a detection. |

The three stay separate in the saved file and are joined only at the moment
the pattern is emitted — so the next person can switch one off and see what
changes.

---

## Screens

### Build — compose the rules, watch the regex and the English assemble together

![Build](docs/screenshots/light-build.png)

### Proof — every line judged, with the reason kept

![Proof](docs/screenshots/light-proof.png)

A line thrown out by an `Exclude` rule and a line that simply never matched
look identical in every other tool. Telling them apart is most of the
debugging, so Sieve tints them differently and names the rule responsible.

The ribbon down the right of the corpus is the **match map**: one hairline per
line, coloured by verdict. At a glance you can see whether the hits are
clustered or spread, whether an Exclude rule ate a whole region, and whether
the pattern is firing on *every* line — which almost always means it is looser
than you intended.

### Safety — does this pattern blow up?

![Safety](docs/screenshots/light-safety.png)

Two methods, reported separately because they mean different things. A static
read finds the shapes known to backtrack — nested quantifiers, overlapping
alternation, adjacent unbounded repeats. Then a probe builds adversarial input
and **times the real engine** against growing lengths, and plots the curve
against a linear-time reference.

It never says a pattern is safe. It says what it checked and what it measured.

### Ship — 19 targets, and the truth about each one

![Ship](docs/screenshots/dark-ship.png)

Picked `grep -E` for a recipe with `Exclude` rules? POSIX has no lookaround,
so Sieve emits a **two-pass pipeline** rather than dropping your exclusions and
handing you something that over-matches:

```bash
grep -E 'Failed password for (invalid user )?([[:alnum:]_]+)' logfile \
  | grep -E -v healthcheck
```

Note the `(?:` that became `(`, and the `\w` that became `[[:alnum:]_]` —
because POSIX has neither, and a pattern that compiles but means something
different is the worst outcome available.

---

## The library

57 patterns across 10 families, and **every one carries
the examples it must match and the examples it must not**. The test suite runs
all of them, so a broken pattern fails CI rather than a detection.

Network · Credentials and secrets · Hashes and crypto · Threat intelligence · Web and injection · Files and paths · Windows · Log formats and time · Personal data · Cloud

Every card also states what the pattern **cannot** do:

> **AWS access key ID** — `\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b`
> *Finds the ID, never the secret, and cannot tell you whether the key is
> live. Treat every hit as live until proven dead.*

> **IPv4 address** — *Version strings and dotted decimals of the right shape
> still match. Anchor it to a field if the log format lets you.*

That is not a disclaimer. It is the part an analyst needs before pasting a
pattern into a SIEM.

---

## Install and run

```bash
git clone https://github.com/at0m-b0mb/Sieve-Regex-Workbench.git
cd Sieve-Regex-Workbench
pip install -r requirements.txt
python3 run.py
```

Or install it properly and get both entry points:

```bash
pip install .
sieve            # the window
sieve --help     # the command line
```

---

## The command line

`sieve/core/` imports no GUI toolkit, so the same engine runs in CI. A pattern
saved from the window is a plain JSON file, and `sieve test` exits non-zero
when a proof case fails — which is what makes a detection rule something you
can put in a pipeline rather than something you remember to check.

```bash
sieve test detections/ssh-brute-force.sieve       # re-run the proof cases
sieve lint --strict 'my (pattern|here)+'          # ReDoS + portability, exit 1 if risky
sieve explain '^(?!.*healthcheck).*error'         # read a regex back in English
sieve scan patterns/aws-keys.sieve ~/src --redact # sweep a tree, redact the hits
sieve emit detections/x.sieve sigma               # write it as a Sigma rule
sieve library rfc1918 --quiet                     # browse the library
sieve samples ssh | sieve scan 'Failed password' -
```

A pre-commit hook that refuses a detection whose own proof cases fail:

```bash
#!/bin/sh
for f in detections/*.sieve; do sieve test "$f" || exit 1; done
```

---

## Engines Sieve knows about

- **Python re** — Atomic groups and possessive quantifiers need Python 3.11+.
- **PCRE2 (grep -P, PHP, nginx)** — The most featureful engine here, and the easiest to write a catastrophic pattern in.
- **RE2 (Go, ripgrep, CloudFlare)** — Runs in guaranteed linear time, and pays for it by dropping lookaround and backreferences entirely.
- **JavaScript (ES2018+)** — Lookbehind needs ES2018 — Safari only shipped it in 16.4. Inline flags like (?i) are not supported at all.
- **Java** — Bounded-width lookbehind only: {0,20} is fine, + is not.
- **.NET** — The only common engine with true variable-length lookbehind.
- **Rust regex crate** — RE2's design in Rust. Same guarantees, same omissions.
- **POSIX ERE (grep -E, awk)** — No \d, no \w, no lazy quantifiers. Use [[:digit:]] and [[:alnum:]_] instead.
- **POSIX BRE (grep, sed)** — Even ( ) and + must be backslash-escaped. Reach for -E instead unless something forces your hand.

Each one is checked against what it can really do — lookaround, lookbehind
width, named-group spelling, atomic groups, possessive quantifiers,
backreferences, shorthand classes, word boundaries, unicode properties, inline
and scoped flags, lazy quantifiers, conditionals and recursion.

---

## Sample corpora

7 built-in corpora, one click away, so you are testing against the
text you actually grep rather than against "the quick brown fox":

- **Linux auth log** — sshd failures, successes and a sudo.
- **Web access log** — Combined format, with probes in it.
- **Config and source** — The things you hope are not committed.
- **Windows process creation** — Sysmon-style command lines.
- **Firewall and DNS** — Connections and lookups, mixed.
- **Records to redact** — Personal data in an export.
- **Incident notes** — A report with defanged indicators.

All synthetic. Addresses come from the documentation ranges (RFC 5737, RFC
3849), the keys are the vendors' own published examples, and the names are
invented.

---

## Design notes

**Warm paper, not white.** A screen full of monospaced log text on pure white
glares. The ground is `#F3F1EC` with white cards and hairline rules.

**Two golds, not one.** A deep brass for anything that carries words, and a
brighter gold reserved for marks that carry none. A single gold cannot be a
fill behind white text *and* a bright accent *and* small text on paper.

**Dark mode is true black.** `#000000` with neutral greys above it. A test
asserts that no colour in the dark ramp reads as blue.

**Contrast is measured, not eyeballed.** `tests/test_theme.py` checks every
text-on-ground pairing against WCAG AA in both themes. It caught two failures
the eye had passed.

**The mark** is a sieve seen from the side: two grains through the mesh, one
held back. Find, and exclude. It is drawn in code, so the window icon, the
96-pixel wordmark and the SVG in this README are the same twelve strokes — and
`docs/make_assets.py` renders the flow diagram above with the *same function*
the How-it-works page paints with, so the documentation cannot drift from the
product.

---

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest
```

603 tests. The ones that matter most:

- every library pattern against its own positive and negative examples
- every library pattern proved **not** to backtrack catastrophically
- the explainer's tokens reconstructing every pattern byte for byte
- no export target silently dropping a `Require` or `Exclude` rule
- the ReDoS probe staying bounded on a pathological pattern
- every text/ground colour pairing meeting WCAG AA in both themes
- the verdict text never containing the words "is safe"
- the window itself, driven headlessly: every page built, both themes applied,
  every export target emitted, a real sweep run and a document round-tripped
- the five shipped example patterns passing their own proof cases

---

## Scope

Sieve is for authorised work on systems and data you are responsible for. The
patterns here find things; what you do about them is the job.

The `Personal data` family exists so you can **find personal data in order to
redact it** — which is why the scanner and every report format take a
`--redact` flag that replaces each match with blocks while keeping its length.
A report can prove the data is present without carrying it.

---

## Licence

MIT. See [LICENSE](LICENSE).
