# Changelog

All notable changes to Sieve are recorded here.

## 1.1.0 — 2026-09-22

A review pass found that the Proof page could disagree with the pattern Ship
emits. Everything below follows from taking that seriously.

### Fixed — correctness

- **Proof and Ship could disagree, four ways.** `matcher.run()` decided a
  verdict from `core_pattern()`, which by construction carries no `^` or `$`,
  so an anchored rule showed green on Proof for lines the exported pattern
  rejects. Anchors now live inside the compiled core — they cannot be applied
  to match spans afterwards, because that cannot reproduce backtracking:
  `(?:a|b)|alpha` against `alpha` reports a one-character match until `$` fails
  and the engine backtracks into the longer branch. A fuzzer now runs 12,000
  generated recipes through both paths and asserts they agree.
- **Anchors leaked past an alternation.** `^passwd|shadow$` means "starts with
  passwd, or ends with shadow" — the anchors bind to one branch each. The core
  is now wrapped before anything is attached to it.
- **Require and Exclude guards crossed newlines.** They were spelled `.*`, which
  becomes newline-crossing the moment "a dot also matches a line break" is set.
  They are line-scoped with `[^\n]` now, independent of the flag.
- **Sigma export discarded every guard but the last.** It emitted a repeated
  `message|re:` key inside one YAML mapping, which is not a list. Each Require
  gets its own named block and the Excludes become a proper list. The test now
  parses the emitted YAML instead of looking for substrings in it — which is
  exactly why the bug survived the first time.
- **Five SIEM targets dropped the anchors** for the same reason as the matcher.
- **The `.sieve` export shipped no proof cases**, despite its own description
  promising them — so a committed file failed `sieve test` in the CI it was
  written for.
- **Sweep claimed a clean bill of health it had not earned.** A file over
  200,000 lines was truncated and reported like any other; one over the size
  limit was skipped silently. Results now carry a `partial` list and a caveat
  naming what was not read, in every output format.
- **Proof could hang the window permanently** — `matcher.run()` executed on the
  GUI thread, and a regex holds the GIL. A pattern with a catastrophic shape is
  no longer run automatically; the page says why and offers to run it once.

- **Quitting during a Safety probe or a Sweep crashed.** The window tore down
  while the worker thread was still running, so the result landed on a deleted
  C++ object: `RuntimeError: wrapped C/C++ object of type _Worker has been
  deleted`. Closing now waits for a running worker; a sweep is asked to stop
  first and returns between files.
- **A half-typed pattern crashed the live validator.** `([a` is not exotic
  input — it is the state you pass through while typing `([a-z]+)`, and the
  Build page re-parses on every keystroke. Reading one character past the end
  of a partial character class raised `IndexError`. Every prefix of every
  library pattern is now a test case.
- The rule error label hid its message when a pattern became valid but never
  cleared it, so the widget described history rather than the pattern in front
  of it.

### Fixed — the library

Thirteen confirmed misses, each now covered by a proof case:

- **Payment cards**: Mastercard's 2-series (2221–2720, live since 2016) was
  absent entirely, so the shipped redaction recipe leaked them. Numbers written
  in groups of four (`4111 1111 1111 1111`) were missed too.
- **SQL injection**: only numeric tautologies were recognised, so the classic
  `' OR 'a'='a` and `AND 1=1` went straight past.
- **Path traversal**: the mixed-encoding form `%2e%2e/` — the most common
  single WAF bypass — was not covered. Replaced with a dot-unit × separator-unit
  product that subsumes every combination.
- **Windows event IDs and Authorization headers** assumed a bare `:` separator,
  so both were blind to JSON- and XML-shaped logs, which is how Sysmon,
  Winlogbeat and every cloud audit trail ship today. `EventCode` is recognised.
- **Encoded PowerShell**: the switch had to fall within 200 characters of the
  binary name, which an ordinary Sysmon command line already exceeds.
- Added a **SHA-1** entry, the hash most vendor IOC feeds publish under, and
  extended the attachment pattern with macro-enabled Office formats and `.xll`.

- **The ReDoS analyser cried wolf on a loaded machine.** The growth exponent
  was taken from the first and last measurement, with a one-microsecond floor —
  so scheduler jitter on a shared CI runner fitted a "quadratic" curve through
  a plainly linear pattern and told the user their innocent regex was
  dangerous. Each length is now timed best-of-three, points below a 50 µs
  noise floor are discarded as clock rather than cost, and the exponent is a
  least-squares fit across every usable point. Where too little signal exists
  it reports *"ran too fast at every length to show a trend"* rather than
  inventing a number. A pattern that exceeds the time limit is now graded on
  *where* it blew up — `^(a+)+$` reports "exceeded the time limit at 24
  characters of crafted input", which says more than any slope.

### Added

- **An Insert menu on every rule** — 33 regex constructs by their English names
  (*any digit*, *one or more*, *either this or that*, *only if not followed
  by*), dropped in at the cursor with the part you need to replace already
  selected. You are still editing the real pattern, which is the only way
  anyone learns the syntax.
- **A live match count on every rule**, against the current sample. A rule that
  matches nothing is dead; a rule that matches every line is not
  discriminating. Both now say so on the card.
- **Proof can open a log file**, rather than only a built-in sample or the
  clipboard. The evidence is usually a file.
- **A first run that produces something.** The empty Build page now offers the
  five worked examples — one click to a pattern that already passes its own
  proof cases, which is a better place to start reading from than a blank
  screen. They moved into the package, so `pip install` carries them.
- **Hovering a rule's match count lists what it actually matched.** The count
  says how much; these say what, and seeing the real text is the fastest way
  to notice a rule is catching the wrong thing.
- **Undo** for a deleted rule or proof case (Edit ▸ Undo). Deleting used to be
  final.
- **Continuous integration** across macOS, Windows and Linux on Python 3.10,
  3.12 and 3.13 — running the suite, proving every shipped example pattern, and
  failing if any library pattern backtracks catastrophically.

### Changed

- **A new banner**, and the README's flow diagram is now a Mermaid block.
  The old SVG was Qt-generated and named fonts GitHub does not have, at
  positions computed for those exact fonts, so every label drifted. The in-app
  diagram is unaffected — it is drawn live, where the fonts exist.
- Removed dead code: the `Stat` widget, the `Themed` mixin, `by_family()`, an
  `if False` branch whose neighbouring text promised a rewrite that never
  happened, and every unused import in the package.

## 1.0.0 — 2026-09-21

First release.

### The workbench

- **Build** — compose a pattern from *Find*, *Require* and *Exclude* rules,
  with the regex and its plain-English reading assembling side by side.
- **Proof** — every line of a corpus judged, with the rule responsible for
  each rejection named. Proof cases are saved with the pattern and re-run on
  every edit.
- **Safety** — static analysis for the three published families of
  catastrophic backtracking, plus a bounded probe that builds adversarial
  input, times the real engine and plots the growth curve.
- **Library** — security patterns, each carrying its own positive and negative
  examples and an honest statement of what it cannot do.
- **Read** — any pasted regex explained piece by piece, with a compatibility
  matrix across nine engines.
- **Sweep** — run a proven pattern over a file or a tree, with context lines,
  binary detection by content, and redaction on the way out.
- **Ship** — 19 export targets. Where the target engine has no lookaround, a
  two-pass pipeline is emitted rather than the exclusions being dropped.

### Elsewhere

- A command line over the same engine: `test`, `lint`, `explain`, `scan`,
  `emit`, `library`, `samples`. `sieve test` exits non-zero on a failing proof
  case, so a detection can live in CI.
- Light, dark and follow-the-system themes. Dark mode is true black, and a
  test asserts no colour in it reads as blue.
