# Changelog

All notable changes to Sieve are recorded here.

## 1.0.0 — 2026-09-21

First release.

### The workbench

- **Build** — compose a pattern from *Find*, *Require* and *Exclude* rules,
  with the regex and its plain-English reading assembling side by side.
- **Proof** — every line of a corpus judged, with the rule responsible for
  each rejection named. Proof cases (must match / must never match) are saved
  with the pattern and re-run on every edit.
- **Safety** — static analysis for the three published families of
  catastrophic backtracking, plus a bounded probe that builds adversarial
  input, times the real engine and plots the growth curve.
- **Library** — 57 security patterns across 10 families, each carrying its own
  positive and negative examples and an honest statement of what it cannot do.
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
- 603 tests, including every library pattern against its own examples, the
  explainer reconstructing every pattern byte for byte, and no export target
  silently dropping a rule.
