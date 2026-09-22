"""
The window, driven headlessly.

Screenshots prove a page renders; they do not prove that clicking the buttons
on it works. This drives the real widgets offscreen — adding rules, taking
library entries, switching pages and themes, running a sweep — because a
runtime error in a click handler is invisible until someone clicks.
"""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication

from sieve.core.rules import EXCLUDE, FIND, Rule
from sieve.ui import theme


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


@pytest.fixture(scope="module")
def _window(app):
    """One window for the whole module, deliberately.

    `apply_mode` sets the stylesheet on the QApplication, which restyles every
    window that still exists — so building a fresh Window per test left a
    growing pile of half-torn-down windows for each theme switch to walk.
    That segfaulted on macOS with Python 3.10 in CI, at around the twentieth
    window, and would eventually have done so anywhere.
    """
    from sieve.ui.app import Window
    win = Window()
    win.resize(1280, 860)
    win.show()
    app.processEvents()
    yield win
    win.state._dirty = False
    win.close()
    win.deleteLater()
    app.processEvents()


@pytest.fixture
def window(_window, app):
    """The shared window, with a fresh document for each test."""
    from sieve.core import samples
    _window.state.new_document()
    _window.state.set_sample(samples.SSH.text, samples.SSH.id)
    _window.state._undo.clear()
    _window.apply_mode(theme.LIGHT)
    app.processEvents()
    yield _window
    # closeEvent asks about unsaved changes with a modal dialog that nothing
    # will ever answer offscreen. Clear the flag before anything tears down.
    _window.state._dirty = False


def test_every_page_builds_and_shows(window, app):
    for key in ("build", "library", "read", "proof", "safety", "sweep",
                "ship", "about"):
        window.show_page(key)
        app.processEvents()
        assert window.stack.currentWidget() is window.pages[key]


def test_both_themes_apply_to_every_page(window, app):
    for mode in (theme.LIGHT, theme.DARK, theme.LIGHT):
        window.apply_mode(mode)
        for key in window.pages:
            window.show_page(key)
            app.processEvents()
        assert window.mode == mode


def test_taking_a_library_entry_adds_a_rule_and_returns_to_build(window, app):
    page = window.pages["library"]
    window.show_page("library")
    page._take("jwt", FIND)
    app.processEvents()
    assert window.state.recipe.rules[-1].source == "jwt"
    assert window.stack.currentWidget() is window.pages["build"]


def test_adding_and_removing_rules_keeps_the_pattern_current(window, app):
    build = window.pages["build"]
    window.show_page("build")
    window.state.add_rule(Rule(pattern="error", label="the word error"))
    window.state.add_rule(Rule(kind=EXCLUDE, pattern="debug", literal=True))
    app.processEvents()
    assert "error" in build.pattern_view.toPlainText()
    assert "debug" in build.pattern_view.toPlainText()
    window.state.remove_rule(1)
    app.processEvents()
    assert "debug" not in build.pattern_view.toPlainText()


def test_proof_page_judges_the_sample_after_a_rule_changes(window, app):
    window.state.add_rule(Rule(pattern="Failed password", label="a failure"))
    window.show_page("proof")
    proof = window.pages["proof"]
    proof._run()
    app.processEvents()
    assert proof._result is not None
    assert proof._result.kept, "the built-in ssh sample should have matches"
    assert proof.map.rows


def test_ship_emits_for_every_target_without_raising(window, app):
    from sieve.core import export
    window.state.add_rule(Rule(pattern=r"\d+", label="a number"))
    ship = window.pages["ship"]
    window.show_page("ship")
    for target in export.TARGETS:
        ship.current = target.id
        ship.refresh()
        app.processEvents()
        assert ship.code.toPlainText().strip()


def test_read_page_explains_a_pasted_pattern(window, app):
    read = window.pages["read"]
    window.show_page("read")
    read.input.set_text(r"^(?!.*healthcheck)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
    read._analyse()
    app.processEvents()
    assert read.tokens.rowCount() > 5
    assert read.matrix.rowCount() > 5


def test_safety_page_runs_a_check_to_completion(window, app):
    import time
    window.state.add_rule(Rule(pattern=r"(a+)+b", label="a bad shape"))
    safety = window.pages["safety"]
    window.show_page("safety")
    safety._pull()
    safety.run_check()
    deadline = time.time() + 20
    while safety.verdict is None and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    assert safety.verdict is not None, "the safety worker never finished"
    assert safety.verdict.is_risky


def test_sweep_finds_hits_in_a_real_tree(window, app, tmp_path):
    import time
    (tmp_path / "a.log").write_text("key=AKIAIOSFODNN7REALKEYS\nnothing\n",
                                    encoding="utf-8")
    window.state.add_rule(Rule(pattern=r"AKIA[A-Z0-9]{16}", label="an aws key"))
    sweep = window.pages["sweep"]
    window.show_page("sweep")
    sweep.path.setText(str(tmp_path))
    sweep._start()
    deadline = time.time() + 20
    while sweep.result is None and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    assert sweep.result is not None, "the sweep worker never finished"
    assert len(sweep.result.hits) == 1
    sweep.redact.setChecked(True)
    app.processEvents()
    assert "AKIAIOSFODNN7REALKEYS" not in sweep.result.hits[0].redacted()


def test_a_document_round_trips_through_the_window(window, app, tmp_path):
    window.state.recipe.name = "Round trip"
    window.state.add_rule(Rule(pattern="x", label="a letter"))
    window.state.add_rule(Rule(kind=EXCLUDE, pattern="y", literal=True))
    path = tmp_path / "p.sieve"
    window.state.save_to(path)
    assert not window.state.dirty

    before = window.state.recipe.pattern()
    window.state.new_document()
    assert window.state.recipe.is_empty()
    window.state.load_document(path.read_text(encoding="utf-8"), path)
    app.processEvents()
    assert window.state.recipe.pattern() == before
    assert window.state.recipe.name == "Round trip"


@pytest.mark.parametrize("name", sorted(
    p.name for p in __import__("pathlib").Path("patterns").glob("*.sieve")))
def test_the_shipped_example_patterns_open(window, app, name):
    from pathlib import Path
    window.state.load_document(
        (Path("patterns") / name).read_text(encoding="utf-8"))
    app.processEvents()
    assert window.state.recipe.rules
    assert window.state.suite.run(window.state.recipe).green


def test_deleting_a_rule_can_be_undone(window, app):
    """A rule you spent ten minutes on used to be gone for good."""
    window.state.add_rule(Rule(pattern="keep-me", label="the one that matters"))
    window.state.add_rule(Rule(pattern="other", label="another"))
    before = len(window.state.recipe.rules)

    window.state.remove_rule(0)
    assert len(window.state.recipe.rules) == before - 1

    message = window.state.undo()
    assert "the one that matters" in message
    assert len(window.state.recipe.rules) == before
    assert window.state.recipe.rules[0].label == "the one that matters"


def test_undo_with_nothing_to_undo_says_so_rather_than_raising(window, app):
    window.state._undo.clear()
    assert window.state.undo() == ""


def test_a_rule_reports_what_it_matches_not_only_how_many(window, app):
    build = window.pages["build"]
    window.show_page("build")
    window.state.add_rule(Rule(pattern=r"Failed password for \w+",
                               label="an auth failure"))
    build._recount()
    app.processEvents()
    card = build.cards[-1]
    assert "of" in card.hits.text().lower()
    assert "Failed password for" in card.hits.toolTip()


def test_a_rule_that_matches_nothing_says_so(window, app):
    build = window.pages["build"]
    window.show_page("build")
    window.state.add_rule(Rule(pattern="NOTHING-LIKE-THIS-IS-PRESENT",
                               label="a dead rule"))
    build._recount()
    app.processEvents()
    assert "NOTHING" in build.cards[-1].hits.text()


def test_the_insert_palette_offers_every_construct(window, app):
    from sieve.ui import palette
    build = window.pages["build"]
    window.show_page("build")
    window.state.add_rule(Rule(pattern="", label="empty"))
    app.processEvents()
    card = build.cards[-1]
    actions = [a for a in card.insert.menu().actions() if not a.isSeparator()]
    assert len(actions) == len(palette.flat())


def test_inserting_a_construct_selects_the_part_you_replace(window, app):
    build = window.pages["build"]
    window.show_page("build")
    window.state.add_rule(Rule(pattern="", label="empty"))
    app.processEvents()
    card = build.cards[-1]
    card.pattern.set_text("")
    card._insert("(?:‹this›|‹that›)")
    assert card.pattern.toPlainText() == "(?:this|that)"
    assert card.pattern.textCursor().selectedText() == "this"


def test_proof_refuses_to_auto_run_a_catastrophic_shape(window, app):
    """The window used to freeze permanently on exactly the shapes Safety
    exists to flag, because matcher.run() executed on the GUI thread."""
    import time
    window.state.set_sample("\n".join(["ordinary"] * 40
                                      + ["a" * 36 + " " + "a" * 12 + "!"]), "")
    window.state.add_rule(Rule(pattern=r"(\w+\s?)+$", label="a bad shape"))
    proof = window.pages["proof"]
    window.show_page("proof")
    started = time.perf_counter()
    proof._run()
    assert time.perf_counter() - started < 2.0, "the GUI thread was blocked"
    assert proof.run_anyway.isVisible()
    assert "Not run automatically" in proof.hint.text()
