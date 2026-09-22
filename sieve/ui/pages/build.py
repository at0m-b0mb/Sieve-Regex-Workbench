"""
Build — where a recipe is composed.

The screen is deliberately two columns. On the left you stack rules; on the
right you watch the regex and the English reading of it change as you type.
Seeing both at once is the teaching mechanism: people learn the syntax by
watching it assemble itself out of choices they understand.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QTextCursor
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFrame,
                             QLineEdit, QMenu,
                             QSpinBox, QSplitter, QToolButton,
                             QVBoxLayout, QWidget)

from ...core import rules as R
from ... import examples
from ...core import redos
from .. import palette
from .. import theme
from ..widgets import (Badge, Card, PatternEdit, QuietButton, caption,
                       intro, label, page_body, row, scrolled, title)


class RuleCard(QFrame):
    """One rule, fully editable, with its kind written on it in colour."""

    changed = pyqtSignal()
    removeRequested = pyqtSignal()
    moveRequested = pyqtSignal(int)

    def __init__(self, rule: R.Rule, mode: str, parent=None):
        super().__init__(parent)
        self.rule = rule
        self.mode = mode
        self.setObjectName("Card")
        self._building = True

        box = QVBoxLayout(self)
        box.setContentsMargins(14, 10, 14, 12)
        box.setSpacing(8)

        # --- head -----------------------------------------------------------
        self.badge = Badge(R.KIND_LABEL[rule.kind], rule.kind, mode)
        self.enabled = QCheckBox()
        self.enabled.setChecked(rule.enabled)
        self.enabled.setToolTip("Switch this rule off without deleting it")
        self.enabled.toggled.connect(self._on_enabled)

        self.label_edit = QLineEdit(rule.label)
        self.label_edit.setPlaceholderText("what this rule is, in your words")
        self.label_edit.textChanged.connect(self._on_label)

        up = QuietButton("↑")
        up.setToolTip("Move earlier")
        up.clicked.connect(lambda: self.moveRequested.emit(-1))
        down = QuietButton("↓")
        down.setToolTip("Move later")
        down.clicked.connect(lambda: self.moveRequested.emit(1))
        remove = QuietButton("×")
        remove.setToolTip("Delete this rule")
        remove.clicked.connect(self.removeRequested.emit)
        for b in (up, down, remove):
            b.setFixedWidth(24)

        box.addLayout(row(self.badge, self.enabled, self.label_edit,
                          None, up, down, remove))

        # --- pattern ---------------------------------------------------------
        self.pattern = PatternEdit(mode, "pattern, or plain text if Literal is on")
        self.pattern.set_text(rule.pattern)
        self.pattern.changed.connect(self._on_pattern)
        box.addWidget(self.pattern)

        self.error = label("", object_name="Faint")
        self.error.setWordWrap(True)
        self.error.setVisible(False)
        box.addWidget(self.error)

        # --- options ---------------------------------------------------------
        self.literal = QCheckBox("Literal")
        self.literal.setToolTip("Treat the text exactly as typed — a dot means "
                                "a dot, not any character")
        self.literal.setChecked(rule.literal)
        self.literal.toggled.connect(self._on_option)

        self.whole_word = QCheckBox("Whole word")
        self.whole_word.setChecked(rule.whole_word)
        self.whole_word.toggled.connect(self._on_option)

        self.capture = QCheckBox("Keep as field")
        self.capture.setChecked(rule.capture)
        self.capture.toggled.connect(self._on_capture)

        self.capture_name = QLineEdit(rule.capture_name)
        self.capture_name.setPlaceholderText("field name")
        self.capture_name.setFixedWidth(110)
        self.capture_name.setVisible(rule.capture)
        self.capture_name.textChanged.connect(self._on_option)

        # Every construct by its English name, inserted at the cursor with the
        # part you are meant to replace already selected. The gap between
        # knowing what you want to match and knowing how to spell it is where
        # most people give up on regex, and this is the bridge across it.
        self.insert = QToolButton()
        self.insert.setText("Insert")
        self.insert.setCursor(Qt.CursorShape.PointingHandCursor)
        self.insert.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.insert.setToolTip("Drop a regex construct in at the cursor")
        menu = QMenu(self.insert)
        for heading, items in palette.GROUPS:
            menu.addSection(heading)
            for lab, snippet, why in items:
                act = QAction(lab, menu)
                act.setToolTip(why)
                act.triggered.connect(
                    lambda _=False, sn=snippet: self._insert(sn))
                menu.addAction(act)
        menu.setToolTipsVisible(True)
        self.insert.setMenu(menu)

        # How much of the sample this one rule accounts for. A rule matching
        # nothing is dead; a rule matching every line is not discriminating.
        self.hits = Badge("", "neutral", mode)
        self.hits.setVisible(False)

        opts = row(self.literal, self.whole_word, self.capture,
                   self.capture_name, None, self.hits, self.insert)
        box.addLayout(opts)

        # --- repetition -------------------------------------------------------
        self.repeat = QComboBox()
        for mode_id in R.REPEATS:
            self.repeat.addItem(R.REPEAT_LABEL[mode_id], mode_id)
        self.repeat.setCurrentIndex(R.REPEATS.index(rule.repeat.mode))
        self.repeat.currentIndexChanged.connect(self._on_repeat)

        self.minimum = QSpinBox()
        self.minimum.setRange(0, 9999)
        self.minimum.setValue(rule.repeat.minimum)
        self.minimum.valueChanged.connect(self._on_option)
        self.maximum = QSpinBox()
        self.maximum.setRange(0, 9999)
        self.maximum.setValue(rule.repeat.maximum)
        self.maximum.valueChanged.connect(self._on_option)
        self.to_label = label("to", object_name="Faint")

        self.greedy = QCheckBox("As much as possible")
        self.greedy.setChecked(rule.repeat.greedy)
        self.greedy.toggled.connect(self._on_option)

        self.case = QComboBox()
        self.case.addItem("Case: follow the recipe", None)
        self.case.addItem("Case: ignore here", True)
        self.case.addItem("Case: exact here", False)
        index = {None: 0, True: 1, False: 2}[rule.ignore_case]
        self.case.setCurrentIndex(index)
        self.case.currentIndexChanged.connect(self._on_option)

        rep = row(label("Repeats", object_name="Label"), self.repeat,
                  self.minimum, self.to_label, self.maximum, self.greedy,
                  None, self.case)
        box.addLayout(rep)

        self._building = False
        self._sync_repeat_visibility()
        self.apply_mode(mode)

    def _insert(self, snippet: str) -> None:
        """Put a construct in at the cursor and select its placeholder."""
        text, sel_at, sel_len = palette.expand(snippet)
        cursor = self.pattern.textCursor()
        cursor.insertText(text)
        if sel_len:
            end = cursor.position() - (len(text) - sel_at - sel_len)
            cursor.setPosition(end - sel_len)
            cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
            self.pattern.setTextCursor(cursor)
        self.pattern.setFocus()

    def set_hits(self, matched: int | None, total: int,
                 examples: list[str] | None = None) -> None:
        """Show what this rule alone accounts for in the current sample."""
        if matched is None or not total:
            self.hits.setVisible(False)
            self.hits.setToolTip("")
            return
        self.hits.setVisible(True)
        if matched == 0:
            self.hits.set_tone("warn", "matches nothing here")
            self.hits.setToolTip(
                "Nothing in the current sample matches this rule on its own. "
                "Either the sample does not contain what you are looking for, "
                "or the rule does not say what you meant.")
            return
        if matched == total and total > 2:
            self.hits.set_tone("warn", "matches every line")
        else:
            self.hits.set_tone("brass", f"{matched} of {total} lines")
        # The count says how much; these say what. Seeing the actual text a
        # rule caught is the fastest way to notice it is catching the wrong
        # thing — a count alone looks healthy right up until you look.
        if examples:
            shown = "\n".join(f"  {e}" for e in examples[:4])
            more = f"\n  … and {matched - len(examples[:4])} more" \
                if matched > len(examples[:4]) else ""
            self.hits.setToolTip("What this rule matches:\n" + shown + more)
        else:
            self.hits.setToolTip("")

    # -- reactions -----------------------------------------------------------

    def _on_enabled(self, checked: bool) -> None:
        self.rule.enabled = checked
        self.pattern.setEnabled(checked)
        self.label_edit.setEnabled(checked)
        self._emit()

    def _on_label(self, text: str) -> None:
        self.rule.label = text
        self._emit()

    def _on_pattern(self, text: str) -> None:
        self.rule.pattern = text
        self._validate()
        self._emit()

    def _on_capture(self, checked: bool) -> None:
        self.rule.capture = checked
        self.capture_name.setVisible(checked)
        self._emit()

    def _on_repeat(self) -> None:
        self.rule.repeat.mode = self.repeat.currentData()
        self._sync_repeat_visibility()
        self._on_option()

    def _on_option(self) -> None:
        self.rule.literal = self.literal.isChecked()
        self.rule.whole_word = self.whole_word.isChecked()
        self.rule.capture_name = self.capture_name.text().strip()
        self.rule.repeat.minimum = self.minimum.value()
        self.rule.repeat.maximum = self.maximum.value()
        self.rule.repeat.greedy = self.greedy.isChecked()
        self.rule.ignore_case = self.case.currentData()
        self._validate()
        self._emit()

    def _emit(self) -> None:
        if not self._building:
            self.changed.emit()

    def _sync_repeat_visibility(self) -> None:
        mode = self.rule.repeat.mode
        needs_min = mode in (R.EXACT, R.RANGE, R.AT_LEAST)
        needs_max = mode == R.RANGE
        self.minimum.setVisible(needs_min)
        self.maximum.setVisible(needs_max)
        self.to_label.setVisible(needs_max)
        self.greedy.setVisible(mode in (R.ANY, R.SOME, R.OPTIONAL, R.RANGE, R.AT_LEAST))

    def _validate(self) -> None:
        import re
        if not self.rule.pattern.strip() or self.rule.literal:
            self._clear_error()
            return
        try:
            re.compile(self.rule.fragment())
            self._clear_error()
        except re.error as exc:
            self.error.setText(R._friendly_re_error(exc, self.rule.pattern))
        except Exception as exc:                 # noqa: BLE001 — see below
            # Defence in depth. This runs on every keystroke against text that
            # is, by definition, half-written, and a raw traceback out of a
            # live validator would take the window with it. Anything the
            # parser did not anticipate is still just an invalid pattern.
            self.error.setText(f"Sieve cannot read this pattern yet ({exc}).")
            self.error.setStyleSheet(f"color: {theme.color('fail', self.mode)};"
                                     f"{theme.font_css('small')}")
            self.error.setVisible(True)
            self.error.setStyleSheet(f"color: {theme.color('fail', self.mode)};"
                                     f"{theme.font_css('small')}")
            self.error.setVisible(True)

    def _clear_error(self) -> None:
        """Hide the message AND forget it.

        Hiding alone left the last complaint sitting in the label, so the
        widget's state described history rather than the pattern in front of
        it — invisible to the eye, and a trap for anything that reads it.
        """
        self.error.setText("")
        self.error.setVisible(False)

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.badge.apply_mode(mode)
        self.pattern.apply_mode(mode)
        edge = theme.color(self.rule.kind, mode)
        self.setStyleSheet(
            f"#Card {{ background: {theme.color('surface', mode)};"
            f" border: 1px solid {theme.color('rule', mode)};"
            f" border-left: 3px solid {edge};"
            f" border-radius: {theme.RADIUS['card']}px; }}")


class BuildPage(QWidget):
    """The composer."""

    goToLibrary = pyqtSignal()

    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self.cards: list[RuleCard] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._left())
        split.addWidget(self._right())
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([600, 460])
        outer.addWidget(split)

        # Counting is cheap but runs per rule per line, so it trails the
        # edit rather than racing it.
        self._count_timer = QTimer(self)
        self._count_timer.setSingleShot(True)
        self._count_timer.setInterval(160)
        self._count_timer.timeout.connect(self._recount)

        state.recipeChanged.connect(self.refresh)
        state.sampleChanged.connect(lambda: self._count_timer.start())
        self.refresh()

    # -- left column ---------------------------------------------------------

    def _left(self) -> QWidget:
        host, box = page_body()

        box.addWidget(title("Build"))
        box.addWidget(intro(
            "A working pattern is rarely one regex. Stack the three kinds of "
            "rule and Sieve joins them for you — and keeps them separate, so "
            "the next person can read what you meant."))

        naming = Card()
        self.name_edit = QLineEdit(self.state.recipe.name)
        self.name_edit.setPlaceholderText("name this pattern")
        self.name_edit.textChanged.connect(self._on_name)
        self.intent_edit = QLineEdit(self.state.recipe.intent)
        self.intent_edit.setPlaceholderText(
            "what it is for — this becomes the description in a Sigma or YARA rule")
        self.intent_edit.textChanged.connect(self._on_intent)
        naming.add(self.name_edit)
        naming.add(self.intent_edit)
        box.addWidget(naming)

        self.rules_host = QWidget()
        self.rules_box = QVBoxLayout(self.rules_host)
        self.rules_box.setContentsMargins(0, 0, 0, 0)
        self.rules_box.setSpacing(10)
        self.rules_box.addStretch(1)
        box.addWidget(self.rules_host)

        # The empty state is the first thing anyone sees, and a blank page is
        # a poor answer to "what does this do". Offer the worked examples: one
        # click to a pattern that already passes its own proof cases, which is
        # a far better place to start reading from than nothing.
        self.empty_note = Card(flat=True)
        self.empty_note.add(label("Nothing here yet", object_name="CardTitle"))
        self.empty_note.add(caption(
            "Start with a Find rule for the thing you are looking for, then "
            "add Exclude rules for the noise you already know about. Or take "
            "a tested pattern from the Library — or open one of these, each "
            "of which arrives with its proof cases already passing."))
        for path, name, intent in examples.listing():
            button = QuietButton(name)
            button.setToolTip(intent)
            button.clicked.connect(
                lambda _=False, p=path: self._open_example(p))
            # In a row with a stretch, so they read as a list of choices
            # rather than a stack of centred blocks.
            self.empty_note.add_layout(row(button, None))
        pick = QuietButton("Browse the Library instead")
        pick.clicked.connect(self.goToLibrary.emit)
        self.empty_note.add_layout(row(pick, None))
        box.addWidget(self.empty_note)

        adders = row(
            self._adder("Add a Find rule", R.FIND),
            self._adder("Add a Require rule", R.REQUIRE),
            self._adder("Add an Exclude rule", R.EXCLUDE),
            None)
        box.addLayout(adders)
        box.addStretch(1)
        return scrolled(host)

    def _adder(self, text: str, kind: str):
        button = QuietButton(text)
        button.setToolTip(R.KIND_BLURB[kind])
        button.clicked.connect(lambda: self._add(kind))
        return button

    def _add(self, kind: str) -> None:
        self.state.add_rule(R.Rule(kind=kind))

    def _open_example(self, path) -> None:
        try:
            self.state.load_document(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self.state.status(f"Could not open that example: {exc}", "fail")
            return
        # Deliberately not treated as "opened from" that path: it is a
        # starting point, and saving should not offer to overwrite the copy
        # that ships with the application.
        self.state.file_path = None
        self.state._dirty = False
        self.state.pathChanged.emit()
        self.state.status(f"Opened the “{self.state.recipe.name}” example",
                          "pass")

    def _on_name(self, text: str) -> None:
        self.state.recipe.name = text
        self.state.touch()

    def _on_intent(self, text: str) -> None:
        self.state.recipe.intent = text
        self.state.touch()

    # -- right column --------------------------------------------------------

    def _right(self) -> QWidget:
        host, box = page_body()

        pattern_card = Card("The pattern")
        self.pattern_view = PatternEdit(self.mode)
        self.pattern_view.setReadOnly(True)
        self.pattern_view.setFixedHeight(76)
        self.pattern_view.setLineWrapMode(
            self.pattern_view.LineWrapMode.WidgetWidth)
        pattern_card.add(self.pattern_view)

        copy = QuietButton("Copy")
        copy.clicked.connect(self._copy_pattern)
        self.safety_badge = Badge("not checked", "neutral", self.mode)
        self.length_note = label("", object_name="Faint")
        pattern_card.add_layout(row(copy, None, self.length_note,
                                    self.safety_badge))
        box.addWidget(pattern_card)

        reading = Card("In plain English")
        self.reading = label("", wrap=True)
        self.reading.setTextFormat(Qt.TextFormat.RichText)
        reading.add(self.reading)
        box.addWidget(reading)

        flags = Card("Throughout")
        self.join = QComboBox()
        for join_id in R.JOINS:
            self.join.addItem("Find rules: " + R.JOIN_LABEL[join_id], join_id)
        self.join.currentIndexChanged.connect(self._on_flags)
        flags.add(self.join)

        self.ignore_case = QCheckBox("Ignore case")
        self.multiline = QCheckBox("^ and $ match at every line break")
        self.dotall = QCheckBox("A dot also matches a line break")
        self.anchor_start = QCheckBox("The match must start the line")
        self.anchor_end = QCheckBox("The match must end the line")
        for check in (self.ignore_case, self.multiline, self.dotall,
                      self.anchor_start, self.anchor_end):
            check.toggled.connect(self._on_flags)
            flags.add(check)
        box.addWidget(flags)
        box.addStretch(1)
        return scrolled(host)

    def _copy_pattern(self) -> None:
        text = self.state.recipe.pattern()
        QApplication.clipboard().setText(text)
        self.state.status("Pattern copied to the clipboard", "pass")

    def _on_flags(self) -> None:
        recipe = self.state.recipe
        recipe.join = self.join.currentData()
        recipe.ignore_case = self.ignore_case.isChecked()
        recipe.multiline = self.multiline.isChecked()
        recipe.dot_matches_newline = self.dotall.isChecked()
        recipe.anchor_start = self.anchor_start.isChecked()
        recipe.anchor_end = self.anchor_end.isChecked()
        self.state.touch()

    # -- refresh -------------------------------------------------------------

    def refresh(self) -> None:
        recipe = self.state.recipe

        if self.name_edit.text() != recipe.name:
            self.name_edit.setText(recipe.name)
        if self.intent_edit.text() != recipe.intent:
            self.intent_edit.setText(recipe.intent)

        for widget in (self.join, self.ignore_case, self.multiline, self.dotall,
                       self.anchor_start, self.anchor_end):
            widget.blockSignals(True)
        self.join.setCurrentIndex(R.JOINS.index(recipe.join))
        self.ignore_case.setChecked(recipe.ignore_case)
        self.multiline.setChecked(recipe.multiline)
        self.dotall.setChecked(recipe.dot_matches_newline)
        self.anchor_start.setChecked(recipe.anchor_start)
        self.anchor_end.setChecked(recipe.anchor_end)
        for widget in (self.join, self.ignore_case, self.multiline, self.dotall,
                       self.anchor_start, self.anchor_end):
            widget.blockSignals(False)

        self._rebuild_cards()

        try:
            pattern = recipe.pattern()
            self.pattern_view.set_text(pattern or "")
            self.length_note.setText(
                f"{len(pattern)} characters" if pattern else "")
        except R.RecipeError as exc:
            self.pattern_view.set_text("")
            self.length_note.setText(str(exc))
            pattern = ""

        lines = recipe.describe()
        html = []
        for line in lines:
            if line.startswith("  · "):
                html.append(f"<div style='margin-left:16px'>&middot; "
                            f"{line[4:]}</div>")
            else:
                html.append(f"<div style='margin-top:4px'>{line}</div>")
        self.reading.setText("".join(html))

        self._update_safety(pattern)

    def _update_safety(self, pattern: str) -> None:
        """A quick static read only — the timed probe lives on Safety."""
        if not pattern:
            self.safety_badge.set_tone("neutral", "no pattern")
            return
        findings = redos.static_findings(pattern)
        if findings:
            self.safety_badge.set_tone("warn", "risky shape")
            self.safety_badge.setToolTip(
                findings[0].kind + " — open Safety for the measurement")
        else:
            self.safety_badge.set_tone("pass", "shape looks plain")
            self.safety_badge.setToolTip(
                "No known-bad shape found. Run Safety for a measured check.")

    def _recount(self) -> None:
        """How many sample lines each rule matches, on its own."""
        import re as _re
        lines = self.state.sample_text.split("\n")
        total = len(lines)
        flags = self.state.recipe.flags()
        for card in self.cards:
            rule = card.rule
            if not rule.enabled or not rule.pattern.strip():
                card.set_hits(None, 0)
                continue
            try:
                fragment = rule.fragment()
                # Never run a shape that can backtrack forever on the GUI
                # thread — the same guard the Proof page uses.
                if redos.static_findings(fragment):
                    card.set_hits(None, 0)
                    continue
                rx = _re.compile(fragment, flags)
            except Exception:
                card.set_hits(None, 0)
                continue
            matched = 0
            examples: list[str] = []
            for line in lines:
                found = rx.search(line)
                if not found:
                    continue
                matched += 1
                if len(examples) < 4:
                    text = found.group(0)
                    examples.append(text[:70] + ("…" if len(text) > 70 else "")
                                    or "(an empty match)")
            card.set_hits(matched, total, examples)

    def _rebuild_cards(self) -> None:
        for card in self.cards:
            card.setParent(None)
            card.deleteLater()
        self.cards = []

        for index, rule in enumerate(self.state.recipe.rules):
            card = RuleCard(rule, self.mode)
            card.changed.connect(self._on_card_changed)
            card.removeRequested.connect(
                lambda _=False, i=index: self.state.remove_rule(i))
            card.moveRequested.connect(
                lambda delta, i=index: self.state.move_rule(i, delta))
            self.rules_box.insertWidget(self.rules_box.count() - 1, card)
            self.cards.append(card)

        self.empty_note.setVisible(not self.state.recipe.rules)
        self._count_timer.start()

    def _on_card_changed(self) -> None:
        # The cards edit the rule objects in place, so the recipe is already
        # current; this only needs to refresh the derived views.
        recipe = self.state.recipe
        pattern = ""
        try:
            pattern = recipe.pattern()
        except R.RecipeError:
            pass
        self.pattern_view.set_text(pattern)
        self.length_note.setText(f"{len(pattern)} characters" if pattern else "")
        lines = recipe.describe()
        self.reading.setText("".join(
            f"<div style='margin-left:16px'>&middot; {l[4:]}</div>"
            if l.startswith("  · ") else f"<div style='margin-top:4px'>{l}</div>"
            for l in lines))
        self._update_safety(pattern)
        self._count_timer.start()
        self.state._dirty = True
        self.state.sampleChanged.emit()      # nudges Proof to re-run

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.pattern_view.apply_mode(mode)
        self.safety_badge.apply_mode(mode)
        for card in self.cards:
            card.apply_mode(mode)
