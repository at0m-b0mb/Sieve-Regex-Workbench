"""
Proof — does the pattern do what you think, and can you show it?

Two halves. Above, a corpus with every line judged and every match lit; beside
it the match map, a core sample of the whole text that no amount of scrolling
would give you. Below, the proof cases: lines that must match and lines that
must not. A detection you cannot re-run is a detection you cannot safely
change, so the cases travel with the pattern in the saved file.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QTextCursor, QTextFormat
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                             QHeaderView, QLineEdit, QPlainTextEdit,
                             QSplitter, QTableWidget, QTableWidgetItem,
                             QTextEdit, QVBoxLayout, QWidget)

from ...core import matcher, samples
from ...core.proof import Case, SHOULD_MATCH, SHOULD_NOT
from .. import theme
from ..marks import MapRow, MatchMap
from ..widgets import (Badge, Card, QuietButton, caption, intro, label,
                       overline, page_body, primary, row, scrolled, title)


class ProofPage(QWidget):
    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self._result: matcher.RunResult | None = None

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(110)
        self._debounce.timeout.connect(self._run)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._left())
        split.addWidget(self._right())
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([600, 500])
        outer.addWidget(split)

        state.recipeChanged.connect(self.schedule)
        state.sampleChanged.connect(self._reload_sample)
        state.suiteChanged.connect(self._reload_cases)
        self._reload_sample()
        self._reload_cases()

    # -- left ---------------------------------------------------------------

    def _left(self) -> QWidget:
        host, box = page_body()
        box.addWidget(title("Proof"))
        box.addWidget(intro(
            "Every line judged, and the reason kept. A line thrown out by an "
            "Exclude rule and a line that never matched look identical in "
            "every other tool — telling them apart is most of the debugging."))

        picker = QComboBox()
        for sample in samples.SAMPLES:
            picker.addItem(sample.title, sample.id)
        picker.currentIndexChanged.connect(self._pick_sample)
        self.picker = picker
        self.sample_blurb = label("", object_name="Faint")

        paste = QuietButton("Paste your own")
        paste.clicked.connect(self._paste)
        box.addLayout(row(picker, self.sample_blurb, None, paste))

        editor_card = Card()
        editor_card.body.setContentsMargins(1, 1, 1, 1)
        holder = QWidget()
        hbox = QHBoxLayout(holder)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(0)

        self.editor = QPlainTextEdit()
        self.editor.setObjectName("Mono")
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setFrameShape(QPlainTextEdit.Shape.NoFrame)
        self.editor.textChanged.connect(self._on_text)
        self.editor.verticalScrollBar().valueChanged.connect(self._sync_map)

        self.map = MatchMap(self.mode)
        self.map.lineClicked.connect(self._jump_to)

        hbox.addWidget(self.editor, 1)
        hbox.addWidget(self.map)
        editor_card.add(holder, 1)
        box.addWidget(editor_card, 1)

        legend = row(
            self._legend("Kept", "find"),
            self._legend("Excluded", "exclude"),
            self._legend("Missing a Require", "warn"),
            self._legend("No match", "neutral"),
            None)
        box.addLayout(legend)
        self.hint = label("", object_name="Faint")
        self.hint.setWordWrap(True)
        box.addWidget(self.hint)
        return host

    def _legend(self, text: str, tone: str):
        return Badge(text, tone, self.mode)

    # -- right --------------------------------------------------------------

    def _right(self) -> QWidget:
        host, box = page_body()

        tally = Card("What happened")
        self.summary = label("", wrap=True)
        tally.add(self.summary)
        self.timing = label("", object_name="Faint")
        tally.add(self.timing)
        box.addWidget(tally)

        fields = Card("Captured fields")
        self.fields = QTableWidget(0, 3)
        self.fields.setHorizontalHeaderLabels(["Line", "Field", "Value"])
        self.fields.verticalHeader().setVisible(False)
        self.fields.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.fields.setAlternatingRowColors(True)
        self.fields.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.fields.setMinimumHeight(120)
        self.fields.setMinimumWidth(200)
        fields.add(self.fields)
        fields.add(caption(
            "Turn on “Keep as field” for a rule on Build and its text appears "
            "here — and becomes a named group everywhere Sieve exports to."))
        box.addWidget(fields)

        cases = Card("Proof cases")
        self.case_state = Badge("no cases", "neutral", self.mode)
        cases.add_layout(row(self.case_state, None))
        cases.add(caption(
            "Lines this pattern must match, and lines it must never match. "
            "They are saved with the pattern and re-run on every edit."))

        self.case_table = QTableWidget(0, 3)
        self.case_table.setHorizontalHeaderLabels(["Expect", "Line", "Result"])
        self.case_table.verticalHeader().setVisible(False)
        self.case_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.case_table.setAlternatingRowColors(True)
        self.case_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.case_table.setMinimumHeight(150)
        self.case_table.setMinimumWidth(200)
        cases.add(self.case_table)

        self.case_input = QLineEdit()
        self.case_input.setObjectName("Mono")
        self.case_input.setPlaceholderText("paste a line to pin down")
        self.case_input.returnPressed.connect(lambda: self._add_case(SHOULD_MATCH))

        must = primary("Must match")
        must.clicked.connect(lambda: self._add_case(SHOULD_MATCH))
        never = QuietButton("Must never match")
        never.clicked.connect(lambda: self._add_case(SHOULD_NOT))
        drop = QuietButton("Remove selected")
        drop.clicked.connect(self._remove_case)
        grab = QuietButton("Take the selected line")
        grab.clicked.connect(self._grab_line)

        cases.add(self.case_input)
        # Two rows: four buttons side by side set a minimum width wider than
        # the column, which drags the whole page past the window edge.
        cases.add_layout(row(must, never, None))
        cases.add_layout(row(grab, None, drop))
        box.addWidget(cases, 1)
        return scrolled(host)

    # -- sample handling ----------------------------------------------------

    def _pick_sample(self) -> None:
        sample = samples.BY_ID[self.picker.currentData()]
        self.sample_blurb.setText(sample.blurb)
        self.state.set_sample(sample.text, sample.id)

    def _paste(self) -> None:
        from PyQt6.QtWidgets import QApplication
        text = QApplication.clipboard().text()
        if text:
            self.state.set_sample(text, "")
            self.state.status("Pasted from the clipboard", "pass")

    def _reload_sample(self) -> None:
        if self.editor.toPlainText() != self.state.sample_text:
            blocked = self.editor.blockSignals(True)
            self.editor.setPlainText(self.state.sample_text)
            self.editor.blockSignals(blocked)
        self.schedule()

    def _on_text(self) -> None:
        self.state.sample_text = self.editor.toPlainText()
        self.state.sample_id = ""
        self.schedule()

    def schedule(self) -> None:
        self._debounce.start()

    def _jump_to(self, line_index: int) -> None:
        block = self.editor.document().findBlockByNumber(line_index)
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        self.editor.setTextCursor(cursor)
        self.editor.centerCursor()

    def _sync_map(self) -> None:
        bar = self.editor.verticalScrollBar()
        first = bar.value()
        visible = max(1, self.editor.viewport().height()
                      // max(1, self.editor.fontMetrics().lineSpacing()))
        self.map.set_viewport(first, first + visible)

    # -- running -------------------------------------------------------------

    def _run(self) -> None:
        result = matcher.run(self.state.recipe, self.editor.toPlainText())
        self._result = result
        self._paint(result)
        self._fill_fields(result)
        self._run_cases()
        self._sync_map()

    def _paint(self, result: matcher.RunResult) -> None:
        if result.error:
            self.summary.setText(result.error)
            self.summary.setStyleSheet(
                f"color: {theme.color('ink_muted', self.mode)};")
            self.timing.setText("")
            self.editor.setExtraSelections([])
            self.map.set_rows([])
            self.hint.setText("")
            return

        self.summary.setText(result.summary())
        self.summary.setStyleSheet("")
        self.timing.setText(
            f"{len(result.lines):,} lines judged in {result.seconds * 1000:.1f} ms"
            + (" · sample truncated" if result.truncated else ""))

        selections = []
        doc = self.editor.document()
        wash = {
            matcher.EXCLUDED: QColor(theme.color("exclude_wash", self.mode)),
            matcher.MISSING_REQUIRE: QColor(theme.color("warn_wash", self.mode)),
        }
        hit = QColor(theme.color("highlight", self.mode))
        hit_ink = QColor(theme.color("highlight_ink", self.mode))

        for line in result.lines:
            block = doc.findBlockByNumber(line.number - 1)
            if not block.isValid():
                continue
            if line.verdict in wash:
                sel = QTextEdit.ExtraSelection()
                sel.format.setBackground(wash[line.verdict])
                sel.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
                cursor = QTextCursor(block)
                sel.cursor = cursor
                selections.append(sel)
            for a, b in line.spans:
                sel = QTextEdit.ExtraSelection()
                sel.format.setBackground(hit)
                sel.format.setForeground(hit_ink)
                cursor = QTextCursor(block)
                cursor.setPosition(block.position() + a)
                cursor.setPosition(block.position() + b,
                                   QTextCursor.MoveMode.KeepAnchor)
                sel.cursor = cursor
                selections.append(sel)

        self.editor.setExtraSelections(selections)
        self.map.set_rows([MapRow(l.verdict, len(l.spans)) for l in result.lines])

        counts = result.counts
        if counts[matcher.KEPT] == 0 and not result.error:
            hint = matcher.first_difference(self.state.recipe,
                                            self.editor.toPlainText())
            self.hint.setText(hint or
                              "Nothing matched. Check a Find rule against one "
                              "line you expect to keep.")
            self.hint.setStyleSheet(f"color: {theme.color('warn', self.mode)};"
                                    f"{theme.font_css('small')}")
        elif counts[matcher.KEPT] == len(result.lines) and len(result.lines) > 3:
            self.hint.setText(
                "Every line matched. That is usually a pattern that is looser "
                "than intended rather than a very clean corpus.")
            self.hint.setStyleSheet(f"color: {theme.color('warn', self.mode)};"
                                    f"{theme.font_css('small')}")
        else:
            self.hint.setText("")

    def _fill_fields(self, result: matcher.RunResult) -> None:
        rows = [(l.number, k, v) for l in result.lines
                for k, v in l.groups.items()][:200]
        self.fields.setRowCount(len(rows))
        for i, (number, key, value) in enumerate(rows):
            self.fields.setItem(i, 0, QTableWidgetItem(str(number)))
            self.fields.setItem(i, 1, QTableWidgetItem(key))
            self.fields.setItem(i, 2, QTableWidgetItem(value))
        self.fields.resizeColumnToContents(0)
        self.fields.resizeColumnToContents(1)

    # -- proof cases ---------------------------------------------------------

    def _add_case(self, expect: str) -> None:
        text = self.case_input.text().strip()
        if not text:
            self.state.status("Type or paste a line first", "warn")
            return
        self.state.add_case(Case(text, expect))
        self.case_input.clear()

    def _grab_line(self) -> None:
        cursor = self.editor.textCursor()
        text = cursor.block().text().strip()
        if text:
            self.case_input.setText(text)

    def _remove_case(self) -> None:
        index = self.case_table.currentRow()
        if index >= 0:
            self.state.remove_case(index)

    def _reload_cases(self) -> None:
        self._run_cases()

    def _run_cases(self) -> None:
        suite = self.state.suite
        if not suite.cases:
            self.case_table.setRowCount(0)
            self.case_state.set_tone("neutral", "no cases")
            return
        outcome = suite.run(self.state.recipe)
        self.case_table.setRowCount(len(outcome.results))
        for i, res in enumerate(outcome.results):
            expect = "must match" if res.case.expect == SHOULD_MATCH \
                else "must not match"
            self.case_table.setItem(i, 0, QTableWidgetItem(expect))
            line_item = QTableWidgetItem(res.case.text)
            self.case_table.setItem(i, 1, line_item)
            verdict = QTableWidgetItem("pass" if res.passed else res.explanation)
            colour = QColor(theme.color("pass" if res.passed else "fail", self.mode))
            verdict.setForeground(colour)
            self.case_table.setItem(i, 2, verdict)
        self.case_table.resizeColumnToContents(0)
        self.case_table.resizeColumnToContents(2)

        if outcome.green:
            self.case_state.set_tone("pass", outcome.headline())
        elif outcome.error:
            self.case_state.set_tone("warn", "cannot run")
        else:
            self.case_state.set_tone("fail", outcome.headline())

    # -- theme ---------------------------------------------------------------

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.map.set_mode(mode)
        for badge in self.findChildren(Badge):
            badge.apply_mode(mode)
        self._run()
