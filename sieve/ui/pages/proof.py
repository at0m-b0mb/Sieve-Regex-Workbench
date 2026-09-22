"""
Proof — does the pattern do what you think, and can you show it?

Two halves. Above, a corpus with every line judged and every match lit; beside
it the match map, a core sample of the whole text that no amount of scrolling
would give you. Below, the proof cases: lines that must match and lines that
must not. A detection you cannot re-run is a detection you cannot safely
change, so the cases travel with the pattern in the saved file.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QTextCursor, QTextFormat
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog,
                             QHBoxLayout,
                             QHeaderView, QLineEdit, QPlainTextEdit,
                             QSplitter, QTableWidget, QTableWidgetItem,
                             QTextEdit, QVBoxLayout, QWidget)

from ...core import matcher, redos, samples
from ...core.compare import Baseline, compare
from ...core.proof import Case, SHOULD_MATCH, SHOULD_NOT
from .. import theme
from ..marks import MapRow, MatchMap
from ..widgets import (Badge, Card, QuietButton, caption, intro, label,
                       page_body, primary, row, scrolled, title)


class ProofPage(QWidget):
    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self._result: matcher.RunResult | None = None
        # Set once the user has explicitly accepted the risk for the current
        # pattern; cleared whenever the pattern changes.
        self._force_run = False
        self._screened: str | None = None
        self._baseline: Baseline | None = None

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
        open_file = QuietButton("Open a file")
        open_file.clicked.connect(self._open_file)
        box.addLayout(row(picker, self.sample_blurb, None, open_file, paste))

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
        self.run_anyway = QuietButton("Run it anyway")
        self.run_anyway.setVisible(False)
        self.run_anyway.clicked.connect(self._run_anyway)
        box.addLayout(row(self.hint, None, self.run_anyway))
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

        # The question after every edit is "what did that let in?", and no
        # regex tool answers it. Take a baseline, edit, see what crossed.
        diff = Card("What changed")
        self.diff_state = Badge("no baseline", "neutral", self.mode)
        diff.add_layout(row(self.diff_state, None))
        self.diff_headline = label("", wrap=True)
        diff.add(self.diff_headline)
        self.diff_detail = QTableWidget(0, 2)
        self.diff_detail.setHorizontalHeaderLabels(["", "Line"])
        self.diff_detail.verticalHeader().setVisible(False)
        self.diff_detail.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.diff_detail.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.diff_detail.setMinimumHeight(110)
        self.diff_detail.setMinimumWidth(200)
        self.diff_detail.setVisible(False)
        diff.add(self.diff_detail)
        take = QuietButton("Take a baseline")
        take.setToolTip("Remember what the pattern keeps right now, so the "
                        "next edit can be measured against it")
        take.clicked.connect(self._take_baseline)
        self.clear_baseline = QuietButton("Clear")
        self.clear_baseline.clicked.connect(self._clear_baseline)
        self.clear_baseline.setVisible(False)
        diff.add_layout(row(take, self.clear_baseline, None))
        box.addWidget(diff)

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

    def _open_file(self) -> None:
        """Load a log from disk — the evidence is usually a file.

        Only the first `max_lines` go in: this page re-runs on every keystroke,
        and a 200 MB log pasted into a text editor helps nobody. The status
        line says when only part of the file was loaded, rather than letting
        the corpus look complete.
        """
        path, _ = QFileDialog.getOpenFileName(self, "Open a log to test against")
        if not path:
            return
        cap = 5000
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = []
                for i, line in enumerate(handle):
                    if i >= cap:
                        break
                    lines.append(line.rstrip("\n"))
        except OSError as exc:
            self.state.status(f"Could not read that file: {exc.strerror}", "fail")
            return
        self.state.set_sample("\n".join(lines), "")
        name = path.rsplit("/", 1)[-1]
        self.state.status(
            f"Loaded the first {len(lines):,} lines of {name}"
            if len(lines) >= cap else f"Loaded {name} ({len(lines):,} lines)",
            "pass")

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
        # matcher.run() executes on this, the GUI thread. A regex holds the
        # GIL and cannot be interrupted, so starting a catastrophic pattern
        # here does not make the window slow — it ends the window. Screen the
        # shape first (the same static read the Build badge uses, which is
        # cheap and never runs the pattern) and make the user opt in.
        try:
            pattern = self.state.recipe.pattern()
        except Exception:
            pattern = ""
        if pattern and pattern != self._screened:
            self._screened = pattern
            self._force_run = False
        if pattern and not self._force_run and redos.static_findings(pattern):
            self._hold_back()
            return
        self.run_anyway.setVisible(False)
        result = matcher.run(self.state.recipe, self.editor.toPlainText())
        self._result = result
        self._paint(result)
        self._fill_fields(result)
        self._update_diff()
        self._run_cases()
        self._sync_map()

    def _hold_back(self) -> None:
        """Refuse to auto-run a pattern whose shape can backtrack forever."""
        kinds = {f.kind for f in redos.static_findings(self._screened or "")}
        self.hint.setText(
            "Not run automatically: this pattern contains "
            + ", ".join(sorted(kinds))
            + ". Against the wrong line that can take longer than the rest of "
              "your afternoon, and it would take this window with it. Safety "
              "will measure it; or run it here once and see.")
        self.hint.setStyleSheet(f"color: {theme.color('warn', self.mode)};"
                                f"{theme.font_css('small')}")
        self.run_anyway.setVisible(True)

    def _run_anyway(self) -> None:
        self._force_run = True
        self._run()

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

    # -- comparison ----------------------------------------------------------

    def _take_baseline(self) -> None:
        if self._result is None or self._result.error:
            self.state.status("Nothing to take a baseline of yet", "warn")
            return
        self._baseline = Baseline.of(self._result)
        self.clear_baseline.setVisible(True)
        self.state.status(
            f"Baseline taken: {len(self._baseline.kept)} lines kept", "pass")
        self._update_diff()

    def _clear_baseline(self) -> None:
        self._baseline = None
        self.clear_baseline.setVisible(False)
        self._update_diff()

    def _update_diff(self) -> None:
        if self._baseline is None or self._result is None or self._result.error:
            self.diff_state.set_tone("neutral", "no baseline")
            self.diff_headline.setText(
                "Take a baseline, then edit the pattern. What crosses the line "
                "in either direction appears here — which is the question you "
                "are actually asking when you loosen a rule.")
            self.diff_headline.setStyleSheet(
                f"{theme.font_css('small')}"
                f"color: {theme.color('ink_muted', self.mode)};")
            self.diff_detail.setVisible(False)
            return

        difference = compare(self._baseline, self._result)
        if not difference.changed:
            self.diff_state.set_tone("neutral", "unchanged")
        elif difference.gained and difference.lost:
            self.diff_state.set_tone("warn", "moved sideways")
        elif difference.gained:
            self.diff_state.set_tone("warn", "looser")
        else:
            self.diff_state.set_tone("pass", "stricter")

        self.diff_headline.setText(
            difference.headline() + ". " + difference.direction())
        self.diff_headline.setStyleSheet("")

        rows = ([("+", line) for line in difference.gained]
                + [("\u2212", line) for line in difference.lost])
        self.diff_detail.setVisible(bool(rows))
        self.diff_detail.setRowCount(len(rows))
        mono = QFont(theme.MONO.split(",")[0]); mono.setPixelSize(11)
        for i, (sign, line) in enumerate(rows):
            mark = QTableWidgetItem(sign)
            tone = "pass" if sign == "+" else "fail"
            mark.setForeground(QColor(theme.color(tone, self.mode)))
            self.diff_detail.setItem(i, 0, mark)
            item = QTableWidgetItem(line)
            item.setFont(mono)
            item.setToolTip(line)
            self.diff_detail.setItem(i, 1, item)
        self.diff_detail.resizeColumnToContents(0)

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
