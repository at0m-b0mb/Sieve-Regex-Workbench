"""
Sweep — run the proven pattern over real files.

Once a pattern holds up on the Proof page, the next question is always what it
finds in the actual data. Two choices here are deliberate: binary files are
skipped by sniffing for a null byte rather than by extension, because nobody
hiding something uses the extension you expect; and redaction is available at
the point of output, so a report can prove card numbers are present without
copying them into a ticket.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (QCheckBox, QFileDialog, QLineEdit, QProgressBar,
                             QSpinBox, QTreeWidget, QTreeWidgetItem,
                             QVBoxLayout, QWidget)

from ...core import scan as scanner
from .. import theme
from ..widgets import (Badge, Card, QuietButton, caption, intro, label,
                       page_body, primary, row, scrolled, title)


class _Worker(QObject):
    done = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)

    def __init__(self, recipe, paths, include, context, ):
        super().__init__()
        self.recipe = recipe
        self.paths = paths
        self.include = include
        self.context = context
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            result = scanner.scan(
                self.recipe, self.paths, include=self.include,
                context=self.context,
                should_stop=lambda: self._stop,
                on_progress=lambda d, t, p: self.progress.emit(d, t, p))
        except Exception as exc:
            result = scanner.ScanResult(errors=[str(exc)])
        self.done.emit(result)


class SweepPage(QWidget):
    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self.thread: QThread | None = None
        self.worker: _Worker | None = None
        self.result: scanner.ScanResult | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        host, box = page_body()

        box.addWidget(title("Sweep"))
        box.addWidget(intro(
            "Run the recipe across a file or a whole tree. Binary files are "
            "skipped by looking inside them rather than by trusting the "
            "extension, and every hit can be redacted on the way out."))

        where = Card("Where to look")
        self.path = QLineEdit()
        self.path.setPlaceholderText("a file or a folder")
        browse_file = QuietButton("Choose a file")
        browse_file.clicked.connect(self._browse_file)
        browse_dir = QuietButton("Choose a folder")
        browse_dir.clicked.connect(self._browse_dir)
        where.add_layout(row(self.path, browse_file, browse_dir))

        self.include = QLineEdit()
        self.include.setPlaceholderText(
            "only these names — *.log, *.conf, *.py  (blank means everything)")
        where.add(self.include)

        self.context = QSpinBox()
        self.context.setRange(0, 10)
        self.context.setPrefix("context lines: ")
        self.redact = QCheckBox("Redact every match in the results")
        self.redact.setToolTip(
            "Replaces the matched text with blocks, keeping its length — "
            "so a report can prove the data is there without carrying it")
        self.redact.toggled.connect(self._repaint_results)
        where.add_layout(row(self.context, self.redact, None))

        self.go = primary("Sweep")
        self.go.clicked.connect(self._start)
        self.stop = QuietButton("Stop")
        self.stop.clicked.connect(self._stop)
        self.stop.setEnabled(False)
        self.status = label("", object_name="Faint")
        where.add_layout(row(self.go, self.stop, self.status, None))

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        where.add(self.progress)
        box.addWidget(where)

        results = Card("What it found")
        self.summary = label("Nothing swept yet.", wrap=True)
        self.results_badge = Badge("idle", "neutral", self.mode)
        results.add_layout(row(self.summary, None, self.results_badge))

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["File and line", "Text"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setColumnWidth(0, 300)
        self.tree.setMinimumHeight(320)
        results.add(self.tree, 1)

        as_text = QuietButton("Save as text")
        as_text.clicked.connect(lambda: self._save("txt"))
        as_csv = QuietButton("Save as CSV")
        as_csv.clicked.connect(lambda: self._save("csv"))
        as_json = QuietButton("Save as JSON")
        as_json.clicked.connect(lambda: self._save("json"))
        results.add_layout(row(as_text, as_csv, as_json, None))
        box.addWidget(results, 1)
        box.addStretch(0)

        outer.addWidget(scrolled(host))

    # -- choosing ------------------------------------------------------------

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to sweep")
        if path:
            self.path.setText(path)

    def _browse_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose a folder to sweep")
        if path:
            self.path.setText(path)

    # -- running -------------------------------------------------------------

    def _start(self) -> None:
        target = self.path.text().strip()
        if not target:
            self.state.status("Choose a file or a folder first", "warn")
            return
        if not Path(target).expanduser().exists():
            self.state.status("That path does not exist", "fail")
            return
        if self.state.recipe.is_empty():
            self.state.status("Build a pattern before sweeping", "warn")
            return
        if self.thread is not None and self.thread.isRunning():
            return

        self.tree.clear()
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.results_badge.set_tone("neutral", "sweeping")

        self.thread = QThread(self)
        self.worker = _Worker(self.state.recipe.copy(), target,
                              self.include.text().strip(), self.context.value())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.done.connect(self.thread.quit)
        self.thread.finished.connect(self._finished)
        self.thread.start()

    def _stop(self) -> None:
        if self.worker is not None:
            self.worker.stop()
            self.status.setText("stopping…")

    def _on_progress(self, done: int, total: int, path: str) -> None:
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
        self.status.setText(Path(path).name)

    def _finished(self) -> None:
        self.go.setEnabled(True)
        self.stop.setEnabled(False)
        self.progress.setVisible(False)
        self.status.setText("")

    def _on_done(self, result: scanner.ScanResult) -> None:
        self.result = result
        self.summary.setText(result.summary())
        if result.errors:
            self.summary.setText(result.summary() + "  ·  "
                                 + f"{len(result.errors)} unreadable")
        self.results_badge.set_tone(
            "pass" if result.hits else "neutral",
            f"{len(result.hits)} hits" if result.hits else "no hits")
        self._repaint_results()

    def _repaint_results(self) -> None:
        self.tree.clear()
        if self.result is None:
            return
        redact = self.redact.isChecked()
        mono = QFont(theme.MONO.split(",")[0])
        mono.setPixelSize(12)
        faint = QColor(theme.color("ink_faint", self.mode))

        for path, hits in self.result.by_file().items():
            parent = QTreeWidgetItem([Path(path).name,
                                      f"{len(hits)} hit{'s' if len(hits) != 1 else ''}"])
            parent.setToolTip(0, path)
            for hit in hits[:500]:
                for before in hit.before:
                    node = QTreeWidgetItem(["", before])
                    node.setForeground(1, faint)
                    node.setFont(1, mono)
                    parent.addChild(node)
                body = hit.redacted() if redact else hit.text
                node = QTreeWidgetItem([str(hit.line_number), body])
                node.setFont(1, mono)
                parent.addChild(node)
                for after in hit.after:
                    node = QTreeWidgetItem(["", after])
                    node.setForeground(1, faint)
                    node.setFont(1, mono)
                    parent.addChild(node)
            self.tree.addTopLevelItem(parent)
            parent.setExpanded(True)

        for error in self.result.errors[:20]:
            self.tree.addTopLevelItem(QTreeWidgetItem(["could not read", error]))

    # -- reports -------------------------------------------------------------

    def _save(self, kind: str) -> None:
        if self.result is None or not self.result.hits:
            self.state.status("Nothing to save yet", "warn")
            return
        name = (self.state.recipe.name or "sweep").lower().replace(" ", "-")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save the sweep", f"{name}-sweep.{kind}")
        if not path:
            return
        redact = self.redact.isChecked()
        writer = {"txt": scanner.to_text, "csv": scanner.to_csv,
                  "json": scanner.to_json}[kind]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(writer(self.result, redact=redact))
        self.state.status(
            f"Saved {len(self.result.hits)} hits to {path}"
            + (" (redacted)" if redact else ""), "pass")

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.results_badge.apply_mode(mode)
        self._repaint_results()
