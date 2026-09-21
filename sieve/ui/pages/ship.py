"""
Ship — the pattern as the thing you actually run.

The gap this closes is between "it works in the tester" and "it works in the
system I deploy to". Nineteen targets, each emitted with its own flavor,
quoting and idiom — and, where the target's engine has no lookaround, as a
two-pass pipeline rather than a single pattern that silently drops your
Exclude rules.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QApplication, QFileDialog, QListWidget,
                             QListWidgetItem, QPlainTextEdit, QSplitter,
                             QVBoxLayout, QWidget)

from ...core import export
from .. import theme
from ..widgets import (Badge, Card, QuietButton, caption, intro, label,
                       overline, page_body, primary, row, scrolled, title)


class ShipPage(QWidget):
    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self.current = "grep_e"

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._left())
        split.addWidget(self._right())
        split.setStretchFactor(1, 1)
        split.setSizes([300, 760])
        outer.addWidget(split)

        state.recipeChanged.connect(self.refresh)
        self._select_initial()
        self.refresh()

    def _left(self) -> QWidget:
        host, box = page_body()
        box.addWidget(title("Ship"))
        box.addWidget(intro("Pick where this is going."))

        self.targets = QListWidget()
        self.targets.setMinimumWidth(240)
        family = None
        for target in export.TARGETS:
            if target.family != family:
                family = target.family
                header = QListWidgetItem(family.upper())
                header.setFlags(Qt.ItemFlag.NoItemFlags)
                font = header.font()
                font.setPointSize(max(8, font.pointSize() - 2))
                font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.2)
                header.setFont(font)
                self.targets.addItem(header)
            item = QListWidgetItem("   " + target.title)
            item.setData(Qt.ItemDataRole.UserRole, target.id)
            self.targets.addItem(item)
        self.targets.currentItemChanged.connect(self._pick)
        box.addWidget(self.targets, 1)
        return host

    def _select_initial(self) -> None:
        """Called once both halves exist — selecting a row fires _pick."""
        for i in range(self.targets.count()):
            if self.targets.item(i).data(Qt.ItemDataRole.UserRole) == self.current:
                self.targets.setCurrentRow(i)
                return

    def _right(self) -> QWidget:
        host, box = page_body()

        self.target_title = label("", object_name="PageTitle")
        self.target_blurb = label("", wrap=True, object_name="PageIntro")
        self.status_badge = Badge("", "neutral", self.mode)
        box.addLayout(row(self.target_title, None, self.status_badge))
        box.addWidget(self.target_blurb)

        code_card = Card()
        code_card.body.setContentsMargins(1, 1, 1, 1)
        self.code = QPlainTextEdit()
        self.code.setObjectName("Mono")
        self.code.setReadOnly(True)
        self.code.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.code.setFrameShape(QPlainTextEdit.Shape.NoFrame)
        self.code.setMinimumHeight(300)
        code_card.add(self.code, 1)
        box.addWidget(code_card, 1)

        copy = primary("Copy")
        copy.clicked.connect(self._copy)
        save = QuietButton("Save to a file")
        save.clicked.connect(self._save)
        box.addLayout(row(copy, save, None))

        notes = Card("Before you paste this")
        self.notes = label("", wrap=True)
        notes.add(self.notes)
        box.addWidget(notes)
        box.addStretch(1)
        return scrolled(host)

    def _pick(self, item) -> None:
        if item is None:
            return
        target_id = item.data(Qt.ItemDataRole.UserRole)
        if target_id:
            self.current = target_id
            self.refresh()

    def _emission(self):
        if self.state.recipe.is_empty():
            return None
        try:
            return export.emit(self.state.recipe, self.current)
        except Exception as exc:
            self.code.setPlainText(f"Cannot emit this recipe yet:\n{exc}")
            return None

    def refresh(self) -> None:
        target = export.BY_ID[self.current]
        self.target_title.setText(target.title)
        self.target_blurb.setText(target.blurb)

        emission = self._emission()
        if emission is None:
            self.code.setPlainText(
                "Build a pattern first — add a rule on the Build page and it "
                "will appear here, written for this target.")
            self.status_badge.set_tone("neutral", "nothing to ship")
            self.notes.setText("")
            return

        self.code.setPlainText(emission.code)

        if emission.pipeline:
            self.status_badge.set_tone("warn", "two-pass pipeline")
        elif emission.report.clean:
            self.status_badge.set_tone("pass", "runs as written")
        elif emission.report.runs:
            self.status_badge.set_tone("warn", "rewritten for this engine")
        else:
            self.status_badge.set_tone("fail", "will not run")

        lines = []
        for issue in emission.report.issues:
            lines.append(f"· {issue.message}" + (f"  {issue.fix}" if issue.fix else ""))
        for note in emission.notes:
            lines.append(f"· {note}")
        self.notes.setText("\n".join(lines) or
                           "Nothing to watch for — this target runs the pattern "
                           "exactly as Sieve built it.")

    def _copy(self) -> None:
        QApplication.clipboard().setText(self.code.toPlainText())
        self.state.status(f"{export.BY_ID[self.current].title} copied", "pass")

    def _save(self) -> None:
        target = export.BY_ID[self.current]
        suffix = {"python": ".py", "javascript": ".js", "go": ".go",
                  "java": ".java", "csharp": ".cs", "rust": ".rs",
                  "php": ".php", "yaml": ".yml", "json": ".json",
                  "bash": ".sh", "powershell": ".ps1", "yara": ".yar",
                  "suricata": ".rules", "splunk": ".spl"}.get(target.language, ".txt")
        name = (self.state.recipe.name or "pattern").lower().replace(" ", "-")
        path, _ = QFileDialog.getSaveFileName(
            self, f"Save the {target.title} version", f"{name}{suffix}")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.code.toPlainText())
        self.state.status(f"Written to {path}", "pass")

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.status_badge.apply_mode(mode)
        self.refresh()
