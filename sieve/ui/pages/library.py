"""
Library — tested patterns you can take.

Every card shows three things the usual cheat-sheet leaves out: what the
pattern will not do, the examples it is proven against, and which of the three
rule kinds you probably want it as. A pattern without its caveat is a trap
with good intentions.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QApplication, QComboBox, QFrame, QLineEdit,
                             QVBoxLayout, QWidget)

from ...core import library as lib
from ...core.rules import EXCLUDE, FIND, REQUIRE, Rule
from .. import theme
from ..widgets import (Badge, Card, QuietButton, caption, intro, label,
                       overline, page_body, row, scrolled, title)


class EntryCard(QFrame):
    take = pyqtSignal(str, str)          # entry id, kind

    def __init__(self, entry: lib.Entry, mode: str, parent=None):
        super().__init__(parent)
        self.entry = entry
        self.mode = mode
        self.setObjectName("Card")

        box = QVBoxLayout(self)
        box.setContentsMargins(16, 12, 16, 14)
        box.setSpacing(6)

        head = label(entry.title, object_name="CardTitle")
        self.family = Badge(entry.family.split()[0], "brass", mode)
        box.addLayout(row(head, None, self.family))

        box.addWidget(label(entry.summary, wrap=True))

        self.pattern = label(entry.pattern, wrap=True)
        self.pattern.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        box.addWidget(self.pattern)

        self.caveat = label("What it cannot do  ·  " + entry.caveat, wrap=True)
        box.addWidget(self.caveat)

        if entry.matches or entry.avoids:
            proof = " · ".join(
                [f"matches {m!r}" for m in entry.matches[:2]]
                + [f"never {a!r}" for a in entry.avoids[:2]])
            box.addWidget(caption(proof))

        as_find = QuietButton("Use as Find")
        as_find.clicked.connect(lambda: self.take.emit(entry.id, FIND))
        as_req = QuietButton("as Require")
        as_req.clicked.connect(lambda: self.take.emit(entry.id, REQUIRE))
        as_exc = QuietButton("as Exclude")
        as_exc.clicked.connect(lambda: self.take.emit(entry.id, EXCLUDE))
        copy = QuietButton("Copy pattern")
        copy.clicked.connect(self._copy)
        box.addLayout(row(as_find, as_req, as_exc, None, copy))

        self.apply_mode(mode)

    def _copy(self) -> None:
        QApplication.clipboard().setText(self.entry.pattern)

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        self.family.apply_mode(mode)
        self.pattern.setStyleSheet(
            f"{theme.font_css('mono_small')}"
            f"color: {theme.color('ink', mode)};"
            f"background: {theme.color('sunken', mode)};"
            f"border: 1px solid {theme.color('rule', mode)};"
            f"border-radius: 3px; padding: 6px 8px;")
        self.caveat.setStyleSheet(
            f"{theme.font_css('small')}"
            f"color: {theme.color('ink_muted', mode)};"
            f"border-left: 2px solid {theme.color('warn', mode)};"
            f"padding-left: 8px;")


class LibraryPage(QWidget):
    ruleTaken = pyqtSignal()

    def __init__(self, state, mode: str, parent=None):
        super().__init__(parent)
        self.state = state
        self.mode = mode
        self.cards: list[EntryCard] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        host, box = page_body()
        box.addWidget(title("Library"))
        box.addWidget(intro(
            f"{len(lib.ENTRIES)} patterns for security work, each one tested "
            "against the examples printed on its card. Every card also says "
            "what the pattern cannot do, because that is the part that "
            "decides whether you can trust a hit."))

        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "search — try jwt, powershell, rfc1918, sigma, redact")
        self.search.textChanged.connect(self._refilter)

        self.family = QComboBox()
        self.family.addItem("Every family", "")
        for family in lib.FAMILIES:
            self.family.addItem(family, family)
        self.family.currentIndexChanged.connect(self._refilter)

        box.addLayout(row(self.search, self.family))
        self.count = label("", object_name="Faint")
        box.addWidget(self.count)

        self.family_note = label("", wrap=True, object_name="PageIntro")
        box.addWidget(self.family_note)

        self.list_host = QWidget()
        self.list_box = QVBoxLayout(self.list_host)
        self.list_box.setContentsMargins(0, 0, 0, 0)
        self.list_box.setSpacing(12)
        self.list_box.addStretch(1)
        box.addWidget(self.list_host)
        box.addStretch(1)

        outer.addWidget(scrolled(host))
        self._refilter()

    def _refilter(self) -> None:
        query = self.search.text().strip()
        family = self.family.currentData()
        entries = lib.search(query) if query else list(lib.ENTRIES)
        if family:
            entries = [e for e in entries if e.family == family]
            self.family_note.setText(lib.FAMILY_BLURB.get(family, ""))
        else:
            self.family_note.setText("")

        for card in self.cards:
            card.setParent(None)
            card.deleteLater()
        self.cards = []

        for entry in entries[:80]:
            card = EntryCard(entry, self.mode)
            card.take.connect(self._take)
            self.list_box.insertWidget(self.list_box.count() - 1, card)
            self.cards.append(card)

        total = len(entries)
        shown = min(total, 80)
        self.count.setText(
            f"{total} pattern{'s' if total != 1 else ''}"
            + (f", showing the first {shown}" if total > shown else ""))

    def _take(self, entry_id: str, kind: str) -> None:
        entry = lib.BY_ID[entry_id]
        rule = Rule(kind=kind, pattern=entry.pattern,
                    label=entry.title.lower(), source=entry.id,
                    note=entry.caveat)
        if entry.ignore_case:
            rule.ignore_case = True
        self.state.add_rule(rule)
        self.state.status(f"Added “{entry.title}” as a {kind} rule", "pass")
        self.ruleTaken.emit()

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        for card in self.cards:
            card.apply_mode(mode)
