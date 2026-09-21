"""
The small shared pieces.

Everything here takes its colours from `theme` and re-reads them when the
theme changes, so there is exactly one place a palette decision is made.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import (QColor, QFont, QSyntaxHighlighter, QTextCharFormat,
                         QTextCursor)
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPlainTextEdit,
                             QPushButton, QSizePolicy, QVBoxLayout, QWidget)

from . import theme


class Themed:
    """Mixin for anything that must repaint when the palette changes."""

    def apply_mode(self, mode: str) -> None:      # pragma: no cover - overridden
        pass


class WrapLabel(QLabel):
    """A word-wrapping label that will admit to being narrow.

    Qt computes a wrapping QLabel's minimum width from its longest *line*, not
    its longest word, so one long sentence inside a scroll area drags the whole
    column wider than the window and clips everything at the right edge. This
    reports a small minimum and lets the layout decide the width, which is what
    word wrap was for.
    """

    def minimumSizeHint(self):
        hint = super().minimumSizeHint()
        hint.setWidth(min(hint.width(), 80))
        return hint

    def sizeHint(self):
        hint = super().sizeHint()
        hint.setWidth(min(hint.width(), 640))
        return hint


def label(text: str, role: str = "body", *, wrap: bool = False,
          object_name: str = "") -> QLabel:
    lab = WrapLabel(text) if wrap else QLabel(text)
    lab.setWordWrap(wrap)
    if object_name:
        lab.setObjectName(object_name)
    lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lab


def title(text: str) -> QLabel:
    return label(text, object_name="PageTitle")


def intro(text: str) -> QLabel:
    lab = label(text, wrap=True, object_name="PageIntro")
    lab.setMaximumWidth(760)
    return lab


def caption(text: str) -> QLabel:
    return label(text, wrap=True, object_name="Faint")


def overline(text: str) -> QLabel:
    return label(text.upper(), object_name="Label")


def hairline() -> QFrame:
    line = QFrame()
    line.setObjectName("Rule")
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    return line


class Card(QFrame):
    """A white panel with a hairline. The only container in the app."""

    def __init__(self, heading: str = "", *, flat: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("CardFlat" if flat else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(theme.SPACE["roomy"], theme.SPACE["base"],
                                     theme.SPACE["roomy"], theme.SPACE["base"])
        self.body.setSpacing(theme.SPACE["snug"])
        self._heading = None
        if heading:
            self._heading = label(heading, object_name="CardTitle")
            self.body.addWidget(self._heading)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)


class Badge(QLabel):
    """A small coloured chip. `tone` names a palette entry and its wash."""

    TONES = {
        "find": ("find", "find_wash"),
        "require": ("require", "require_wash"),
        "exclude": ("exclude", "exclude_wash"),
        "pass": ("pass", "pass_wash"),
        "fail": ("fail", "danger_wash"),
        "warn": ("warn", "warn_wash"),
        "danger": ("danger", "danger_wash"),
        "neutral": ("ink_muted", "surface_alt"),
        "brass": ("brass", "brass_wash"),
    }

    def __init__(self, text: str = "", tone: str = "neutral",
                 mode: str = theme.LIGHT, parent=None):
        super().__init__(text.upper(), parent)
        self.tone = tone
        self.mode = mode
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)
        self.apply_mode(mode)

    def set_tone(self, tone: str, text: str | None = None) -> None:
        self.tone = tone
        if text is not None:
            self.setText(text.upper())
        self.apply_mode(self.mode)

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        ink_name, wash_name = self.TONES.get(self.tone, self.TONES["neutral"])
        self.setStyleSheet(
            f"color: {theme.color(ink_name, mode)};"
            f"background: {theme.color(wash_name, mode)};"
            f"border: 1px solid {theme.color(ink_name, mode)};"
            f"border-radius: 2px; padding: 1px 6px;"
            f"{theme.font_css('label')} letter-spacing: 1px;"
        )


class Stat(QWidget):
    """A figure with a word under it. Serif numeral, small-caps label."""

    def __init__(self, value: str, name: str, tone: str = "ink",
                 mode: str = theme.LIGHT, parent=None):
        super().__init__(parent)
        self.tone = tone
        self.mode = mode
        box = QVBoxLayout(self)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(0)
        self.value = label(value, object_name="Figure")
        self.name = overline(name)
        box.addWidget(self.value)
        box.addWidget(self.name)
        self.apply_mode(mode)

    def set_value(self, value: str, tone: str | None = None) -> None:
        self.value.setText(value)
        if tone is not None and tone != self.tone:
            self.tone = tone
            self.apply_mode(self.mode)

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        family, size, weight = theme.TYPE["figure"]
        self.value.setStyleSheet(
            f"font-family: {family}; font-size: {size}px; font-weight: {weight};"
            f"color: {theme.color(self.tone, mode)};")


class QuietButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setObjectName("Quiet")
        self.setCursor(Qt.CursorShape.PointingHandCursor)


def primary(text: str) -> QPushButton:
    button = QPushButton(text)
    button.setObjectName("Primary")
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def row(*widgets, spacing: int = 8, stretch_at: int | None = None) -> QHBoxLayout:
    box = QHBoxLayout()
    box.setContentsMargins(0, 0, 0, 0)
    box.setSpacing(spacing)
    for i, w in enumerate(widgets):
        if w is None:
            box.addStretch(1)
            continue
        if isinstance(w, QWidget):
            box.addWidget(w)
        else:
            box.addLayout(w)
        if stretch_at == i:
            box.addStretch(1)
    return box


# --- regex syntax highlighting ---------------------------------------------

class PatternHighlighter(QSyntaxHighlighter):
    """Colours a regex by construct, using the explainer's own tokeniser.

    Sharing the tokeniser matters: what is highlighted and what is explained
    can never disagree, because they are the same reading of the pattern.
    """

    def __init__(self, document, mode: str = theme.LIGHT):
        super().__init__(document)
        self.mode = mode
        self._build_formats()

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self._build_formats()
        self.rehighlight()

    def _build_formats(self) -> None:
        def fmt(colour: str, *, bold: bool = False, italic: bool = False,
                back: str | None = None) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(theme.color(colour, self.mode)))
            if back:
                f.setBackground(QColor(theme.color(back, self.mode)))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            f.setFontItalic(italic)
            return f

        self.formats = {
            "literal": fmt("ink"),
            "class": fmt("require"),
            "quantifier": fmt("brass", bold=True),
            "group": fmt("ink_muted", bold=True),
            "lookahead": fmt("exclude", bold=True),
            "lookbehind": fmt("exclude", bold=True),
            "anchor": fmt("brass", bold=True),
            "alternation": fmt("brass", bold=True),
            "backref": fmt("warn", bold=True),
            "flags": fmt("ink_faint", italic=True),
            "comment": fmt("ink_faint", italic=True),
            "unrecognised": fmt("fail", back="danger_wash"),
        }

    def highlightBlock(self, text: str) -> None:
        from ..core.explain import tokenise
        try:
            tokens = tokenise(text)
        except Exception:
            return
        for token in tokens:
            fmt = self.formats.get(token.kind)
            if fmt is not None:
                self.setFormat(token.start, token.end - token.start, fmt)


class PatternEdit(QPlainTextEdit):
    """A one-line-ish editor for a pattern, with highlighting and no wrapping."""

    changed = pyqtSignal(str)

    def __init__(self, mode: str = theme.LIGHT, placeholder: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("Mono")
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setPlaceholderText(placeholder)
        self.setTabChangesFocus(True)
        self.setFixedHeight(40)     # room for the text above its scrollbar
        self.highlighter = PatternHighlighter(self.document(), mode)
        self.textChanged.connect(lambda: self.changed.emit(self.toPlainText()))

    def apply_mode(self, mode: str) -> None:
        self.highlighter.set_mode(mode)

    def set_text(self, text: str) -> None:
        if text != self.toPlainText():
            blocked = self.blockSignals(True)
            self.setPlainText(text)
            self.blockSignals(blocked)
            self.highlighter.rehighlight()

    def keyPressEvent(self, event) -> None:
        # Enter would insert a newline into a pattern, which is never wanted.
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            event.ignore()
            return
        super().keyPressEvent(event)


def scrolled(widget: QWidget):
    from PyQt6.QtWidgets import QScrollArea
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(widget)
    # Always off, so the column reflows into whatever width the splitter gives
    # it. Tables and code views carry their own horizontal scrollbars.
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setMinimumWidth(260)
    widget.setMinimumWidth(0)
    return area


def page_body(spacing: int = 16) -> tuple[QWidget, QVBoxLayout]:
    """A page's content column, with the standard page margins."""
    host = QWidget()
    box = QVBoxLayout(host)
    box.setContentsMargins(theme.SPACE["gutter"], theme.SPACE["wide"],
                           theme.SPACE["gutter"], theme.SPACE["wide"])
    box.setSpacing(spacing)
    return host, box
