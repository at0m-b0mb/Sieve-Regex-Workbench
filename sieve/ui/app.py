"""
The window.

A rail on the left with the identity and the pages, a content area on the
right, and one status line. The rail is grouped by what you are doing —
composing, proving, applying — rather than listing features, because the
groups are the argument for the order you should work in.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (QApplication, QButtonGroup, QFileDialog, QFrame,
                             QHBoxLayout, QMainWindow, QMessageBox,
                             QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from ..core.rules import RecipeError
from . import theme
from .marks import SieveMark, mark_pixmap
from .state import AppState
from .widgets import QuietButton, hairline, label
from .pages.about import AboutPage
from .pages.build import BuildPage
from .pages.library import LibraryPage
from .pages.proof import ProofPage
from .pages.read import ReadPage
from .pages.safety import SafetyPage
from .pages.ship import ShipPage
from .pages.sweep import SweepPage

APP_NAME = "Sieve"
TAGLINE = "REGEX WORKBENCH"
VERSION = "1.1.0"

# (group heading, [(page key, label)])
NAV = [
    ("Compose", [("build", "Build"), ("library", "Library"), ("read", "Read")]),
    ("Prove", [("proof", "Proof"), ("safety", "Safety")]),
    ("Apply", [("sweep", "Sweep"), ("ship", "Ship")]),
]


class Window(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.state = AppState()
        self.mode = theme.resolve(self.state.theme_choice)
        self.pages: dict[str, QWidget] = {}
        self.nav_buttons: dict[str, QPushButton] = {}

        self.setWindowTitle(APP_NAME)
        self.resize(1360, 880)
        self.setMinimumSize(1060, 700)
        self.setWindowIcon(self._icon())

        shell = QWidget()
        shell.setObjectName("PageHost")
        outer = QHBoxLayout(shell)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._rail())

        right = QWidget()
        right.setObjectName("PageHost")
        rbox = QVBoxLayout(right)
        rbox.setContentsMargins(0, 0, 0, 0)
        rbox.setSpacing(0)
        rbox.addWidget(self._topbar())
        rbox.addWidget(hairline())
        self.stack = QStackedWidget()
        rbox.addWidget(self.stack, 1)
        rbox.addWidget(hairline())
        rbox.addWidget(self._statusbar())
        outer.addWidget(right, 1)
        self.setCentralWidget(shell)

        self._build_pages()
        self._menus()

        self.state.statusPosted.connect(self._status)
        self.state.recipeChanged.connect(self._update_title)
        self.state.pathChanged.connect(self._update_title)

        self.apply_mode(self.mode)
        self.show_page("build")
        self._update_title()

    # -- chrome --------------------------------------------------------------

    def _icon(self):
        from PyQt6.QtGui import QIcon
        icon = QIcon()
        for size in (16, 32, 64, 128, 256):
            icon.addPixmap(mark_pixmap(size, self.mode))
        return icon

    def _rail(self) -> QWidget:
        rail = QFrame()
        rail.setObjectName("Rail")
        rail.setFixedWidth(206)
        box = QVBoxLayout(rail)
        box.setContentsMargins(0, theme.SPACE["wide"], 0, theme.SPACE["base"])
        box.setSpacing(0)

        self.mark = SieveMark(38, self.mode)
        wordmark = label(APP_NAME.upper(), object_name="Wordmark")
        sub = label(TAGLINE, object_name="WordmarkSub")

        head = QWidget()
        hbox = QVBoxLayout(head)
        hbox.setContentsMargins(theme.SPACE["base"], 0, theme.SPACE["base"], 0)
        hbox.setSpacing(2)
        hbox.addWidget(self.mark)
        hbox.addSpacing(6)
        hbox.addWidget(wordmark)
        hbox.addWidget(sub)
        box.addWidget(head)
        box.addSpacing(theme.SPACE["wide"])

        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        for heading, items in NAV:
            box.addWidget(label(heading.upper(), object_name="NavGroup"))
            for key, text in items:
                button = QPushButton(text)
                button.setObjectName("NavButton")
                button.setCheckable(True)
                button.setCursor(Qt.CursorShape.PointingHandCursor)
                button.clicked.connect(lambda _=False, k=key: self.show_page(k))
                self.group.addButton(button)
                self.nav_buttons[key] = button
                box.addWidget(button)

        box.addStretch(1)
        box.addWidget(hairline())

        about = QPushButton("How it works")
        about.setObjectName("NavButton")
        about.setCheckable(True)
        about.setCursor(Qt.CursorShape.PointingHandCursor)
        about.clicked.connect(lambda: self.show_page("about"))
        self.group.addButton(about)
        self.nav_buttons["about"] = about
        box.addWidget(about)

        self.theme_button = QPushButton()
        self.theme_button.setObjectName("NavButton")
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.clicked.connect(self._cycle_theme)
        box.addWidget(self.theme_button)
        return rail

    def _topbar(self) -> QWidget:
        bar = QWidget()
        box = QHBoxLayout(bar)
        box.setContentsMargins(theme.SPACE["gutter"], theme.SPACE["snug"],
                               theme.SPACE["gutter"], theme.SPACE["snug"])
        box.setSpacing(theme.SPACE["snug"])

        self.doc_name = label("", object_name="CardTitle")
        self.doc_where = label("", object_name="Faint")
        box.addWidget(self.doc_name)
        box.addWidget(self.doc_where)
        box.addStretch(1)

        for text, slot in (("New", self.new_file), ("Open", self.open_file),
                           ("Save", self.save_file)):
            button = QuietButton(text)
            button.clicked.connect(slot)
            box.addWidget(button)
        return bar

    def _statusbar(self) -> QWidget:
        bar = QWidget()
        box = QHBoxLayout(bar)
        box.setContentsMargins(theme.SPACE["gutter"], theme.SPACE["tight"],
                               theme.SPACE["gutter"], theme.SPACE["tight"])
        self.status_label = label("", object_name="Faint")
        self.version_label = label(f"{APP_NAME} {VERSION}", object_name="Faint")
        box.addWidget(self.status_label)
        box.addStretch(1)
        box.addWidget(self.version_label)
        bar.setFixedHeight(26)
        return bar

    # -- pages ---------------------------------------------------------------

    def _build_pages(self) -> None:
        build = BuildPage(self.state, self.mode)
        library = LibraryPage(self.state, self.mode)
        read = ReadPage(self.state, self.mode)
        proof = ProofPage(self.state, self.mode)
        safety = SafetyPage(self.state, self.mode)
        sweep = SweepPage(self.state, self.mode)
        ship = ShipPage(self.state, self.mode)
        about = AboutPage(self.state, self.mode)

        build.goToLibrary.connect(lambda: self.show_page("library"))
        library.ruleTaken.connect(lambda: self.show_page("build"))
        read.loadRequested.connect(lambda: self.show_page("build"))

        for key, page in (("build", build), ("library", library),
                          ("read", read), ("proof", proof),
                          ("safety", safety), ("sweep", sweep),
                          ("ship", ship), ("about", about)):
            self.pages[key] = page
            self.stack.addWidget(page)

    def show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        button = self.nav_buttons.get(key)
        if button is not None and not button.isChecked():
            button.setChecked(True)

    # -- theme ---------------------------------------------------------------

    def _cycle_theme(self) -> None:
        order = [theme.AUTO, theme.LIGHT, theme.DARK]
        nxt = order[(order.index(self.state.theme_choice) + 1) % len(order)]
        self.state.set_theme_choice(nxt)
        self.apply_mode(theme.resolve(nxt))

    def apply_mode(self, mode: str) -> None:
        self.mode = mode
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.stylesheet(mode))
        self.mark.set_mode(mode)
        self.setWindowIcon(self._icon())
        names = {theme.AUTO: "Theme: follow the system",
                 theme.LIGHT: "Theme: paper",
                 theme.DARK: "Theme: black"}
        self.theme_button.setText(names[self.state.theme_choice])
        for page in self.pages.values():
            if hasattr(page, "apply_mode"):
                page.apply_mode(mode)

    # -- documents -----------------------------------------------------------

    def _update_title(self) -> None:
        name = self.state.recipe.name or "Untitled pattern"
        mark = " ·" if self.state.dirty else ""
        self.doc_name.setText(name + mark)
        self.doc_where.setText(
            str(self.state.file_path) if self.state.file_path else "not saved")
        self.setWindowTitle(f"{name} — {APP_NAME}")

    def _confirm_discard(self) -> bool:
        if not self.state.dirty:
            return True
        answer = QMessageBox.question(
            self, "Unsaved changes",
            "This pattern has changes that are not saved. Carry on anyway?",
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel)
        if answer == QMessageBox.StandardButton.Save:
            return self.save_file()
        return answer == QMessageBox.StandardButton.Discard

    def new_file(self) -> None:
        if not self._confirm_discard():
            return
        self.state.new_document()
        self.state.status("New pattern")

    def open_file(self) -> None:
        if not self._confirm_discard():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a Sieve pattern", "", "Sieve patterns (*.sieve *.json)")
        if not path:
            return
        try:
            self.state.load_document(Path(path).read_text(encoding="utf-8"),
                                     Path(path))
            self.state.remember_file(Path(path))
            self.state.status(f"Opened {Path(path).name}", "pass")
        except (OSError, ValueError, RecipeError) as exc:
            QMessageBox.warning(self, "Could not open that file", str(exc))

    def save_file(self) -> bool:
        path = self.state.file_path
        if path is None:
            name = (self.state.recipe.name or "pattern").lower().replace(" ", "-")
            chosen, _ = QFileDialog.getSaveFileName(
                self, "Save the pattern", f"{name}.sieve",
                "Sieve patterns (*.sieve)")
            if not chosen:
                return False
            path = Path(chosen)
        try:
            self.state.save_to(path)
            self.state.remember_file(path)
            self.state.status(f"Saved to {path.name}", "pass")
            return True
        except OSError as exc:
            QMessageBox.warning(self, "Could not save", str(exc))
            return False

    def save_file_as(self) -> None:
        self.state.file_path = None
        self.save_file()

    # -- menus and shortcuts --------------------------------------------------

    def _menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        for text, slot, shortcut in (
                ("New pattern", self.new_file, QKeySequence.StandardKey.New),
                ("Open…", self.open_file, QKeySequence.StandardKey.Open),
                ("Save", self.save_file, QKeySequence.StandardKey.Save),
                ("Save as…", self.save_file_as, QKeySequence.StandardKey.SaveAs)):
            action = QAction(text, self)
            action.setShortcut(shortcut)
            action.triggered.connect(slot)
            file_menu.addAction(action)

        view = bar.addMenu("&View")
        keys = [k for _, items in NAV for k, _ in items] + ["about"]
        for i, key in enumerate(keys, start=1):
            action = QAction(key.title(), self)
            action.setShortcut(QKeySequence(f"Ctrl+{i}"))
            action.triggered.connect(lambda _=False, k=key: self.show_page(k))
            view.addAction(action)
        view.addSeparator()
        cycle = QAction("Change theme", self)
        cycle.setShortcut(QKeySequence("Ctrl+T"))
        cycle.triggered.connect(self._cycle_theme)
        view.addAction(cycle)

    def _status(self, message: str, tone: str = "neutral") -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(
            f"{theme.font_css('small')}"
            f"color: {theme.color(tone if tone in ('pass', 'fail', 'warn') else 'ink_faint', self.mode)};")
        QTimer.singleShot(4200, lambda: self.status_label.setText("")
                          if self.status_label.text() == message else None)

    def closeEvent(self, event) -> None:
        if self._confirm_discard():
            event.accept()
        else:
            event.ignore()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("at0m-b0mb")
    app.setApplicationVersion(VERSION)

    window = Window()
    window.show()

    if len(argv) > 1 and Path(argv[1]).exists():
        try:
            window.state.load_document(
                Path(argv[1]).read_text(encoding="utf-8"), Path(argv[1]))
        except Exception as exc:
            window.state.status(f"Could not open that file: {exc}", "fail")

    return app.exec()
