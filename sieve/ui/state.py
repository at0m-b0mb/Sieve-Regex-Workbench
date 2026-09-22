"""
What the window is working on.

One object holds the recipe, the proof cases and the sample text; every page
reads from it and writes to it, and anything that changes emits a signal. The
alternative — pages owning fragments of the state and syncing on tab change —
is where this kind of application usually starts leaking.
"""

from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import QObject, QSettings, pyqtSignal

from ..core.proof import Case, Suite
from ..core.rules import Recipe, Rule
from ..core import samples

ORG = "at0m-b0mb"
APP = "Sieve"


class AppState(QObject):
    recipeChanged = pyqtSignal()
    sampleChanged = pyqtSignal()
    suiteChanged = pyqtSignal()
    themeChanged = pyqtSignal(str)
    pathChanged = pyqtSignal()
    statusPosted = pyqtSignal(str, str)      # message, tone

    def __init__(self) -> None:
        super().__init__()
        self.settings = QSettings(ORG, APP)
        self.recipe = Recipe()
        self.suite = Suite()
        self.sample_text = samples.SSH.text
        self.sample_id = samples.SSH.id
        self.file_path: Path | None = None
        self._dirty = False
        self.theme_choice = self.settings.value("theme", "auto")
        # Deleting a rule you spent ten minutes on used to be final. One level
        # of undo per destructive action, bounded, with the wording to show in
        # the status line when it is used.
        self._undo: list[tuple[str, object]] = []

    # -- theme ---------------------------------------------------------------

    def set_theme_choice(self, choice: str) -> None:
        self.theme_choice = choice
        self.settings.setValue("theme", choice)     # the choice, not the result
        self.themeChanged.emit(choice)

    # -- mutation ------------------------------------------------------------

    def touch(self) -> None:
        self._dirty = True
        self.recipeChanged.emit()

    @property
    def dirty(self) -> bool:
        return self._dirty

    def add_rule(self, rule: Rule) -> None:
        self.recipe.rules.append(rule)
        self.touch()

    def remove_rule(self, index: int) -> None:
        if 0 <= index < len(self.recipe.rules):
            rule = self.recipe.rules.pop(index)
            self._push_undo(
                f"Restored the rule “{rule.label or rule.pattern[:24]}”",
                lambda: self.recipe.rules.insert(min(index, len(self.recipe.rules)), rule))
            self.touch()

    def _push_undo(self, message: str, restore) -> None:
        self._undo.append((message, restore))
        del self._undo[:-20]

    @property
    def can_undo(self) -> bool:
        return bool(self._undo)

    def undo(self) -> str:
        """Put back whatever was last removed. Returns what to tell the user."""
        if not self._undo:
            return ""
        message, restore = self._undo.pop()
        restore()
        self.touch()
        self.suiteChanged.emit()
        return message

    def move_rule(self, index: int, delta: int) -> None:
        target = index + delta
        rules = self.recipe.rules
        if 0 <= index < len(rules) and 0 <= target < len(rules):
            rules[index], rules[target] = rules[target], rules[index]
            self.touch()

    def set_sample(self, text: str, sample_id: str = "") -> None:
        self.sample_text = text
        self.sample_id = sample_id
        self.sampleChanged.emit()

    def add_case(self, case: Case) -> None:
        self.suite.cases.append(case)
        self._dirty = True
        self.suiteChanged.emit()

    def remove_case(self, index: int) -> None:
        if 0 <= index < len(self.suite.cases):
            case = self.suite.cases.pop(index)
            self._push_undo(
                "Restored the proof case",
                lambda: self.suite.cases.insert(
                    min(index, len(self.suite.cases)), case))
            self._dirty = True
            self.suiteChanged.emit()

    def status(self, message: str, tone: str = "neutral") -> None:
        self.statusPosted.emit(message, tone)

    # -- files ---------------------------------------------------------------

    def to_document(self) -> str:
        doc = self.recipe.to_dict()
        doc["proof"] = self.suite.to_list()
        if self.sample_id:
            doc["sample"] = self.sample_id
        return json.dumps(doc, indent=2)

    def load_document(self, text: str, path: Path | None = None) -> None:
        data = json.loads(text)
        self.recipe = Recipe.from_dict(data)
        self.suite = Suite.from_list(data.get("proof", []))
        sample_id = data.get("sample")
        if sample_id and sample_id in samples.BY_ID:
            self.sample_text = samples.BY_ID[sample_id].text
            self.sample_id = sample_id
        self.file_path = path
        self._dirty = False
        self.recipeChanged.emit()
        self.suiteChanged.emit()
        self.sampleChanged.emit()
        self.pathChanged.emit()

    def save_to(self, path: Path) -> None:
        path.write_text(self.to_document(), encoding="utf-8")
        self.file_path = path
        self._dirty = False
        self.pathChanged.emit()

    def new_document(self) -> None:
        self.recipe = Recipe()
        self.suite = Suite()
        self.file_path = None
        self._dirty = False
        self.recipeChanged.emit()
        self.suiteChanged.emit()
        self.pathChanged.emit()

    # -- recents -------------------------------------------------------------

    def recent_files(self) -> list[str]:
        value = self.settings.value("recent", [])
        return [v for v in (value or []) if Path(v).exists()][:8]

    def remember_file(self, path: Path) -> None:
        recents = [str(path)] + [r for r in self.recent_files() if r != str(path)]
        self.settings.setValue("recent", recents[:8])
