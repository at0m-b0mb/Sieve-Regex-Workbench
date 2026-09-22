"""
Render the mark from the application's own drawing code.

The flow diagram used to be generated here too, from the same `draw_flow` the
How-it-works page paints with. It was dropped: Qt writes <text> elements naming
real macOS fonts at x/y positions computed for those exact fonts, and GitHub
has neither, so every label drifted. The README uses a Mermaid block instead,
which GitHub renders natively and which stays legible in both its themes. The
in-app diagram is unaffected — it is drawn live, where the fonts exist.

    python3 docs/make_assets.py      # the mark
    python3 docs/make_banner.py      # the banner
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtCore import QRectF, QSize
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtSvg import QSvgGenerator
from PyQt6.QtWidgets import QApplication

from sieve.ui import theme
from sieve.ui.marks import paint_mark

HERE = Path(__file__).resolve().parent


def svg(path: Path, width: int, height: int, mode: str, draw,
        title: str = "Sieve", description: str = "") -> None:
    generator = QSvgGenerator()
    generator.setFileName(str(path))
    generator.setSize(QSize(width, height))
    generator.setViewBox(QRectF(0, 0, width, height))
    generator.setTitle(title)
    # Qt writes "Generated with Qt" into <desc> unless told otherwise, and a
    # <desc> is what a screen reader announces — so it should say what the
    # picture shows rather than what drew it.
    generator.setDescription(description or title)
    painter = QPainter()
    painter.begin(generator)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.fillRect(QRectF(0, 0, width, height),
                     QColor(theme.color("canvas", mode)))
    draw(painter, QRectF(0, 0, width, height), mode)
    painter.end()
    print("wrote", path.name)


def main() -> int:
    app = QApplication(sys.argv)
    mark_desc = ("The Sieve mark: a mesh bowl with two grains falling through "
                 "it and one held back on top. Find, and exclude.")
    for mode, suffix in ((theme.LIGHT, "light"), (theme.DARK, "dark")):
        svg(HERE / f"mark-{suffix}.svg", 160, 160, mode,
            lambda p, r, m: paint_mark(p, r.adjusted(16, 16, -16, -16), m),
            "Sieve", mark_desc)
    del app
    return 0


if __name__ == "__main__":
    sys.exit(main())
