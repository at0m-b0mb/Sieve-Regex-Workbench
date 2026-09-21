"""
Render the brand assets from the application's own drawing code.

The diagram in the README is produced by the same `draw_flow` the How-it-works
page paints with, through an SVG painter instead of a screen one. That is the
whole point: the picture in the documentation cannot drift from the picture in
the product, because there is only one of them.

    python3 docs/make_assets.py
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
from sieve.ui.marks import draw_flow, paint_mark

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
    flow_desc = ("Sample text passes through three gates in turn — Find, then "
                 "Require, then Exclude — and what survives becomes kept "
                 "lines with captured fields. The Library feeds patterns into "
                 "the gates, Proof cases hold them in place, Safety checks the "
                 "pattern for catastrophic backtracking, and Ship exports it.")
    mark_desc = ("The Sieve mark: a mesh bowl with two grains falling through "
                 "it and one held back on top. Find, and exclude.")
    for mode, suffix in ((theme.LIGHT, "light"), (theme.DARK, "dark")):
        svg(HERE / f"flow-{suffix}.svg", 1040, 560, mode, draw_flow,
            "How Sieve works", flow_desc)
        svg(HERE / f"mark-{suffix}.svg", 160, 160, mode,
            lambda p, r, m: paint_mark(p, r.adjusted(16, 16, -16, -16), m),
            "Sieve", mark_desc)
    del app
    return 0


if __name__ == "__main__":
    sys.exit(main())
