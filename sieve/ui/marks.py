"""
The drawn things.

Four widgets that paint rather than compose, because none of them could be
built out of stock controls:

  SieveMark    the identity — a mesh with grains falling through it, and one
               caught. It is the product's whole idea in twelve strokes.
  MatchMap     a core sample of the corpus: one hairline per line, coloured by
               verdict. Scroll position rides along it. Nothing else in a
               regex tool shows you the shape of your own data.
  GrowthCurve  measured runtime against input length, from the ReDoS probe.
               Real numbers, not a stock illustration of a hockey stick.
  FlowChart    how a pattern travels through the application.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (QBrush, QColor, QFont, QFontMetrics, QPainter,
                         QPainterPath, QPen, QPixmap, QPolygonF)
from PyQt6.QtWidgets import QSizePolicy, QWidget

from . import theme


def _c(name: str, mode: str) -> QColor:
    return QColor(theme.color(name, mode))


# --- identity ---------------------------------------------------------------

def paint_mark(painter: QPainter, rect: QRectF, mode: str,
               *, grains: bool = True) -> None:
    """The Sieve mark: a mesh, two grains through it, one held back.

    Drawn from a unit square so it is sharp at any size — the window icon and
    the 96px wordmark are the same code.
    """
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    size = min(rect.width(), rect.height())
    x0 = rect.x() + (rect.width() - size) / 2
    y0 = rect.y() + (rect.height() - size) / 2
    u = size / 100.0

    def P(ux: float, uy: float) -> QPointF:
        return QPointF(x0 + ux * u, y0 + uy * u)

    brass = _c("brass", mode)
    shine = _c("shine", mode)
    ink = _c("ink", mode)

    # The rim: a shallow bowl, open at the top.
    rim = QPainterPath()
    rim.moveTo(P(12, 34))
    rim.lineTo(P(88, 34))
    rim.cubicTo(P(88, 74), P(66, 88), P(50, 88))
    rim.cubicTo(P(34, 88), P(12, 74), P(12, 34))
    painter.setPen(QPen(brass, 2.2 * u / 10 * 10 / 3, Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.setPen(QPen(brass, max(1.4, 2.4 * u)))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(rim)

    # The mesh, clipped to the bowl.
    painter.save()
    painter.setClipPath(rim)
    painter.setPen(QPen(brass, max(0.8, 1.15 * u)))
    for i in range(1, 7):
        y = 34 + i * 8.6
        painter.drawLine(P(10, y), P(90, y))
    for i in range(1, 9):
        x = 12 + i * 8.6
        painter.drawLine(P(x, 32), P(x, 90))
    painter.restore()

    if not grains:
        painter.restore()
        return

    # One grain held on the mesh — the thing you were looking for.
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(shine))
    r = 5.0 * u
    painter.drawEllipse(P(50, 40), r, r)

    # Two grains already through, falling away.
    painter.setBrush(QBrush(ink))
    painter.setOpacity(0.55)
    painter.drawEllipse(P(37, 95), 2.6 * u, 2.6 * u)
    painter.setOpacity(0.3)
    painter.drawEllipse(P(63, 99), 2.0 * u, 2.0 * u)
    painter.setOpacity(1.0)
    painter.restore()


class SieveMark(QWidget):
    """The mark, on its own, at whatever size the layout gives it."""

    def __init__(self, size: int = 34, mode: str = theme.LIGHT, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.setFixedSize(size, size)
        self.setAccessibleName("Sieve")
        self.setAccessibleDescription(
            "The Sieve mark: a mesh bowl with two grains falling through it "
            "and one held back on top.")

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        paint_mark(painter, QRectF(self.rect()), self.mode)
        painter.end()


def mark_pixmap(size: int, mode: str) -> QPixmap:
    """The mark as a pixmap, for the window and taskbar icon."""
    pm = QPixmap(size, size)
    pm.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pm)
    paint_mark(painter, QRectF(0, 0, size, size), mode)
    painter.end()
    return pm


# --- the match map ----------------------------------------------------------

@dataclass
class MapRow:
    verdict: str
    weight: int = 0        # how many matches on the line


class MatchMap(QWidget):
    """One hairline per line of the corpus, coloured by what happened to it.

    At a glance: are the hits clustered or spread, did an Exclude rule eat a
    whole region, is the pattern firing on every line (which almost always
    means it is too loose). A scrollbar tells you where you are; this tells
    you what is there.
    """

    lineClicked = pyqtSignal(int)

    def __init__(self, mode: str = theme.LIGHT, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.rows: list[MapRow] = []
        self.viewport_range: tuple[int, int] = (0, 0)
        self.setMinimumWidth(30)
        self.setMaximumWidth(30)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Every line of the sample, in order. Click to jump.")
        # This widget is pure QPainter, so without an explicit description a
        # screen reader finds nothing here at all — not even that it exists.
        self.setAccessibleName("Match map")
        self._describe()

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.update()

    def set_rows(self, rows: list[MapRow]) -> None:
        self.rows = rows
        self._describe()
        self.update()

    def _describe(self) -> None:
        """Say in words what the ribbon shows, for anything that cannot see it."""
        from ..core import matcher
        if not self.rows:
            self.setAccessibleDescription(
                "A map of the sample, one mark per line. Nothing loaded yet.")
            return
        counts: dict[str, int] = {}
        for row in self.rows:
            counts[row.verdict] = counts.get(row.verdict, 0) + 1
        parts = [f"{n} {matcher.VERDICT_LABEL[v].lower()}"
                 for v, n in counts.items() if n]
        self.setAccessibleDescription(
            f"A map of {len(self.rows)} lines, one mark each, in order: "
            + ", ".join(parts) + ".")

    def set_viewport(self, first: int, last: int) -> None:
        self.viewport_range = (first, last)
        self.update()

    def mousePressEvent(self, event) -> None:
        if not self.rows:
            return
        frac = max(0.0, min(1.0, (event.position().y() - 6) / max(1, self.height() - 12)))
        self.lineClicked.emit(int(frac * len(self.rows)))

    def paintEvent(self, event) -> None:
        from ..core import matcher
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.fillRect(self.rect(), _c("sunken", self.mode))

        if not self.rows:
            painter.end()
            return

        pad = 6
        n = len(self.rows)
        available = max(1, self.height() - pad * 2)
        # Cap how tall one line may be, so a short sample reads as a short
        # ribbon rather than a stretched bar chart.
        height = min(available, n * 6)
        bar_h = max(1.0, height / n)
        colours = {
            matcher.KEPT: _c("shine", self.mode),
            matcher.EXCLUDED: _c("exclude", self.mode),
            matcher.MISSING_REQUIRE: _c("warn", self.mode),
            matcher.NO_MATCH: _c("rule_strong", self.mode),
        }

        for i, row in enumerate(self.rows):
            y = pad + i * height / n
            colour = colours.get(row.verdict, colours[matcher.NO_MATCH])
            if row.verdict == matcher.NO_MATCH:
                # Misses are drawn short and faint: present, not shouting.
                painter.fillRect(QRectF(11, y, 8, bar_h), colour)
            else:
                width = 20 if row.verdict == matcher.KEPT else 14
                painter.fillRect(QRectF(5, y, width, max(1.2, bar_h)), colour)

        first, last = self.viewport_range
        if last > first:
            y0 = pad + first * height / n
            y1 = pad + min(n, last) * height / n
            pen = QPen(_c("ink", self.mode), 1)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(QRectF(1.5, y0, self.width() - 3, max(3.0, y1 - y0)))
        painter.end()


# --- the growth curve -------------------------------------------------------

class GrowthCurve(QWidget):
    """Measured seconds against input length, on log axes.

    A straight line at 45 degrees is linear time. Steeper is the warning. The
    numbers come from the probe actually running the user's pattern, which is
    why this is evidence rather than decoration.
    """

    def __init__(self, mode: str = theme.LIGHT, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.points: list[tuple[int, float, bool]] = []
        self.caption = ""
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAccessibleName("Measured runtime")
        self.setAccessibleDescription("No measurements yet.")

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.update()

    def set_points(self, points, caption: str = "") -> None:
        self.points = [(p.length, max(p.seconds, 1e-7), p.timed_out) for p in points]
        self.caption = caption
        if self.points:
            first, last = self.points[0], self.points[-1]
            self.setAccessibleDescription(
                f"Measured runtime against input length, on log scales. "
                f"At {first[0]} characters the pattern took "
                f"{first[1] * 1000:.2f} milliseconds; at {last[0]} characters, "
                f"{last[1] * 1000:.2f} milliseconds."
                + (" The probe hit its time limit." if last[2] else ""))
        else:
            self.setAccessibleDescription("No measurements yet.")
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.fillRect(rect, _c("surface", self.mode))
        painter.setPen(QPen(_c("rule", self.mode), 1))
        painter.drawRect(rect)

        font = QFont(theme.MONO.split(",")[0], 8)
        painter.setFont(font)

        if len(self.points) < 2:
            painter.setPen(_c("ink_faint", self.mode))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter,
                             "Not enough measurements to plot")
            painter.end()
            return

        pad_l, pad_r, pad_t, pad_b = 44, 12, 14, 26
        plot = QRectF(rect.x() + pad_l, rect.y() + pad_t,
                      rect.width() - pad_l - pad_r, rect.height() - pad_t - pad_b)

        xs = [math.log10(max(1, p[0])) for p in self.points]
        ys = [math.log10(p[1]) for p in self.points]
        x_lo, x_hi = min(xs), max(xs)
        y_lo, y_hi = min(ys), max(ys)
        if x_hi - x_lo < 0.4:
            x_hi = x_lo + 0.4
        if y_hi - y_lo < 0.8:
            y_lo, y_hi = y_lo - 0.4, y_hi + 0.4

        def to_px(lx: float, ly: float) -> QPointF:
            fx = (lx - x_lo) / (x_hi - x_lo)
            fy = (ly - y_lo) / (y_hi - y_lo)
            return QPointF(plot.x() + fx * plot.width(),
                           plot.bottom() - fy * plot.height())

        # Grid: one line per decade.
        painter.setPen(QPen(_c("rule", self.mode), 1, Qt.PenStyle.DotLine))
        for decade in range(int(math.floor(y_lo)), int(math.ceil(y_hi)) + 1):
            if not (y_lo <= decade <= y_hi):
                continue
            p = to_px(x_lo, decade)
            painter.drawLine(QPointF(plot.x(), p.y()), QPointF(plot.right(), p.y()))
            painter.setPen(_c("ink_faint", self.mode))
            label = f"{10 ** decade:g}s" if decade >= -3 else f"1e{decade}s"
            painter.drawText(QRectF(rect.x() + 2, p.y() - 7, pad_l - 6, 14),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             label)
            painter.setPen(QPen(_c("rule", self.mode), 1, Qt.PenStyle.DotLine))

        # A linear-time reference, anchored at the first measurement.
        painter.setPen(QPen(_c("ink_faint", self.mode), 1, Qt.PenStyle.DashLine))
        ref_start = to_px(x_lo, ys[0])
        ref_end = to_px(x_hi, ys[0] + (x_hi - x_lo))
        painter.drawLine(ref_start, ref_end)
        painter.setPen(_c("ink_faint", self.mode))
        painter.drawText(QRectF(ref_end.x() - 60, ref_end.y() - 14, 58, 12),
                         Qt.AlignmentFlag.AlignRight, "linear")

        # The measured curve.
        path = QPainterPath()
        for i, (length, seconds, _) in enumerate(self.points):
            p = to_px(math.log10(max(1, length)), math.log10(seconds))
            path.moveTo(p) if i == 0 else path.lineTo(p)
        blew = any(p[2] for p in self.points)
        line = _c("danger" if blew else "brass", self.mode)
        painter.setPen(QPen(line, 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        painter.setPen(Qt.PenStyle.NoPen)
        for length, seconds, timed_out in self.points:
            p = to_px(math.log10(max(1, length)), math.log10(seconds))
            painter.setBrush(_c("danger" if timed_out else "shine", self.mode))
            painter.drawEllipse(p, 3.0, 3.0)

        painter.setPen(_c("ink_faint", self.mode))
        painter.drawText(QRectF(plot.x(), rect.bottom() - 20, plot.width(), 14),
                         Qt.AlignmentFlag.AlignLeft,
                         f"{self.points[0][0]} chars")
        painter.drawText(QRectF(plot.x(), rect.bottom() - 20, plot.width(), 14),
                         Qt.AlignmentFlag.AlignRight,
                         f"{self.points[-1][0]} chars")
        if self.caption:
            painter.setPen(_c("ink_muted", self.mode))
            painter.drawText(QRectF(plot.x(), rect.bottom() - 20, plot.width(), 14),
                             Qt.AlignmentFlag.AlignHCenter, self.caption)
        painter.end()


# --- the flow chart ---------------------------------------------------------

@dataclass
class Node:
    x: float
    y: float
    w: float
    h: float
    title: str
    body: str = ""
    kind: str = "stage"        # stage | gate | source | sink | tool


# Laid out on a 1000 x 560 virtual canvas and scaled to fit, so the diagram is
# identical at every window size and in the exported SVG.
CANVAS = (1040.0, 560.0)

NODES: list[Node] = [
    Node(30, 230, 150, 84, "Sample text",
         "A built-in corpus,\nor your own paste", "source"),
    Node(30, 60, 150, 76, "Library",
         "57 security patterns,\neach with its caveat", "tool"),
    Node(30, 400, 150, 76, "Proof cases",
         "Should match.\nShould not match.", "tool"),

    Node(250, 214, 150, 116, "FIND", "What the match\nis made of", "gate"),
    Node(470, 214, 150, 116, "REQUIRE", "Must also be\non the line", "gate"),
    Node(690, 214, 150, 116, "EXCLUDE", "Throws the\nline away", "gate"),

    Node(890, 214, 140, 116, "Kept lines",
         "With the fields\nyou captured", "sink"),

    Node(470, 60, 370, 76, "Safety",
         "Static read plus a timed probe \u2014 does this pattern blow up?", "tool"),
    Node(470, 400, 370, 76, "Ship",
         "19 targets. No lookaround in the flavor? A two-pass pipeline.", "tool"),
]

EDGES: list[tuple[int, int, str]] = [
    (0, 3, ""),
    (3, 4, "matched"),
    (4, 5, "required"),
    (5, 6, "survived"),
    (1, 3, "insert"),
    (2, 3, "prove"),
    (3, 7, ""),
    (5, 8, ""),
]


class FlowChart(QWidget):
    """How a pattern travels through Sieve, drawn rather than described."""

    def __init__(self, mode: str = theme.LIGHT, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.setMinimumHeight(360)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAccessibleName("How Sieve works")
        self.setAccessibleDescription(
            "Sample text passes through three gates in turn — Find, then "
            "Require, then Exclude — and what survives becomes kept lines with "
            "captured fields. The Library feeds patterns into the gates, Proof "
            "cases hold them in place, Safety checks the pattern for "
            "catastrophic backtracking, and Ship exports it.")

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        draw_flow(painter, QRectF(self.rect()), self.mode)
        painter.end()


def _node_colours(kind: str, mode: str) -> tuple[QColor, QColor, QColor]:
    """(fill, border, ink) for each kind of box."""
    if kind == "gate":
        return (_c("surface", mode), _c("brass", mode), _c("ink", mode))
    if kind == "source":
        return (_c("surface_alt", mode), _c("rule_strong", mode), _c("ink", mode))
    if kind == "sink":
        return (_c("brass_wash", mode), _c("brass", mode), _c("ink", mode))
    if kind == "tool":
        return (_c("surface_alt", mode), _c("rule", mode), _c("ink_muted", mode))
    return (_c("surface", mode), _c("rule", mode), _c("ink", mode))


def draw_flow(painter: QPainter, rect: QRectF, mode: str) -> None:
    """Paint the flow chart into `rect`, scaled to fit and centred."""
    cw, ch = CANVAS
    scale = min(rect.width() / cw, rect.height() / ch)
    ox = rect.x() + (rect.width() - cw * scale) / 2
    oy = rect.y() + (rect.height() - ch * scale) / 2

    def R(n: Node) -> QRectF:
        return QRectF(ox + n.x * scale, oy + n.y * scale,
                      n.w * scale, n.h * scale)

    title_font = QFont(theme.SANS.split(",")[0])
    title_font.setPixelSize(max(9, int(13 * scale)))
    title_font.setWeight(QFont.Weight.DemiBold)
    body_font = QFont(theme.SANS.split(",")[0])
    body_font.setPixelSize(max(8, int(10.5 * scale)))
    edge_font = QFont(theme.SANS.split(",")[0])
    edge_font.setPixelSize(max(7, int(9 * scale)))

    # --- edges first, so boxes sit on top ---------------------------------
    for a, b, label in EDGES:
        na, nb = NODES[a], NODES[b]
        ra, rb = R(na), R(nb)
        horizontal = abs(na.y - nb.y) < 40

        if horizontal:
            start = QPointF(ra.right(), ra.center().y())
            end = QPointF(rb.left(), rb.center().y())
            path = QPainterPath(start)
            path.lineTo(end)
        else:
            # An elbow: out of the side, then vertically into the face.
            if na.y < nb.y:
                start = QPointF(ra.center().x(), ra.bottom())
                end = QPointF(rb.center().x(), rb.top())
            else:
                start = QPointF(ra.center().x(), ra.top())
                end = QPointF(rb.center().x(), rb.bottom())
            mid = (start.y() + end.y()) / 2
            path = QPainterPath(start)
            path.lineTo(QPointF(start.x(), mid))
            path.lineTo(QPointF(end.x(), mid))
            path.lineTo(end)

        dashed = NODES[a].kind == "tool" or NODES[b].kind == "tool"
        pen = QPen(_c("rule_strong" if dashed else "brass", mode),
                   max(1.0, 1.6 * scale))
        if dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Arrow head at the end, pointing the way the path arrives.
        head = max(3.0, 5.0 * scale)
        if horizontal:
            tip = end
            tri = QPolygonF([tip, QPointF(tip.x() - head * 1.6, tip.y() - head),
                             QPointF(tip.x() - head * 1.6, tip.y() + head)])
        else:
            tip = end
            direction = 1 if na.y < nb.y else -1
            tri = QPolygonF([tip,
                             QPointF(tip.x() - head, tip.y() - head * 1.6 * direction),
                             QPointF(tip.x() + head, tip.y() - head * 1.6 * direction)])
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(_c("rule_strong" if dashed else "brass", mode))
        painter.drawPolygon(tri)

        if label:
            painter.setFont(edge_font)
            mid_pt = path.pointAtPercent(0.5)
            metrics = QFontMetrics(edge_font)
            width = metrics.horizontalAdvance(label) + 8
            height = metrics.height() + 2
            box = QRectF(mid_pt.x() - width / 2,
                         mid_pt.y() - (16 * scale + height if horizontal
                                       else height / 2),
                         width, height)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(_c("surface", mode))
            painter.drawRect(box)
            painter.setPen(_c("ink_faint", mode))
            painter.drawText(box, Qt.AlignmentFlag.AlignCenter, label)

    # --- boxes -------------------------------------------------------------
    for node in NODES:
        r = R(node)
        fill, border, ink = _node_colours(node.kind, mode)
        painter.setPen(QPen(border, max(1.0, (2.0 if node.kind == "gate" else 1.0) * scale)))
        painter.setBrush(fill)
        painter.drawRoundedRect(r, 5 * scale, 5 * scale)

        if node.kind == "gate":
            # A gold shoulder marks the three stages that are the pipeline.
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(_c("shine", mode))
            painter.drawRoundedRect(QRectF(r.x(), r.y(), r.width(), 3.5 * scale),
                                    2 * scale, 2 * scale)

        painter.setFont(title_font)
        painter.setPen(ink)
        title_h = 22 * scale
        painter.drawText(QRectF(r.x(), r.y() + 9 * scale, r.width(), title_h),
                         Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                         node.title)
        if node.body:
            painter.setFont(body_font)
            painter.setPen(_c("ink_muted", mode))
            painter.drawText(
                QRectF(r.x() + 8 * scale, r.y() + 9 * scale + title_h,
                       r.width() - 16 * scale, r.height() - title_h - 14 * scale),
                int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop
                    | Qt.TextFlag.TextWordWrap),
                node.body)
