"""
The repository banner.

Hand-written SVG rather than QPainter output, for one concrete reason: Qt's
generator emits <text> elements naming real macOS fonts ("SF Pro Text",
"Iowan Old Style") at x/y positions it computed for those exact fonts. GitHub
has neither, so the fallback renders at the wrong widths and the layout drifts.
Web-safe stacks and centred anchors survive anywhere.

    python3 docs/make_banner.py
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent

SERIF = "Georgia, 'Iowan Old Style', 'Times New Roman', serif"
SANS = ("-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Helvetica, "
        "Arial, sans-serif")

THEMES = {
    "light": dict(bg="#F3F1EC", ink="#1B1813", muted="#575144", faint="#847D6E",
                  brass="#7A5D18", shine="#C39B24", rule="#DCD6C9",
                  card="#FFFFFF"),
    "dark": dict(bg="#000000", ink="#F3F0E9", muted="#A29C91", faint="#6B675F",
                 brass="#D9B75C", shine="#F1C84B", rule="#2B2B28",
                 card="#131312"),
}

W, H = 1280, 420


def mark(cx: float, cy: float, size: float, c: dict) -> str:
    """The sieve mark: a mesh bowl, two grains through it, one held back."""
    u = size / 100.0
    x0, y0 = cx - size / 2, cy - size / 2

    def P(ux, uy):
        return f"{x0 + ux * u:.2f},{y0 + uy * u:.2f}"

    bowl = (f"M{P(12,34)} L{P(88,34)} "
            f"C{P(88,74)} {P(66,88)} {P(50,88)} "
            f"C{P(34,88)} {P(12,74)} {P(12,34)} Z")
    mesh = []
    for i in range(1, 7):
        y = 34 + i * 8.6
        mesh.append(f'<line x1="{P(10,y).split(",")[0]}" y1="{P(10,y).split(",")[1]}"'
                    f' x2="{P(90,y).split(",")[0]}" y2="{P(90,y).split(",")[1]}"/>')
    for i in range(1, 9):
        x = 12 + i * 8.6
        mesh.append(f'<line x1="{P(x,32).split(",")[0]}" y1="{P(x,32).split(",")[1]}"'
                    f' x2="{P(x,90).split(",")[0]}" y2="{P(x,90).split(",")[1]}"/>')
    gx, gy = P(50, 40).split(",")
    d1x, d1y = P(37, 97).split(",")
    d2x, d2y = P(63, 101).split(",")
    return f"""
  <g>
    <clipPath id="bowl"><path d="{bowl}"/></clipPath>
    <g clip-path="url(#bowl)" stroke="{c['brass']}" stroke-width="{1.15*u:.2f}"
       opacity="0.9">
      {''.join(mesh)}
    </g>
    <path d="{bowl}" fill="none" stroke="{c['brass']}"
          stroke-width="{2.4*u:.2f}" stroke-linejoin="round"/>
    <circle cx="{gx}" cy="{gy}" r="{5*u:.2f}" fill="{c['shine']}"/>
    <circle cx="{d1x}" cy="{d1y}" r="{2.6*u:.2f}" fill="{c['ink']}" opacity="0.5"/>
    <circle cx="{d2x}" cy="{d2y}" r="{2.0*u:.2f}" fill="{c['ink']}" opacity="0.28"/>
  </g>"""


def grains(c: dict) -> str:
    """Faint falling grains either side — the motif, not decoration for its own sake."""
    out = []
    seeds = [(96, 128, 3.0, .22), (168, 250, 2.2, .16), (60, 300, 2.6, .12),
             (210, 92, 2.0, .14), (132, 344, 1.8, .10),
             (1184, 132, 3.0, .22), (1112, 262, 2.2, .16), (1220, 308, 2.6, .12),
             (1070, 96, 2.0, .14), (1148, 350, 1.8, .10)]
    for x, y, r, o in seeds:
        out.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{c["brass"]}" opacity="{o}"/>')
    return "".join(out)


def banner(c: dict) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}"
     width="{W}" height="{H}" role="img"
     aria-label="Sieve — a regex workbench for security work">
  <title>Sieve</title>
  <desc>The Sieve wordmark: a mesh bowl with two grains falling through it and
  one held back, above the word SIEVE and the line "a regex workbench for
  security work".</desc>

  <rect width="{W}" height="{H}" fill="{c['bg']}"/>
  {grains(c)}

  <!-- a hairline frame, inset -->
  <rect x="28" y="28" width="{W-56}" height="{H-56}" fill="none"
        stroke="{c['rule']}" stroke-width="1"/>

  {mark(W/2, 138, 96, c)}

  <text x="{W/2}" y="264" text-anchor="middle" font-family="{SERIF}"
        font-size="68" font-weight="600" letter-spacing="18"
        fill="{c['ink']}">SIEVE</text>

  <line x1="{W/2-110}" y1="292" x2="{W/2+110}" y2="292"
        stroke="{c['shine']}" stroke-width="1.5"/>

  <text x="{W/2}" y="326" text-anchor="middle" font-family="{SANS}"
        font-size="16" letter-spacing="3.2" fill="{c['muted']}">
    A REGEX WORKBENCH FOR SECURITY WORK
  </text>

  <text x="{W/2}" y="364" text-anchor="middle" font-family="{SANS}"
        font-size="11.5" letter-spacing="4.5" fill="{c['faint']}">
    BUILD &#183; PROVE &#183; CHECK &#183; SHIP
  </text>
</svg>
"""


def main() -> int:
    for name, c in THEMES.items():
        path = HERE / f"banner-{name}.svg"
        path.write_text(banner(c), encoding="utf-8")
        print("wrote", path.name, f"({path.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
