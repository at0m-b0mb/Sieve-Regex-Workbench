"""
Worked examples, shipped with the package.

They live inside `sieve/` rather than at the repository root so that a
`pip install` carries them: the Build page offers them on its empty state,
which is the difference between a first run that produces something and a
first run that produces a blank screen.

Each one passes its own proof cases; CI re-runs them on every push.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def paths() -> list[Path]:
    return sorted(HERE.glob("*.sieve"))


def listing() -> list[tuple[Path, str, str]]:
    """(path, name, intent) for each example, without fully loading it."""
    out = []
    for path in paths():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append((path, data.get("name") or path.stem,
                    data.get("intent") or ""))
    return out
