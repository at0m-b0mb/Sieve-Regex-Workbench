"""
Contrast.

Not ceremony. Checking these by eye passes pairings that fail, and this suite
has already caught two of them — the brass accent was illegible on the two
darker grounds in the light theme until it was measured.
"""

import pytest

from sieve.ui import theme

TEXT_TOKENS = ["ink", "ink_muted", "ink_faint", "brass", "find", "require",
               "exclude", "pass", "fail", "warn", "danger"]
GROUNDS = ["canvas", "surface", "surface_alt", "sunken", "rail"]
WASHES = {"find": "find_wash", "require": "require_wash",
          "exclude": "exclude_wash", "danger": "danger_wash",
          "warn": "warn_wash", "pass": "pass_wash"}

# WCAG AA: 4.5:1 for body text. ink_faint is only ever used at large sizes or
# for decoration, so it is held to the 3:1 large-text threshold.
def _required(token: str) -> float:
    return 3.0 if token == "ink_faint" else 4.5


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("token", TEXT_TOKENS)
@pytest.mark.parametrize("ground", GROUNDS)
def test_text_is_legible_on_every_ground(mode, token, ground):
    ratio = theme.contrast(theme.color(token, mode), theme.color(ground, mode))
    assert ratio >= _required(token), (
        f"{token} on {ground} in {mode}: {ratio:.2f}:1")


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("token,wash", sorted(WASHES.items()))
def test_badge_text_is_legible_on_its_own_wash(mode, token, wash):
    ratio = theme.contrast(theme.color(token, mode), theme.color(wash, mode))
    assert ratio >= 4.5, f"{token} on {wash} in {mode}: {ratio:.2f}:1"


def test_dark_mode_is_true_black_and_never_blue():
    assert theme.color("canvas", theme.DARK) == "#000000"
    for name, pair in theme.PALETTE.items():
        hexcode = pair.dark.lstrip("#")
        r, g, b = (int(hexcode[i:i + 2], 16) for i in (0, 2, 4))
        assert b <= max(r, g) + 12, f"{name} reads as blue in the dark theme"


def test_every_colour_declares_both_themes():
    for name, pair in theme.PALETTE.items():
        assert pair.light.startswith("#") and len(pair.light) == 7, name
        assert pair.dark.startswith("#") and len(pair.dark) == 7, name


def test_there_are_two_golds_and_they_differ():
    for mode in (theme.LIGHT, theme.DARK):
        assert theme.color("brass", mode) != theme.color("shine", mode)


def test_stylesheet_builds_for_both_modes():
    for mode in (theme.LIGHT, theme.DARK):
        sheet = theme.stylesheet(mode)
        assert "QPushButton" in sheet
        assert "{{" not in sheet, "an unescaped brace leaked into the QSS"
