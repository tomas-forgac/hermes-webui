"""Tests for #3635 — profile chip must reflect the ACTIVE profile, not the
loaded session's profile.

Regression from #3331 (shipped v0.51.204): #3331 changed the composer profile
chip label in syncTopbar()'s session-present branch to read
``(S.session&&S.session.profile)||S.activeProfile`` so the label would track the
profile of whatever session was being browsed. But the chip is the profile
*switcher* trigger (it fronts the profile dropdown), and message routing /
new-chat creation both follow the client active profile (the ``hermes_profile``
cookie, set only by ``/api/profile/switch``). ``loadSession()`` sets
``S.session`` but never updates ``S.activeProfile``, so opening a session that
belongs to a different profile than the active one made the chip diverge from
the dropdown checkmark and misrepresent where the next message would route.

The fix reverts JUST the chip label to ``S.activeProfile`` in both syncTopbar
branches. #3331's legitimate project/session-operation scoping (which keys on
the session's own profile) is unrelated to this line and stays in place.
"""

from pathlib import Path

import re


def _ui_js() -> str:
    return (Path(__file__).parent.parent / "static" / "ui.js").read_text(encoding="utf-8")


def _sync_topbar_body(src: str) -> str:
    """Return the full source of the syncTopbar() function."""
    start = src.find("function syncTopbar(){")
    assert start != -1, "syncTopbar function not found in ui.js"
    # Walk braces to find the matching close.
    i = src.find("{", start)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start : j + 1]
    raise AssertionError("could not find end of syncTopbar()")


class TestIssue3635ProfileChipActive:
    def test_session_present_chip_reads_active_profile(self):
        """The session-present chip-label update must read S.activeProfile."""
        body = _sync_topbar_body(_ui_js())
        # There are two profileChipLabel updates: the !S.session early-return
        # block and the session-present block. Both must key on S.activeProfile.
        updates = re.findall(
            r"profileChipLabel'\);\s*\n\s*if\([^)]*\)\s*[^.]*\.textContent=([^;]+);",
            body,
        )
        assert updates, "no profileChipLabel textContent assignment found in syncTopbar"
        for expr in updates:
            assert "S.activeProfile" in expr, (
                "profile chip label must read S.activeProfile, got: " + expr.strip()
            )

    def test_chip_does_not_key_on_session_profile(self):
        """Forbid the #3331 regression shape: chip keying on S.session.profile.

        This negative assertion stops a future change from re-pointing the
        switcher-trigger chip at the loaded session's profile (#3635).
        """
        body = _sync_topbar_body(_ui_js())
        assert "(S.session&&S.session.profile)||S.activeProfile" not in body, (
            "profile chip label must NOT key on S.session.profile — that is the "
            "#3331 regression that made the chip diverge from the active profile "
            "and misrepresent message routing (#3635)."
        )
        # Also guard the spaced variant.
        assert "(S.session && S.session.profile) || S.activeProfile" not in body, (
            "profile chip label must NOT key on S.session.profile (#3635)."
        )

    def test_both_chip_setters_consistent(self):
        """Both the no-session and session-present chip setters must agree.

        Before the fix the early-return (no session) branch read S.activeProfile
        while the session-present branch read S.session.profile — the
        inconsistency was the bug. They must now be identical.
        """
        body = _sync_topbar_body(_ui_js())
        setters = re.findall(r"\.textContent=(S\.activeProfile\|\|'default')", body)
        assert len(setters) >= 2, (
            "expected both syncTopbar chip-label setters to read "
            "S.activeProfile||'default'; found: " + str(setters)
        )
