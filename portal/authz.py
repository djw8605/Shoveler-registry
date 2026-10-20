"""Registry authorization: one COmanage admin group.

Only members of ADMIN_GROUP (delivered by CILogon in the ``isMemberOf`` claim
at login, see ``auth.py``) may use the portal: they approve or reject
shovelers that registered themselves, mint registration tokens, and disable or
re-enable shovelers. Nobody else logs in; site operators only run shovelers.

Group memberships are captured into the session at login, so changes in
COmanage take effect on the user's next login rather than instantly.
"""

from __future__ import annotations

from typing import Iterable


def is_admin(admin_group: str, groups: Iterable[str]) -> bool:
    """True if ``groups`` contains the admin group (never for an empty group)."""
    if not admin_group:
        return False
    return admin_group in (groups or ())
