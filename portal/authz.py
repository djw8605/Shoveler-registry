"""Registry authorization: one COmanage admin group, plus an allow-list of subs.

Only admins may use the portal: they approve or reject shovelers that
registered themselves, mint registration tokens, and disable or re-enable
shovelers. Nobody else logs in; site operators only run shovelers.

An admin is a member of ADMIN_GROUP (delivered by CILogon in the
``isMemberOf`` claim at login, see ``auth.py``) OR anyone whose CILogon
``sub`` is listed in ADMIN_SUBS. The allow-list is a stopgap for when group
claims aren't released to this client; prefer the group.

Group memberships are captured into the session at login, so changes in
COmanage take effect on the user's next login rather than instantly.
"""

from __future__ import annotations

from typing import Iterable, Optional


def is_admin(
    admin_group: str,
    groups: Iterable[str],
    *,
    admin_subs: Iterable[str],
    sub: Optional[str],
) -> bool:
    """True if ``sub`` is allow-listed or ``groups`` contains the admin group.

    Exact matches only; an empty admin group or sub never matches.
    """
    if sub and sub in set(admin_subs or ()):
        return True
    if not admin_group:
        return False
    return admin_group in (groups or ())
