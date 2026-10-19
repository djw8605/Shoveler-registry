"""COmanage group-based site authorization.

Authorization is driven by the user's COmanage group memberships, delivered by
CILogon in the ``isMemberOf`` claim at login (see ``auth.py``). There is no
local allow-list file to maintain: a person's access follows directly from the
groups the central admin manages in COmanage.

Convention: a group named ``<prefix><site>`` (e.g. ``shoveler-nebraska`` with
the default ``shoveler-`` prefix) grants management of ``<site>``. The site
name is the part of the group name after the prefix. Groups that don't start
with the prefix (e.g. COmanage's built-in ``CO:members:active``) are ignored.

Group memberships are captured into the session at login, so changes in
COmanage take effect on the user's next login rather than instantly.

The registry-admin group is never a site group, even when its name starts with
the prefix (the documented defaults, ``shoveler-`` and ``shoveler-admins``,
do): it grants the admin role, not a site called ``admins``.
"""

from __future__ import annotations

from typing import Iterable, Optional


def _site_from_group(group: str, prefix: str, admin_group: str) -> Optional[str]:
    """Return the site a group authorizes, or None if it isn't a site group."""
    if not group.startswith(prefix) or (admin_group and group == admin_group):
        return None
    site = group[len(prefix):].strip()
    return site or None


def sites_for_groups(
    groups: Iterable[str], prefix: str, *, admin_group: Optional[str]
) -> list[str]:
    """Return the sorted, de-duplicated sites the given groups may manage.

    ``admin_group`` (REGISTRY_ADMIN_GROUP) is required so no caller can forget
    to exclude it; pass "" or None when there is none.
    """
    sites = set()
    for group in groups or ():
        if not isinstance(group, str):
            continue
        site = _site_from_group(group, prefix, admin_group or "")
        if site:
            sites.add(site)
    return sorted(sites)


def may_manage_site(
    groups: Iterable[str], prefix: str, site: str, *, admin_group: Optional[str]
) -> bool:
    return site in sites_for_groups(groups, prefix, admin_group=admin_group)


def is_registry_admin(admin_group: Optional[str], groups: Iterable[str]) -> bool:
    """Registry-wide admins are members of the configured REGISTRY_ADMIN_GROUP.

    An empty/unset ``admin_group`` disables the admin role entirely.
    """
    if not admin_group:
        return False
    return admin_group in (groups or ())
