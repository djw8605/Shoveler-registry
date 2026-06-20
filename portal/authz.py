"""File-based site-management allow-list.

A central admin maps CILogon identities (the stable ``sub`` claim) to the
sites they may manage. The file is reloaded on every request so edits take
effect without a restart. There is no domain-based auto-grant: a person must
have an explicit entry.

    # site-admins.yaml
    nebraska:
      - sub: "http://cilogon.org/serverA/users/12345"
        email: "derek@unl.edu"
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import yaml

log = logging.getLogger("portal.authz")


def load_admins(path: str) -> dict[str, list[dict]]:
    """Load the allow-list. Missing/empty file -> no grants (fail closed)."""
    if not os.path.exists(path):
        log.warning("Site-admins file %s not found; no one is authorized", path)
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        log.error("Site-admins file %s is not a mapping; ignoring", path)
        return {}
    return data


def sites_for_sub(path: str, sub: Optional[str]) -> list[str]:
    """Return the sorted list of sites the given ``sub`` may manage."""
    if not sub:
        return []
    admins = load_admins(path)
    sites = []
    for site, members in admins.items():
        if not isinstance(members, list):
            continue
        for member in members:
            if isinstance(member, dict) and member.get("sub") == sub:
                sites.append(site)
                break
    return sorted(sites)


def may_manage_site(path: str, sub: Optional[str], site: str) -> bool:
    return site in sites_for_sub(path, sub)
