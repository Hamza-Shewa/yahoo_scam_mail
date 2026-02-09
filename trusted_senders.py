#!/usr/bin/env python3
"""Shared trusted senders/services loader with optimised domain lookups."""

import json
import os
from typing import Dict, List, Set


def load_trusted_data(path: str = None) -> Dict[str, object]:
    if not path:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base_dir, "trusted_senders.json")
    if not os.path.exists(path):
        return {
            "trusted_senders": set(),
            "trusted_domains": set(),
            "brand_domains": {},
            "brand_keywords": [],
        }
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "trusted_senders": frozenset(s.lower() for s in data.get("trusted_senders", [])),
        "trusted_domains": frozenset(d.lower() for d in data.get("trusted_domains", [])),
        "brand_domains": {
            k.lower(): frozenset(v.lower() for v in vals)
            for k, vals in data.get("brand_domains", {}).items()
        },
        "brand_keywords": [k.lower() for k in data.get("brand_keywords", [])],
    }


def domain_matches(domain: str, allowed: str) -> bool:
    """Check if *domain* exactly matches or is a subdomain of *allowed*."""
    if not domain or not allowed:
        return False
    return domain == allowed or domain.endswith(f".{allowed}")


# Cache for the expanded suffix set (built once per unique frozenset id)
_DOMAIN_CACHE: Dict[int, Set[str]] = {}


def _build_suffix_set(allowed_domains: frozenset) -> Set[str]:
    """Build a set containing each domain AND its dotted-suffix form for O(1) lookup."""
    key = id(allowed_domains)
    if key in _DOMAIN_CACHE:
        return _DOMAIN_CACHE[key]
    result: Set[str] = set()
    for d in allowed_domains:
        result.add(d)
        result.add(f".{d}")
    _DOMAIN_CACHE[key] = result
    return result


def domain_in_list(domain: str, allowed_domains) -> bool:
    """Fast O(1) check: is *domain* (or any parent) in the trusted set?

    Works by walking up the domain labels:
      mail.amazon.com -> check 'mail.amazon.com', then '.amazon.com', then '.com'
    """
    if not domain:
        return False
    # For frozenset inputs we can use the fast suffix set
    if isinstance(allowed_domains, frozenset):
        suffix_set = _build_suffix_set(allowed_domains)
        if domain in suffix_set:
            return True
        # Walk the domain labels for subdomain matching
        idx = domain.find('.')
        while idx != -1:
            if domain[idx:] in suffix_set:
                return True
            idx = domain.find('.', idx + 1)
        return False
    # Fallback for plain set / list
    return any(domain_matches(domain, allowed) for allowed in allowed_domains)
