#!/usr/bin/env python3
"""Data loading and domain verification utilities for the Yahoo Mail Smart Scanner."""

import json
import os
from typing import Dict, List, Set, Any


def _clean_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _clean_list(values: object) -> List[str]:
    if not isinstance(values, list):
        return []
    seen: Set[str] = set()
    result: List[str] = []
    for raw in values:
        text = _clean_text(raw)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _clean_domain_map(values: object) -> Dict[str, frozenset]:
    if not isinstance(values, dict):
        return {}
    cleaned: Dict[str, frozenset] = {}
    for key, domain_list in values.items():
        brand = _clean_text(key)
        if not brand:
            continue
        domains = frozenset(_clean_list(domain_list))
        if domains:
            cleaned[brand] = domains
    return cleaned


def _default_trusted_path() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "trusted_senders.json")


def _default_scam_path() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "scam_data.json")


def read_json_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object at top-level in {path}")
    return data


def write_json_file(path: str, data: Dict[str, Any]) -> None:
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(temp_path, path)


def load_trusted_data(path: str = None) -> Dict[str, object]:
    if not path:
        path = _default_trusted_path()
    if not os.path.exists(path):
        return {
            "trusted_senders": set(),
            "trusted_domains": set(),
            "brand_domains": {},
            "brand_keywords": [],
        }
    data = read_json_file(path)
    trusted_senders = frozenset(_clean_list(data.get("trusted_senders", [])))
    trusted_domains = frozenset(_clean_list(data.get("trusted_domains", [])))
    brand_domains = _clean_domain_map(data.get("brand_domains", {}))
    brand_keywords = _clean_list(data.get("brand_keywords", []))
    return {
        "trusted_senders": trusted_senders,
        "trusted_domains": trusted_domains,
        "brand_domains": brand_domains,
        "brand_keywords": brand_keywords,
    }


def load_scam_data(path: str = None) -> Dict[str, object]:
    if not path:
        path = _default_scam_path()
    if not os.path.exists(path):
        return {
        "keywords": [],
            "suspicious_domains": [],
            "lookalikes": {},
        }
    data = read_json_file(path)
    lookalikes_raw = data.get("lookalikes", {})
    lookalikes: Dict[str, List[str]] = {}
    if isinstance(lookalikes_raw, dict):
        for legit, fake_list in lookalikes_raw.items():
            legit_clean = _clean_text(legit)
            fakes_clean = _clean_list(fake_list)
            if legit_clean and fakes_clean:
                lookalikes[legit_clean] = fakes_clean

    # Prefer a unified 'keywords' list. If not present, fall back to
    # the older separate keys and merge them (preserving order).
    raw_keywords = []
    if "keywords" in data and isinstance(data.get("keywords"), list):
        raw_keywords = data.get("keywords", [])
    else:
        # Merge spam_display_keywords then scam_keywords, avoiding duplicates
        sd = data.get("spam_display_keywords", [])
        sk = data.get("scam_keywords", [])
        seen: Set[str] = set()
        merged: List[str] = []
        for v in (sd or []):
            t = _clean_text(v)
            if t and t not in seen:
                seen.add(t)
                merged.append(t)
        for v in (sk or []):
            t = _clean_text(v)
            if t and t not in seen:
                seen.add(t)
                merged.append(t)
        raw_keywords = merged
        # Persist migration back to disk: add a unified 'keywords' field
        try:
            data["keywords"] = raw_keywords
            # Keep the old keys for now but write the unified list for future runs
            write_json_file(path, data)
        except Exception:
            pass

    return {
        "keywords": _clean_list(raw_keywords),
        "suspicious_domains": _clean_list(data.get("suspicious_domains", [])),
        "urgency_words": _clean_list(data.get("urgency_words", [])),
        "lookalikes": lookalikes,
    }


def add_trusted_senders(senders: List[str], path: str = None) -> int:
    if not path:
        path = _default_trusted_path()

    data = read_json_file(path) if os.path.exists(path) else {}
    existing = _clean_list(data.get("trusted_senders", []))
    existing_set = set(existing)

    added = 0
    for sender in _clean_list(senders):
        if sender not in existing_set:
            existing.append(sender)
            existing_set.add(sender)
            added += 1

    data["trusted_senders"] = sorted(existing)
    write_json_file(path, data)
    return added


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
