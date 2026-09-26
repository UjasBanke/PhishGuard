"""URL feature extraction for PhishGuard.

IMPORTANT: everything in this module works on the URL *string* only. No request
is ever made to the submitted URL, no DNS lookup is performed and nothing is
executed. ``tldextract`` is configured to use its bundled public-suffix
snapshot, so it does not touch the network either.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pandas as pd
import tldextract

CONFIG_PATH = Path(__file__).with_name("feature_config.json")

# Offline extractor: bundled suffix snapshot only, no cache directory, no HTTP.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_BLOCKED_PSEUDO_SCHEMES = re.compile(
    r"^(javascript|data|vbscript|file|mailto|tel|blob|about):", re.IGNORECASE
)
_NUMERIC_HOST_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_WWW_RE = re.compile(r"^www\d*$")
_SPECIAL_CHARS = set("@?&=_%~!$*()+,;#[]{}|\\^`<>'\"")
_LEET = [{"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"},
         {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}]


class InvalidURLError(ValueError):
    """Raised when the input cannot be interpreted as a URL string."""


@lru_cache(maxsize=1)
def load_config(path: str | None = None) -> dict[str, Any]:
    with open(path or CONFIG_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def feature_names() -> list[str]:
    return list(load_config()["feature_order"])


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char). Higher = more random-looking."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class ParsedURL:
    raw: str
    normalized: str
    scheme: str
    scheme_provided: bool
    host: str
    port: int | None
    has_userinfo: bool
    userinfo: str
    path: str
    query: str
    subdomain_labels: list[str]
    domain: str
    suffix: str
    registered_domain: str
    is_ip: bool


@dataclass
class ExtractionResult:
    parsed: ParsedURL
    features: dict[str, float]
    signals: dict[str, Any] = field(default_factory=dict)


def normalize_url(raw: str) -> tuple[str, bool]:
    """Validate + normalise a raw input string. Returns (url, scheme_provided)."""
    cfg = load_config()
    if raw is None or not isinstance(raw, str):
        raise InvalidURLError("URL must be a string.")
    text = raw.strip()
    if not text:
        raise InvalidURLError("URL is empty.")
    if len(text) > cfg["max_url_length"]:
        raise InvalidURLError(f"URL is longer than {cfg['max_url_length']} characters.")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in text):
        raise InvalidURLError("URL contains whitespace or control characters.")
    if _BLOCKED_PSEUDO_SCHEMES.match(text):
        raise InvalidURLError("Only http(s)/ftp URLs are supported.")
    if _SCHEME_RE.match(text):
        scheme = text.split("://", 1)[0].lower()
        if scheme not in cfg["allowed_schemes"]:
            raise InvalidURLError(f"Unsupported URL scheme: {scheme!r}.")
        return text, True
    return "https://" + text.lstrip("/"), False


def _looks_numeric_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST_RE.match(host))


def parse_url(raw: str) -> ParsedURL:
    normalized, scheme_provided = normalize_url(raw)
    try:
        parts = urlsplit(normalized)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError(f"Malformed URL: {exc}") from exc
    if not host:
        raise InvalidURLError("No host name found in URL.")

    is_ip = _looks_numeric_ip(host)
    if is_ip:
        labels, domain, suffix, registered = [], host, "", host
    else:
        ext = _TLD_EXTRACT(host)
        labels = [x for x in ext.subdomain.split(".") if x]
        if labels and _WWW_RE.match(labels[0]):
            labels = labels[1:]
        domain, suffix = ext.domain, ext.suffix
        registered = f"{domain}.{suffix}" if suffix else domain

    return ParsedURL(
        raw=raw, normalized=normalized, scheme=parts.scheme.lower(),
        scheme_provided=scheme_provided, host=host, port=port,
        has_userinfo="@" in parts.netloc,
        userinfo=parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else "",
        path=parts.path, query=parts.query,
        subdomain_labels=labels, domain=domain, suffix=suffix,
        registered_domain=registered, is_ip=is_ip,
    )


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _brand_hit(token: str, brand: str) -> bool:
    variants = {token} | {token.translate(str.maketrans(m)) for m in _LEET}
    for t in variants:
        if t == brand or (len(brand) >= 5 and t.startswith(brand)):
            return True
    return False


def _find_brands(tokens: list[str], registered: str, brands: dict[str, list[str]]) -> list[str]:
    found = []
    for brand, official in brands.items():
        if registered in official:
            continue
        if any(_brand_hit(t, brand) for t in tokens):
            found.append(brand)
    return found


def _find_keywords(text: str, keywords: list[str]) -> list[str]:
    found = [k for k in keywords if k in text]
    # drop keywords that are substrings of another hit (e.g. "suspend" in "suspended")
    return [k for k in found if not any(k != o and k in o for o in found)]


def extract(raw_url: str) -> ExtractionResult:
    """Parse ``raw_url`` and compute the model feature vector + rule signals."""
    cfg = load_config()
    p = parse_url(raw_url)
    url = p.normalized
    haystack = (p.host + p.path + "?" + p.query).lower()

    keywords = _find_keywords(haystack, cfg["suspicious_keywords"])
    tld = p.suffix.split(".")[-1] if p.suffix else ""
    sus_tld = int(tld in cfg["suspicious_tlds"])
    shortener = int(p.registered_domain in cfg["url_shorteners"])

    host_tokens = _tokens(".".join(p.subdomain_labels + [p.domain])) if not p.is_ip else []
    host_tokens += _tokens(p.userinfo)  # "https://paypal.com@evil.tk" mimicry
    path_tokens = _tokens(p.path)
    brands_host = _find_brands(host_tokens, p.registered_domain, cfg["brands"])
    brands_path = [b for b in _find_brands(path_tokens, p.registered_domain, cfg["brands"])
                   if b not in brands_host]

    n_digits = sum(ch.isdigit() for ch in url)
    query_params = len(parse_qsl(p.query, keep_blank_values=True)) if p.query else 0
    path_segments = len([s for s in p.path.split("/") if s])
    non_ascii = any(ord(c) > 127 for c in p.host)

    f: dict[str, float] = {
        "url_length": len(url),
        "domain_length": len(p.host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "domain_hyphens": p.host.count("-"),
        "num_digits": n_digits,
        "domain_digits": sum(ch.isdigit() for ch in p.host),
        "digit_ratio": round(n_digits / max(len(url), 1), 4),
        "num_subdomains": len(p.subdomain_labels),
        "has_https": int(p.scheme in ("https", "ftps")),
        "has_ip_domain": int(p.is_ip),
        "has_at_symbol": int("@" in url),
        "num_suspicious_keywords": len(keywords),
        "num_special_chars": sum(ch in _SPECIAL_CHARS for ch in url),
        "num_query_params": query_params,
        "domain_entropy": round(shannon_entropy(p.host), 4),
        "path_entropy": round(shannon_entropy(p.path) if len(p.path) > 1 else 0.0, 4),
        "suspicious_tld": sus_tld,
        "is_shortener": shortener,
        "has_punycode": int("xn--" in p.host or non_ascii),
        "has_port": int(p.port not in (None, 80, 443)),
        "num_path_segments": path_segments,
        "num_percent_encoded": len(_PERCENT_RE.findall(url)),
        "double_slash_in_path": int("//" in p.path),
        "brand_in_host": int(bool(brands_host)),
        "brand_in_path": int(bool(brands_path)),
    }
    order = cfg["feature_order"]
    missing = set(order) - set(f)
    if missing:  # config/extractor drift guard
        raise RuntimeError(f"Extractor is missing features: {sorted(missing)}")
    features = {name: f[name] for name in order}

    signals = {
        "keywords": keywords,
        "tld": tld,
        "brands_host": brands_host,
        "brands_path": brands_path,
        "port": p.port,
        "subdomain_labels": p.subdomain_labels,
        "scheme_provided": p.scheme_provided,
        "scheme": p.scheme,
        "registered_domain": p.registered_domain,
        "has_userinfo": p.has_userinfo,
    }
    return ExtractionResult(parsed=p, features=features, signals=signals)


def extract_features(raw_url: str) -> dict[str, float]:
    return extract(raw_url).features


def to_frame(rows: list[dict[str, float]]) -> pd.DataFrame:
    """Feature dicts -> DataFrame with the exact training column order."""
    return pd.DataFrame(rows, columns=feature_names())
