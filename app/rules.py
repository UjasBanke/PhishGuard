"""Rule-based URL security analysis.

Each rule inspects the extracted features/signals of a URL string and, when it
fires, returns an :class:`Indicator` with a human-readable explanation and a
point value. Points are summed and capped at 100 to produce the *rule score*.
Weights and thresholds live in ``feature_engineering/feature_config.json``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from feature_engineering.extractor import ExtractionResult, load_config


@dataclass
class Indicator:
    id: str
    title: str        # short card heading, e.g. "Suspicious keyword"
    detail: str       # one-line explanation shown under the heading
    reason: str       # sentence used in the plain-text explanation
    severity: str     # "low" | "medium" | "high"
    points: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _quote_list(items: list[str], limit: int = 4) -> str:
    shown = ", ".join(f'"{i}"' for i in items[:limit])
    return shown + (f" +{len(items) - limit} more" if len(items) > limit else "")


def evaluate_rules(result: ExtractionResult) -> tuple[int, list[Indicator]]:
    """Return ``(rule_score 0-100, indicators)`` for an extraction result."""
    cfg = load_config()
    w, t = cfg["rule_weights"], cfg["rule_thresholds"]
    f, s, p = result.features, result.signals, result.parsed
    out: list[Indicator] = []

    def add(id_: str, title: str, detail: str, reason: str, severity: str, points: int) -> None:
        out.append(Indicator(id_, title, detail, reason, severity, int(points)))

    if f["has_ip_domain"]:
        add("ip_domain", "IP address as domain", f"Host is the raw address {p.host}",
            "IP address used as domain", "high", w["ip_domain"])

    if p.has_userinfo:
        add("userinfo_at", "Credentials trick ('@' in host part)",
            "Text before '@' is ignored by browsers and often mimics a trusted site",
            "'@' symbol hides the real destination", "high", w["userinfo_at"])
    elif f["has_at_symbol"]:
        add("at_symbol", "'@' symbol in URL", "Unusual character outside the host part",
            "'@' symbol present in URL", "low", w["at_symbol_other"])

    if s["brands_host"]:
        brands = s["brands_host"]
        add("brand_host", "Brand impersonation",
            f'Mentions {_quote_list(brands, 2)} but the domain is "{p.registered_domain}"',
            f"Impersonates {', '.join(brands[:2])} on an unrelated domain", "high", w["brand_host"])
    elif s["brands_path"]:
        brands = s["brands_path"]
        add("brand_path", "Brand name in path",
            f'{_quote_list(brands, 2)} appears in the path of "{p.registered_domain}"',
            f"Brand name ({', '.join(brands[:2])}) in the path of an unrelated domain",
            "medium", w["brand_path"])

    if s["keywords"]:
        kws = s["keywords"]
        pts = min(w["keyword_each"] * len(kws), w["keyword_max"])
        add("keywords", "Suspicious keyword" + ("s" if len(kws) > 1 else ""),
            f"{_quote_list(kws)} detected",
            f"Suspicious keyword{'s' if len(kws) > 1 else ''}: {', '.join(kws[:4])}",
            "medium" if len(kws) > 1 else "low", pts)

    n_sub = f["num_subdomains"]
    if n_sub >= t["subdomains_extreme"]:
        add("subdomains", "Excessive subdomains", f"{int(n_sub)} subdomains detected",
            "Excessive subdomains", "high", w["subdomains_extreme"])
    elif n_sub >= t["subdomains_excessive"]:
        add("subdomains", "Many subdomains", f"{int(n_sub)} subdomains detected",
            "Many subdomains", "medium", w["subdomains_excessive"])

    length = f["url_length"]
    if length >= t["url_very_long"]:
        add("url_length", "URL unusually long", f"{int(length)} characters",
            "URL unusually long", "medium", w["url_very_long"])
    elif length >= t["url_long"]:
        add("url_length", "Long URL", f"{int(length)} characters", "URL is long", "low", w["url_long"])

    if f["suspicious_tld"]:
        add("suspicious_tld", "Suspicious top-level domain", f'".{s["tld"]}" is frequently abused',
            f'Suspicious TLD ".{s["tld"]}"', "medium", w["suspicious_tld"])

    if s["scheme_provided"] and f["has_https"] == 0:
        add("non_https", "Non-HTTPS connection", "Connection is not encrypted",
            "Connection is not encrypted (HTTP)", "medium", w["non_https"])

    if f["is_shortener"]:
        add("shortener", "URL shortener", f'"{p.registered_domain}" hides the final destination',
            "URL shortener hides the real destination", "medium", w["shortener"])

    if f["has_punycode"]:
        add("punycode", "Punycode / non-ASCII host", "Look-alike characters may imitate a real domain",
            "Punycode / look-alike characters in host", "high", w["punycode"])

    hy = f["domain_hyphens"]
    if hy >= t["hyphens_extreme"]:
        add("hyphens", "Excessive hyphens in domain", f"{int(hy)} hyphens in host name",
            "Excessive hyphens in domain", "medium", w["hyphens_extreme"])
    elif hy >= t["hyphens_many"]:
        add("hyphens", "Multiple hyphens in domain", f"{int(hy)} hyphens in host name",
            "Multiple hyphens in domain", "low", w["hyphens_many"])

    if not f["has_ip_domain"] and f["domain_digits"] >= t["domain_digits"]:
        add("domain_digits", "Digits in domain", f"{int(f['domain_digits'])} digits in host name",
            "Many digits in domain name", "low", w["domain_digits"])

    if (not f["has_ip_domain"] and f["domain_entropy"] >= t["high_entropy"]
            and f["domain_length"] >= t["high_entropy_min_length"]):
        add("entropy", "Random-looking domain", f"Entropy {f['domain_entropy']:.2f} bits/char",
            "Domain looks randomly generated", "low", w["high_entropy"])

    if f["has_port"]:
        add("odd_port", "Non-standard port", f"Port {s['port']} specified",
            "Non-standard port in URL", "low", w["odd_port"])

    if f["num_query_params"] >= t["many_params"]:
        add("many_params", "Many query parameters", f"{int(f['num_query_params'])} parameters",
            "Many query parameters", "low", w["many_params"])

    if f["num_percent_encoded"] >= t["encoded_chars"]:
        add("encoded", "Encoded characters", f"{int(f['num_percent_encoded'])} %XX sequences",
            "Heavily percent-encoded URL", "low", w["encoded_chars"])

    if f["double_slash_in_path"]:
        add("double_slash", "Double slash in path", "'//' inside the path can signal redirection tricks",
            "Double slash in path", "low", w["double_slash"])

    score = min(100, sum(i.points for i in out))
    out.sort(key=lambda i: i.points, reverse=True)
    return score, out
