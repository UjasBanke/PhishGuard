import socket

import pytest

from app.rules import evaluate_rules
from feature_engineering.extractor import InvalidURLError, extract


def ids(url):
    return {i.id for i in evaluate_rules(extract(url))[1]}


def test_clean_url_no_indicators():
    score, inds = evaluate_rules(extract("https://www.wikipedia.org/wiki/Python"))
    assert score == 0 and inds == []


def test_expected_indicators():
    got = ids("http://192.168.1.5/login")
    assert {"ip_domain", "keywords", "non_https"} <= got
    assert "brand_host" in ids("https://paypal.secure-verify.tk/login")
    assert "shortener" in ids("https://bit.ly/abc123")


def test_rule_score_capped():
    score, _ = evaluate_rules(extract("http://paypal.a.b.c.d.e.login-verify-secure-account.tk/webscr?x=1"))
    assert score == 100


def test_result_schema_and_ranges(analyzer):
    r = analyzer.analyze("http://paypal.secure-verify.tk/login")
    for k in ("risk_score", "verdict", "ml_prediction", "ml_confidence", "rule_score", "indicators", "features",
              "reasons", "explanation"):
        assert k in r
    assert 0 <= r["risk_score"] <= 100 and 0.5 <= r["ml_confidence"] <= 1
    assert r["explanation"].startswith(f'{r["verdict"]} \u2014 {r["risk_score"]}/100')


def test_verdicts(analyzer):
    assert analyzer.analyze("https://www.wikipedia.org/")["verdict"] == "LOW RISK"
    assert analyzer.analyze("https://github.com/login")["verdict"] == "LOW RISK"
    assert analyzer.analyze("http://paypal.secure-verify.account-update.tk/login.php?s=1")["verdict"] == "HIGH RISK"


def test_batch_matches_single_and_handles_invalid(analyzer):
    urls = ["https://example.com", "not a url with spaces", "http://192.168.0.1/login"]
    out = analyzer.analyze_many(urls)
    assert out[1] is None
    assert out[0]["risk_score"] == analyzer.analyze(urls[0])["risk_score"]


def test_invalid_raises(analyzer):
    with pytest.raises(InvalidURLError):
        analyzer.analyze("javascript:alert(1)")


def test_never_touches_network(analyzer, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    assert analyzer.analyze("http://evil-login.tk/verify")["risk_score"] > 0
