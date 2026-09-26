import pytest

from feature_engineering.extractor import (InvalidURLError, extract, extract_features,
                                           feature_names, shannon_entropy)


def test_feature_vector_matches_config_order():
    assert list(extract_features("https://example.com").keys()) == feature_names()


def test_basic_lengths_and_https():
    f = extract_features("https://www.example.com/a/b?x=1&y=2")
    assert f["has_https"] == 1 and f["num_query_params"] == 2 and f["num_path_segments"] == 2
    assert f["url_length"] == len("https://www.example.com/a/b?x=1&y=2")


def test_ip_domain_variants():
    assert extract_features("http://192.168.1.1/login")["has_ip_domain"] == 1
    assert extract_features("http://3232235777/")["has_ip_domain"] == 1
    assert extract_features("http://example.com/")["has_ip_domain"] == 0


def test_at_symbol_and_userinfo():
    r = extract("https://paypal.com@evil.tk/x")
    assert r.features["has_at_symbol"] == 1 and r.parsed.has_userinfo
    assert r.signals["brands_host"] == ["paypal"]


def test_subdomains_ignore_leading_www():
    assert extract_features("https://www.example.com")["num_subdomains"] == 0
    assert extract_features("https://a.b.c.example.co.uk")["num_subdomains"] == 3


def test_keywords_and_tld():
    r = extract("http://x.tk/login/verify")
    assert set(r.signals["keywords"]) == {"login", "verify"}
    assert r.features["suspicious_tld"] == 1


def test_brand_official_domain_not_flagged():
    assert extract_features("https://accounts.google.com/signin")["brand_in_host"] == 0
    assert extract_features("http://paypa1-secure.xyz/")["brand_in_host"] == 1


def test_scheme_less_input_assumed_https():
    assert extract_features("example.com/path")["has_https"] == 1


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


@pytest.mark.parametrize("bad", ["", "   ", "javascript:alert(1)", "data:text/html,x", "ftp2://x.com",
                                 "http://", "http://exa mple.com", "a" * 3000, "http://[::1"])
def test_invalid_urls_rejected(bad):
    with pytest.raises(InvalidURLError):
        extract(bad)
