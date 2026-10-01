"""
Unit tests for URLParser component (Phase 5)
"""

import pytest
from src.preprocessing.url_parser import URLParser, ParsedURL


@pytest.fixture
def parser():
    return URLParser()


def test_standard_url_parsing(parser):
    url = "https://login.example.com/account/verify?id=123&token=abc#section2"
    parsed = parser.parse(url)

    assert isinstance(parsed, ParsedURL)
    assert parsed.scheme == "https"
    assert parsed.hostname == "login.example.com"
    assert parsed.domain == "example.com"
    assert parsed.subdomain == "login"
    assert parsed.suffix == "com"
    assert parsed.path == "/account/verify"
    assert parsed.path_tokens == ["account", "verify"]
    assert parsed.query == "id=123&token=abc"
    assert parsed.query_params == {"id": ["123"], "token": ["abc"]}
    assert parsed.fragment == "section2"
    assert parsed.is_ip is False
    assert parsed.has_port is False
    assert parsed.has_auth is False


def test_missing_scheme_auto_prepends(parser):
    url = "github.com/explore"
    parsed = parser.parse(url)

    assert parsed.scheme == "https"
    assert parsed.domain == "github.com"
    assert parsed.path == "/explore"


def test_ipv4_host_detection(parser):
    url = "http://192.168.1.1:8080/admin/panel"
    parsed = parser.parse(url)

    assert parsed.is_ip is True
    assert parsed.hostname == "192.168.1.1"
    assert parsed.port == 8080
    assert parsed.has_port is True
    assert parsed.path == "/admin/panel"


def test_credential_delimiter_injection(parser):
    url = "http://user:secret@evil-domain.com/login"
    parsed = parser.parse(url)

    assert parsed.has_auth is True
    assert parsed.user_info == "user:secret"
    assert parsed.domain == "evil-domain.com"


def test_punycode_homograph_detection(parser):
    url = "https://xn--pple-43d.com/iphone-offer"
    parsed = parser.parse(url)

    assert parsed.is_punycode is True
    assert "xn--" in parsed.hostname


def test_multi_level_subdomain(parser):
    url = "https://auth.portal.dev.internal.corp.com/api"
    parsed = parser.parse(url)

    assert parsed.domain == "corp.com"
    assert parsed.subdomain == "auth.portal.dev.internal"


def test_empty_url_raises_error(parser):
    with pytest.raises(ValueError, match="non-empty string"):
        parser.parse("")


def test_excessive_length_raises_error(parser):
    huge_url = "https://example.com/" + ("x" * 2050)
    with pytest.raises(ValueError, match="maximum permissible length"):
        parser.parse(huge_url)


def test_to_dict_serialization(parser):
    parsed = parser.parse("https://stripe.com/docs")
    data = parsed.to_dict()

    assert isinstance(data, dict)
    assert data["domain"] == "stripe.com"
    assert data["path_tokens"] == ["docs"]
