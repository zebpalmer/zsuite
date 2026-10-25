# flake8: noqa E501
from zsuite.jwks import extract_signing_keys, get_jwks_from_url

JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "n": "u08bvm6u6Lyq-cCa76QtMq2RYNWe9XkzH9jdwAbLUK6TAmxNc7_ihNyff9snQBjMInBBtJGewfnPDmtvd-7Z4X0-77y7_pJgDDrmgZb3uFPwYtAColMMO29Sm80EX6uZzQbzpCRFPwtYMT96LrHATnFabO9VSe1vPHaLldSTADm3fqQkqrBSIwo9c1j14PS5irLzH0k6KrQbwE4SOirrsYgjUl8VyxLjGxq4DyJJAsAuqOMWv0H8yYHLdm0mjfj9Q6Bnn3HKiqvx6pctH2Nj7ihhCAz_N8R5xa7cOGJCGaMv_5DeHdl8KL8oX4-d3YJqVork2gDtbIGKYJsNbeIQYQ",
            "e": "AQAB",
            "use": "sig",
            "kid": "",
        }
    ]
}
JWTOKEN = """eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly93aG9hbWkubGNnb3BzLmNvbSJdLCJleHAiOjE2OTUxNDA3MDYsImlhdCI6MTY5NTExMTkwOSwiaXNzIjoidGVsZXBvcnQubGFjYWxsZWdyb3VwLmNvbSIsIm5iZiI6MTY5NTExMTg5OSwicm9sZXMiOlsic3VwZXJ1c2VyIl0sInN1YiI6InplYiIsInRyYWl0cyI6eyJsb2dpbnMiOlsiIl19LCJ1c2VybmFtZSI6InplYiJ9.b6XwcsSZvC0paxDKf2hrzM994xfZvvv3dtzkWxdS0JJyxKaW-k1RyiD2vdKeuyB-dxQl42MX9F0kerGe4ZhlEOdeqlkFcxuqQgMJVLMHr81lbQudp-rbjykZFXbFDda_TqJNTbkxy898lCHzkg3_Tl58ZRBpcvUPpTjOUtumibtT7U0e4XP8wpaiMR2DWaFj2YsTQ6mZ8ZMapT4ir8GluaGi0e5gG8lSF76k-u00_yQM8PLBNER-NTJTjv9ieRd-8MMu5k6GfoNn0tzzJKbcoxlwBV5US0Of0U2QalmyBeSBcibbX7J2KCW37pojr0dFMSkHKtV_mtg_qf4jyRjbVw"""


def test_extract_signing_keys():
    keys = extract_signing_keys(JWKS)
    assert len(keys) >= 1


def test_get_jwks_from_url():
    keys = get_jwks_from_url("https://teleport.lacallegroup.com/.well-known/jwks.json")
    assert len(keys) >= 1
    assert "BEGIN PUBLIC KEY" in keys[0].decode("utf-8")


def test_extract_signing_keys_skips_non_rsa():
    """Non-RSA keys in the JWKS (e.g. EC keys) are skipped instead of raising."""
    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def", "kid": "ec-key"}, *JWKS["keys"]]}
    keys = extract_signing_keys(jwks)
    assert len(keys) == 1


def test_get_jwks_from_url_raises_on_http_error(mocker):
    """A non-2xx JWKS response raises instead of parsing an error page."""
    import pytest
    import requests

    mock_resp = mocker.Mock()
    mock_resp.raise_for_status.side_effect = requests.HTTPError("404 Client Error")
    mocker.patch("zsuite.jwks.requests.get", return_value=mock_resp)

    with pytest.raises(requests.HTTPError):
        get_jwks_from_url("https://example.com/jwks.json")
