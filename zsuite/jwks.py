"""Utilities for fetching and parsing JWKS for JWT verification."""

import base64
import logging

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

__all__ = ["extract_signing_keys", "get_jwks_from_url"]


def extract_signing_keys(jwks: dict) -> list:
    """Extract RSA public keys from JWKS and convert to PEM format for JWT verification.

    Parses a JSON Web Key Set (JWKS) dictionary and extracts RSA public keys, converting
    them from JWK format (base64url-encoded modulus and exponent) to PEM format suitable
    for use with PyJWT token verification.

    :param jwks: JWKS dictionary containing a 'keys' list with RSA public key components
                 ('n' for modulus and 'e' for exponent in base64url encoding).
    :type jwks: dict
    :returns: List of RSA public keys in PEM format (bytes).
    :rtype: list[bytes]

    **Example:**

    .. code-block:: python

        jwks = {"keys": [{"kty": "RSA", "n": "0vx7agoebG...", "e": "AQAB", "kid": "key-id-1"}]}

        pem_keys = extract_signing_keys(jwks)
        # Returns list of PEM-formatted public keys for JWT verification

    .. note::
        The function adds '==' padding to base64url values before decoding, which is
        required for proper base64 decoding when the encoded string length is not
        a multiple of 4.
    """
    # Parsing the JWKS JSON to get the first key
    keys = []

    for jwk in jwks["keys"]:
        # Only RSA keys are supported; providers may also publish EC/OKP keys
        if jwk.get("kty") != "RSA":
            logging.debug(f"Skipping non-RSA JWK (kty={jwk.get('kty')!r}, kid={jwk.get('kid')!r})")
            continue

        # Decoding the base64url encoded 'n' and 'e'
        n = base64.urlsafe_b64decode(jwk["n"] + "==")
        e = base64.urlsafe_b64decode(jwk["e"] + "==")

        # Constructing the RSA public key
        public_numbers = rsa.RSAPublicNumbers(
            e=int.from_bytes(e, byteorder="big"),
            n=int.from_bytes(n, byteorder="big"),
        )
        public_key = public_numbers.public_key(backend=default_backend())

        # Converting the RSA key to PEM format for use with pyjwt
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        keys.append(pem)
    return keys


def get_jwks_from_url(url):
    """Fetch JWKS from a URL and extract RSA public keys for JWT verification.

    Retrieves JSON Web Key Set from the specified URL and converts the keys to PEM
    format. Commonly used to fetch public keys from OAuth2/OIDC providers for
    validating JWT tokens.

    :param url: URL endpoint serving the JWKS JSON (e.g.,
                https://example.com/.well-known/jwks.json).
    :type url: str
    :returns: List of RSA public keys in PEM format (bytes).
    :rtype: list[bytes]
    :raises requests.RequestException: If HTTP request to URL fails.
    :raises requests.HTTPError: If the URL returns a non-2xx status code.
    :raises KeyError: If JWKS response doesn't contain expected 'keys' field.
    :raises ValueError: If base64 decoding fails for key components.

    **Example:**

    .. code-block:: python

        # Fetch public keys from OAuth provider
        jwks_url = "https://auth.example.com/.well-known/jwks.json"
        signing_keys = get_jwks_from_url(jwks_url)

        # Use with PyJWT for token verification
        import jwt

        for key in signing_keys:
            try:
                payload = jwt.decode(token, key, algorithms=["RS256"])
                break  # Successfully decoded
            except jwt.InvalidTokenError:
                continue  # Try next key

    .. note::
        This function makes a synchronous HTTP request. Consider caching the result
        or using it with AuthManager's TTL cache to avoid frequent requests to the
        JWKS endpoint.
    """
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return extract_signing_keys(response.json())
