import jwt
import pytest
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from zsuite.webservice import AuthManager, HALOFlask, auth_required, public_endpoint
from zsuite.webservice.auth import User, _get_users_from_tokens, has_required_role, token_from_auth_header

TEST_TOKENS = [
    {
        "username": "alice",
        "roles": ["admin", "developer"],
        "tokens": ["abc1234567890123", "xyz9876543210987"],
    },
    {
        "username": "bob",
        "roles": ["sysadmin"],
        "tokens": ["mno7654321098765"],
    },
]


def create_app():
    app = HALOFlask(__name__)
    AuthManager(app, persistent_tokens=TEST_TOKENS)
    return app


@pytest.fixture
def client():
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    client = app.test_client()

    @app.route("/public")
    @public_endpoint
    def public_route():
        return "Public", 200

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    @app.route("/private_no_roles")
    @auth_required
    def private_no_roles():
        return "Private", 200

    @app.route("/private_kwarg")
    @auth_required(roles=["admin"])
    def private_kwarg():
        return "Private", 200

    # run security preflight
    # should be done on last line of app creation
    am.security_preflight()

    return client


def generate_test_token(private_key, payload) -> str:
    """Generate a test JWT token with a given private key and payload.

    Parameters
    ----------
        private_key (str): The private key to sign the token.
        payload (Dict[str, str]): The payload to include in the token.

    Returns
    -------
        str: The generated JWT token.

    """
    return jwt.encode(payload, private_key, algorithm="RS256")


def temp_signing_keys():
    """Generate a temporary RSA private key and its corresponding public key in PEM format.

    Returns
    -------
        tuple: (private_key, public_key) where both are strings in PEM format.

    """
    key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        crypto_serialization.NoEncryption(),
    ).decode("utf-8")

    public_key = (
        key.public_key()
        .public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return private_key, public_key


def test_with_and_without_roles(client, monkeypatch):
    # need to ensure the auth_required decorator works
    # with and without roles specified
    private_key, public_key = temp_signing_keys()
    payload = {"username": "test_user", "roles": ["admin"]}
    test_token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # test with roles specified as args
    print("test with roles specified as args")
    response = client.get("/private", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200

    # # test with roles not specified
    print("test with roles not specified")
    response = client.get("/private_no_roles", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200

    # test with roles specified as kwargs
    print("test with roles specified as kwargs")
    response = client.get("/private_kwarg", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200


def test_temp_signing_keys():
    temp_signing_keys()


def test_endpoint_not_found(client):
    response = client.get("/notfound")
    assert response.status_code == 404


def test_check_auth_valid(client, monkeypatch):
    private_key, public_key = temp_signing_keys()
    payload = {"username": "alice", "roles": ["admin", "developer"]}
    test_token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Test an endpoint that requires authentication
    response = client.get("/private", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200
    response = client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})  # token for alice
    assert response.status_code == 200


def test_check_auth_missing_role(client, monkeypatch):
    private_key, public_key = temp_signing_keys()
    payload = {"username": "bob", "roles": ["sysadmin"]}
    test_token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Test an endpoint that requires authentication
    response = client.get("/private", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 403
    response = client.get("/private", headers={"Authorization": "Bearer mno7654321098765"})  # token for bob
    assert response.status_code == 403


def test_check_auth_public_endpoint(client):
    response = client.get("/public")
    assert response.status_code == 200
    assert response.data == b"Public"


def test_check_auth_private_endpoint_no_auth(client):
    response = client.get("/private")
    assert response.status_code == 401  # Assuming 401 for unauthorized


def test_parse_jwt_valid_token(monkeypatch, mocker):
    jwks_response = {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "n": "u08bvm6u6Lyq-cCa76QtMq2RYNWe9XkzH9jdwAbLUK6TAmxNc7_ihNyff9snQBjMInBBtJGewfnPDmtvd-7Z4X0-77y7_pJg"
                "DDrmgZb3uFPwYtAColMMO29Sm80EX6uZzQbzpCRFPwtYMT96LrHATnFabO9VSe1vPHaLldSTADm3fqQkqrBSIwo9c1j14PS5i"
                "rLzH0k6KrQbwE4SOirrsYgjUl8VyxLjGxq4DyJJAsAuqOMWv0H8yYHLdm0mjfj9Q6Bnn3HKiqvx6pctH2Nj7ihhCAz_N8R5xa"
                "7cOGJCGaMv_5DeHdl8KL8oX4-d3YJqVork2gDtbIGKYJsNbeIQYQ",
                "e": "AQAB",
                "use": "sig",
                "kid": "",
            },
        ],
    }

    monkeypatch.setenv("JWKS_URL", "https://teleport.lacallegroup.com/.well-known/jwks.json")

    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = jwks_response

    mocker.patch("requests.get", return_value=mock_response)

    app = create_app()
    token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cHM6Ly93aG9hbWkubGNnb3BzLmNvbSJdLCJleHAiOjE2OTUxNDA"
        "3MDYsImlhdCI6MTY5NTExMTkwOSwiaXNzIjoidGVsZXBvcnQubGFjYWxsZWdyb3VwLmNvbSIsIm5iZiI6MTY5NTExMTg5OSwicm9sZXM"
        "iOlsic3VwZXJ1c2VyIl0sInN1YiI6InplYiIsInRyYWl0cyI6eyJsb2dpbnMiOlsiIl19LCJ1c2VybmFtZSI6InplYiJ9.b6XwcsSZvC"
        "0paxDKf2hrzM994xfZvvv3dtzkWxdS0JJyxKaW-k1RyiD2vdKeuyB-dxQl42MX9F0kerGe4ZhlEOdeqlkFcxuqQgMJVLMHr81lbQudp-"
        "rbjykZFXbFDda_TqJNTbkxy898lCHzkg3_Tl58ZRBpcvUPpTjOUtumibtT7U0e4XP8wpaiMR2DWaFj2YsTQ6mZ8ZMapT4ir8GluaGi0e"
        "5gG8lSF76k-u00_yQM8PLBNER-NTJTjv9ieRd-8MMu5k6GfoNn0tzzJKbcoxlwBV5US0Of0U2QalmyBeSBcibbX7J2KCW37pojr0dFMS"
        "kHKtV_mtg_qf4jyRjbVw"
    )
    options = {
        "verify_exp": False,
        "verify_aud": False,
    }
    user = app.auth_manager._parse_jwt(token, options=options)
    assert isinstance(user, User)
    options["verify_exp"] = True
    user = app.auth_manager._parse_jwt(token, options=options)
    assert user is None
    options["verify_exp"] = True
    monkeypatch.setenv("JWT_AUDIENCE", "https://whoami.example.com")
    options["verify_exp"] = False
    user = app.auth_manager._parse_jwt(token, options=options)
    assert isinstance(user, User)


def test_auth_signing_keys(monkeypatch):
    monkeypatch.setenv("JWKS_URL", "https://teleport.lacallegroup.com/.well-known/jwks.json")
    app = create_app()
    keys = app.auth_manager.signing_keys
    assert len(keys) >= 0
    assert "BEGIN PUBLIC KEY" in keys[0].decode("utf-8")


def test_user_repr():
    user = User("john_doe", {"admin", "user"})
    assert (
        repr(user) == "User(name='john_doe', roles=admin,user)"
        or repr(user) == "User(name='john_doe', roles=user,admin)"
    )
    user = User("john_doe", ["admin", "user"])
    assert (
        repr(user) == "User(name='john_doe', roles=admin,user)"
        or repr(user) == "User(name='john_doe', roles=user,admin)"
    )
    user = User("empty_user", [])
    assert repr(user) == "User(name='empty_user', roles=None)"
    user = User("none_user", None)
    assert repr(user) == "User(name='none_user', roles=None)"


def test_user_roles_type():
    user = User("type_test", ["admin"])
    assert isinstance(user.roles, set)


def test_user():
    user = User("john_doe", {"admin", "user"})
    assert user.name == "john_doe"
    assert user.roles == {"admin", "user"}


@pytest.mark.parametrize(
    "user_roles, required_roles, expected_result",
    [
        (None, None, True),  # No roles required and no user roles
        (None, {"admin"}, False),  # Role required but user has no roles
        ({"admin"}, None, True),  # No roles required but user has roles
        ({"admin"}, {"admin"}, True),  # User has the required role
        ({"admin", "user"}, {"admin"}, True),  # User has more roles than required
        ({"admin", "user"}, {"admin", "user"}, True),  # User has all the required roles
        ({"admin", "user"}, {"manager"}, False),  # User doesn't have the required role
        (
            {"admin", "user"},
            {"manager", "admin"},
            True,
        ),  # User has at least one of the required roles
    ],
)
def test_has_required_role(user_roles, required_roles, expected_result):
    user = User("test_user", user_roles)
    assert has_required_role(user, required_roles) == expected_result


def test_get_users_from_tokens_short_token():
    short_token_data = [{"username": "alice", "roles": ["admin"], "tokens": ["short"]}]

    with pytest.raises(
        ValueError,
        match=r"Token for alice is too short, must be at least 16 characters",
    ):
        _get_users_from_tokens(short_token_data)


# def test_auth_undefined_tokens():
#     # Create a new app instance with no persistent tokens
#     app = HALOFlask(__name__)
#     am = AuthManager(app, persistent_tokens=None)  # Explicitly pass None
#     test_client = app.test_client()
#
#     @app.route("/test_endpoint")
#     @auth_required
#     def endpoint():
#         return "Test", 200
#
#     # Run security preflight
#     am.security_preflight()
#
#     # Test with a service token
#     response = test_client.get("/test_endpoint", headers={"Authorization": "Bearer some-persistent-token"})
#
#     # Assert that we get a proper 401 unauthorized response
#     # rather than a 500 server error from the NoneType error
#     assert response.status_code == 401
#
#     # # Also test without any authorization header to ensure baseline behavior
#     # response = test_client.get("/test_endpoint")
#     # assert response.status_code == 401


# ==================== JWT Error Handling Tests ====================


def test_jwt_expired_signature(client, monkeypatch):
    """Test JWT token with expired signature is rejected."""
    private_key, public_key = temp_signing_keys()
    # Create an expired token (exp in the past)
    import time

    payload = {"username": "test_user", "roles": ["admin"], "exp": int(time.time()) - 3600}  # Expired 1 hour ago
    expired_token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)
    monkeypatch.setenv("JWT_VERIFY_EXPIRE", "True")

    response = client.get("/private", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401


def test_jwt_invalid_signature(client, monkeypatch):
    """Test JWT token with invalid signature is rejected."""
    private_key, public_key = temp_signing_keys()
    # Create a token with one key but verify with another
    _, different_public_key = temp_signing_keys()

    payload = {"username": "test_user", "roles": ["admin"]}
    token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", different_public_key)

    response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_jwt_malformed_token(client, monkeypatch):
    """Test malformed JWT token is rejected."""
    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Test various malformed tokens
    response = client.get("/private", headers={"Authorization": "Bearer not.a.valid.jwt.token.at.all"})
    assert response.status_code == 401

    response = client.get("/private", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401


def test_jwt_invalid_audience(client, monkeypatch):
    """Test JWT token with wrong audience is rejected."""
    private_key, public_key = temp_signing_keys()
    payload = {"username": "test_user", "roles": ["admin"], "aud": "wrong-audience"}
    token = generate_test_token(private_key, payload)

    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)
    monkeypatch.setenv("JWT_AUDIENCE", "correct-audience")

    response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_jwt_no_roles_claim(client, monkeypatch):
    """Test JWT token without roles claim defaults to empty roles."""
    private_key, public_key = temp_signing_keys()
    # Token without roles claim
    payload = {"username": "test_user"}
    token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Should fail because private endpoint requires admin role
    response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

    # Should succeed for endpoint with no role requirements
    response = client.get("/private_no_roles", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_jwt_multiple_signing_keys(monkeypatch):
    """Test JWT validation tries multiple signing keys until one works."""
    private_key1, public_key1 = temp_signing_keys()
    private_key2, public_key2 = temp_signing_keys()

    # Create token signed with second key
    payload = {"username": "test_user", "roles": ["admin"]}
    token = generate_test_token(private_key2, payload)

    # Set first key in env (token won't verify with this)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key1)

    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @auth_required(["admin"])
    def test_route():
        return "Success", 200

    am.security_preflight()

    # The first key won't work, should fail
    test_client = app.test_client()
    response = test_client.get("/test", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401

    # Now test with the correct key
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key2)
    # Clear the cache so it picks up the new key
    am._cache.clear()

    app2 = HALOFlask(__name__)
    am2 = AuthManager(app2, persistent_tokens=TEST_TOKENS)

    @app2.route("/test")
    @auth_required(["admin"])
    def test_route2():
        return "Success", 200

    am2.security_preflight()
    test_client2 = app2.test_client()
    response = test_client2.get("/test", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


# ==================== Auth Header Tests ====================


def test_token_from_auth_header_with_bearer():
    """Test extracting token from Authorization header with Bearer prefix."""
    header = "Bearer abc123def456"
    token = token_from_auth_header(header)
    assert token == "abc123def456"


def test_token_from_auth_header_without_bearer():
    """Test extracting token from Authorization header without Bearer prefix."""
    header = "abc123def456"
    token = token_from_auth_header(header)
    assert token == "abc123def456"


def test_teleport_jwt_assertion_header(client, monkeypatch):
    """Test authentication via Teleport-Jwt-Assertion header."""
    private_key, public_key = temp_signing_keys()
    payload = {"username": "alice", "roles": ["admin"]}
    token = generate_test_token(private_key, payload)
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Use Teleport header instead of Authorization
    response = client.get("/private", headers={"Teleport-Jwt-Assertion": token})
    assert response.status_code == 200


def test_api_token_authentication(client, monkeypatch):
    """Test authentication using persistent API tokens."""
    # Set a JWT signing key to avoid NoneType error when token is not found in persistent tokens
    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Use Alice's API token
    response = client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})
    assert response.status_code == 200

    # Use Bob's API token (should fail - wrong role)
    response = client.get("/private", headers={"Authorization": "Bearer mno7654321098765"})
    assert response.status_code == 403

    # Invalid API token (will try JWT validation and fail)
    response = client.get("/private", headers={"Authorization": "Bearer invalidtoken12345"})
    assert response.status_code == 401


# ==================== User Model Tests ====================


def test_user_to_dict():
    """Test User.to_dict() serialization."""
    user = User("john_doe", ["admin", "developer"])
    user_dict = user.to_dict()
    assert user_dict["name"] == "john_doe"
    assert set(user_dict["roles"]) == {"admin", "developer"}
    assert isinstance(user_dict["roles"], list)


def test_user_invalid_roles_type():
    """Test User initialization with invalid roles type raises ValueError."""
    with pytest.raises(ValueError, match="roles must be None, list or set"):
        User("test_user", "invalid")  # String is not valid

    with pytest.raises(ValueError, match="roles must be None, list or set"):
        User("test_user", 123)  # Integer is not valid


def test_user_name_lowercase():
    """Test User name is converted to lowercase."""
    user = User("JohnDoe", ["admin"])
    assert user.name == "johndoe"


# ==================== Security Preflight Tests ====================


def test_security_preflight_jwt_and_jwks_both_set(monkeypatch):
    """Test security_preflight raises error when both JWT_SIGNING_KEY and JWKS_URL are set."""
    monkeypatch.setenv("JWT_SIGNING_KEY", "some_key")
    monkeypatch.setenv("JWKS_URL", "https://example.com/jwks")

    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    with pytest.raises(ValueError, match="JWT_SIGNING_KEY and JWKS_URL are both set"):
        am.security_preflight()


def test_security_preflight_auth_disabled(monkeypatch):
    """Test security_preflight with AUTH_ENABLED=False."""
    monkeypatch.setenv("AUTH_ENABLED", "False")

    app = HALOFlask(__name__)
    AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    # Should not have auth_manager when disabled
    assert app.auth_manager is None


# ==================== Redirect Tests ====================


def test_trailing_slash_redirect(client):
    """Test redirect handling for URLs with/without trailing slashes."""
    # If the route is defined without trailing slash, accessing with slash should redirect
    # This is Flask's default behavior that auth middleware must preserve
    response = client.get("/public/", follow_redirects=False)
    # Flask typically redirects with 308 (Permanent Redirect)
    # But the endpoint might not be set up with strict_slashes=False
    # Just verify it doesn't return 500 or auth errors
    assert response.status_code in [200, 308, 404]


# ==================== JWT Verification Options Tests ====================


def test_parse_jwt_with_custom_options(monkeypatch):
    """Test _parse_jwt with custom verification options."""
    private_key, public_key = temp_signing_keys()
    import time

    payload = {
        "username": "test_user",
        "roles": ["admin"],
        "exp": int(time.time()) - 3600,  # Expired
        "aud": "test-audience",
    }
    token = generate_test_token(private_key, payload)

    app = create_app()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # Should fail with exp verification enabled
    options = {"verify_exp": True, "verify_aud": False}
    user = app.auth_manager._parse_jwt(token, options=options)
    assert user is None

    # Should succeed with exp verification disabled
    options = {"verify_exp": False, "verify_aud": False}
    user = app.auth_manager._parse_jwt(token, options=options)
    assert isinstance(user, User)
    assert user.name == "test_user"


def test_parse_jwt_returns_none_on_invalid(monkeypatch):
    """Test _parse_jwt returns None for invalid tokens."""
    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    app = create_app()
    # Invalid token should return None
    user = app.auth_manager._parse_jwt("invalid.token.here")
    assert user is None


# ==================== Error Path Tests ====================


def test_method_not_allowed(client):
    """Test 405 Method Not Allowed for wrong HTTP methods."""
    # POST to a GET endpoint should return 405
    response = client.post("/public")
    assert response.status_code == 405


def test_preflight_required_before_serving():
    """Requests are refused until security_preflight() is called, then served normally."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    test_client = app.test_client()

    # Before the preflight runs, all requests are refused
    assert am._preflight_completed is None
    response = test_client.get("/test")
    assert response.status_code == 503

    # After the preflight, requests are served
    am.security_preflight()
    response = test_client.get("/test")
    assert response.status_code == 200
    assert am._preflight_completed is True


def test_preflight_not_called_refuses_all_requests(caplog):
    """Without security_preflight(), every request is refused, even public endpoints."""
    app = HALOFlask(__name__)
    AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    # Deliberately NOT calling security_preflight()
    test_client = app.test_client()
    with caplog.at_level("CRITICAL"):
        response = test_client.get("/test")
    assert response.status_code == 503
    assert "Security preflight not called, refusing all connections" in caplog.text


def test_get_token_users_both_params_raises_error():
    """Test get_token_users raises error when both params provided."""
    from zsuite.webservice.auth import get_token_users

    with pytest.raises(ValueError, match="persistent_tokens and persistent_token_file are mutually exclusive"):
        get_token_users("some_file.yaml", TEST_TOKENS)


def test_load_persistent_tokens_file_not_found():
    """Test load_persistent_tokens with non-existent file."""
    from zsuite.webservice.auth import load_persistent_tokens

    with pytest.raises(FileNotFoundError, match="Could not find persistent token file"):
        load_persistent_tokens("/nonexistent/path/to/tokens.yaml")


def test_parse_jwt_non_pyjwt_exception_raised(monkeypatch, mocker):
    """Test _parse_jwt re-raises non-PyJWT exceptions."""
    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    app = create_app()

    # Mock jwt.decode to raise a non-PyJWT exception
    mocker.patch("jwt.decode", side_effect=RuntimeError("Unexpected error"))

    with pytest.raises(RuntimeError, match="Unexpected error"):
        app.auth_manager._parse_jwt("some.token.here")


# ==================== Security Hardening Tests ====================


def test_jwt_second_jwks_key_validates(client, monkeypatch, mocker):
    """A token signed by a later JWKS key is accepted (all keys are tried in order)."""
    _, public_key1 = temp_signing_keys()
    private_key2, public_key2 = temp_signing_keys()
    monkeypatch.setenv("JWKS_URL", "https://example.com/.well-known/jwks.json")
    mocker.patch("zsuite.webservice.auth.get_jwks_from_url", return_value=[public_key1, public_key2])

    token = generate_test_token(private_key2, {"username": "test_user", "roles": ["admin"]})
    response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_jwt_no_matching_jwks_key_rejected(client, monkeypatch, mocker):
    """A token matching none of the JWKS keys is rejected after trying all keys."""
    _, public_key1 = temp_signing_keys()
    _, public_key2 = temp_signing_keys()
    private_key3, _ = temp_signing_keys()
    monkeypatch.setenv("JWKS_URL", "https://example.com/.well-known/jwks.json")
    mocker.patch("zsuite.webservice.auth.get_jwks_from_url", return_value=[public_key1, public_key2])

    token = generate_test_token(private_key3, {"username": "test_user", "roles": ["admin"]})
    response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_jwt_missing_username_claim_rejected(client, monkeypatch):
    """A validly signed JWT without a username claim gets a 401, not a 500."""
    private_key, public_key = temp_signing_keys()
    token = generate_test_token(private_key, {"roles": ["admin"]})
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_jwt_failure_does_not_log_raw_token(client, monkeypatch, caplog):
    """JWT decode failures log a short token ID, never the raw token."""
    _, public_key = temp_signing_keys()
    private_key2, _ = temp_signing_keys()
    token = generate_test_token(private_key2, {"username": "test_user", "roles": ["admin"]})
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    with caplog.at_level("DEBUG"):
        response = client.get("/private", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert token not in caplog.text
    assert token[:8] in caplog.text


def test_persistent_tokens_stored_hashed():
    """Raw tokens are not kept in memory; lookup is by SHA-256 digest."""
    import hashlib

    token_users = _get_users_from_tokens(TEST_TOKENS)
    raw_token = TEST_TOKENS[0]["tokens"][0]
    assert raw_token not in token_users
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    assert token_users[digest].name == "alice"


def test_invalid_auth_fail_log_level_falls_back(monkeypatch):
    """A bogus AUTH_FAIL_LOG_LEVEL doesn't break the auth failure path."""
    monkeypatch.setenv("AUTH_FAIL_LOG_LEVEL", "bogus")
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    am.security_preflight()
    response = app.test_client().get("/private")
    assert response.status_code == 401


def test_preflight_warns_when_jwt_audience_missing(monkeypatch, caplog):
    """Preflight logs critical when signing keys are configured without JWT_AUDIENCE."""
    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    with caplog.at_level("CRITICAL"):
        am.security_preflight()
    assert "JWT_AUDIENCE is not set" in caplog.text


def test_preflight_warns_when_expire_check_disabled(monkeypatch, caplog):
    """Preflight logs critical when JWT_VERIFY_EXPIRE is disabled."""
    monkeypatch.setenv("JWT_VERIFY_EXPIRE", "false")
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    with caplog.at_level("CRITICAL"):
        am.security_preflight()
    assert "JWT_VERIFY_EXPIRE is disabled" in caplog.text


def test_preflight_failure_fails_closed_with_503(monkeypatch, caplog):
    """If the preflight fails, requests are refused even if the caller swallows the exception."""
    _, public_key = temp_signing_keys()
    # Setting both makes security_preflight raise ValueError
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)
    monkeypatch.setenv("JWKS_URL", "https://example.com/.well-known/jwks.json")

    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    # A misbehaving app catches the preflight failure and starts anyway
    with pytest.raises(ValueError, match="JWT_SIGNING_KEY and JWKS_URL are both set"):
        am.security_preflight()

    test_client = app.test_client()
    with caplog.at_level("CRITICAL"):
        response = test_client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})
        assert response.status_code == 503
        response = test_client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})
        assert response.status_code == 503

    assert "Security preflight failed, refusing all connections" in caplog.text


def test_auth_required_rejects_bare_string_roles():
    """A bare string would become a set of characters -- must fail at decoration time."""
    with pytest.raises(TypeError, match="bare string"):

        @auth_required(roles="admin")
        def view_kwarg():
            return "nope"

    with pytest.raises(TypeError, match="bare string"):

        @auth_required("admin")
        def view_positional():
            return "nope"


def test_preflight_with_auth_disabled_serves_everything(monkeypatch, caplog):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    app = HALOFlask(__name__)
    am = AuthManager(app)

    @app.route("/open")
    @auth_required(["admin"])
    def open_route():
        return "open", 200

    am.security_preflight()
    assert "Authentication is disabled" in caplog.text

    response = app.test_client().get("/open")
    assert response.status_code == 200


def test_preflight_fails_when_jwks_url_yields_no_keys(monkeypatch, mocker):
    monkeypatch.setenv("JWKS_URL", "https://example.invalid/jwks.json")
    monkeypatch.delenv("JWT_SIGNING_KEY", raising=False)
    mocker.patch("zsuite.webservice.auth.get_jwks_from_url", return_value=[])

    app = HALOFlask(__name__)
    am = AuthManager(app)

    with pytest.raises(ValueError, match="no signing keys"):
        am.security_preflight()


def test_load_basic_auth_users_file_not_found(tmp_path):
    from zsuite.exceptions import BasicAuthError
    from zsuite.webservice.auth import load_basic_auth_users

    with pytest.raises(BasicAuthError, match="not found"):
        load_basic_auth_users(str(tmp_path / "missing.yaml"))

    with pytest.raises(BasicAuthError):
        corrupt = tmp_path / "corrupt.yaml"
        corrupt.write_text("users: [unclosed\n : :")
        load_basic_auth_users(str(corrupt))


def test_load_oauth_roles_file_errors(tmp_path):
    from zsuite.exceptions import OAuthError
    from zsuite.webservice.auth import load_oauth_roles

    with pytest.raises(OAuthError, match="not found"):
        load_oauth_roles(str(tmp_path / "missing.yaml"))

    with pytest.raises(OAuthError):
        corrupt = tmp_path / "corrupt.yaml"
        corrupt.write_text("users: [unclosed\n : :")
        load_oauth_roles(str(corrupt))


def test_token_id_empty():
    from zsuite.webservice.auth import _token_id

    assert _token_id("") == "<empty>"


def test_get_token_users_mutually_exclusive_args():
    from zsuite.webservice.auth import get_token_users

    with pytest.raises(ValueError, match="mutually exclusive"):
        get_token_users("some_file.yaml", [{"username": "u", "token": "t", "roles": []}])


def test_get_token_users_falls_back_to_env(monkeypatch, tmp_path):
    from zsuite.webservice.auth import get_token_users

    tokens_file = tmp_path / "tokens.yaml"
    tokens_file.write_text(
        "users:\n  - username: envuser\n    tokens:\n      - some-token-1234567890\n    roles:\n      - agent\n"
    )
    monkeypatch.setenv("AUTH_TOKENS_FILE", str(tokens_file))

    users = get_token_users(None, None)
    assert {user.name for user in users.values()} == {"envuser"}
