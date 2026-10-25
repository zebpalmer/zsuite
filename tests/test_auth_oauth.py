"""Tests for OAuth support in AuthManager."""

import json

import pytest

from zsuite.exceptions import OAuthError
from zsuite.webservice import AuthManager, HALOFlask, auth_required, public_endpoint
from zsuite.webservice.auth import User, load_oauth_roles

TEST_TOKENS = [
    {
        "username": "alice",
        "roles": ["admin", "developer"],
        "tokens": ["abc1234567890123", "xyz9876543210987"],
    },
]

GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

# Sample userinfo responses
VALID_USERINFO = {
    "sub": "1234567890",
    "email": "zeb@lacallegroup.com",
    "email_verified": True,
    "hd": "lacallegroup.com",
    "name": "Zeb",
    "picture": "https://example.com/photo.jpg",
}


def create_oauth_app(monkeypatch, **env_overrides):
    """Helper to create a Flask app with OAuth enabled."""
    monkeypatch.setenv("OAUTH_ENABLED", "true")
    monkeypatch.setenv("OAUTH_ALLOWED_DOMAINS", "lacallegroup.com,continued.com,simucase.com")
    monkeypatch.setenv("OAUTH_RESOURCE_URL", "https://cartographer.example.com")
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    app = HALOFlask(__name__)

    @app.route("/public")
    @public_endpoint
    def public_route():
        return "Public", 200

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    @app.route("/private_any")
    @auth_required
    def private_any():
        return "Private", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    am.security_preflight()
    return app, am


# ==================== OAuth Feature Flag Tests ====================


def test_oauth_disabled_by_default(monkeypatch):
    """Verify _oauth_enabled is False when OAUTH_ENABLED is not set."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    assert am._oauth_enabled is False


def test_oauth_enabled_sets_flag(monkeypatch):
    """Verify _oauth_enabled is True when OAUTH_ENABLED=true."""
    app, am = create_oauth_app(monkeypatch)
    assert am._oauth_enabled is True


# ==================== Well-Known Endpoint Tests ====================


def test_oauth_well_known_endpoint_registered(monkeypatch):
    """Verify /.well-known/oauth-protected-resource returns correct metadata."""
    app, am = create_oauth_app(monkeypatch)
    client = app.test_client()

    response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200

    data = json.loads(response.data)
    assert data["resource"] == "https://cartographer.example.com"
    assert data["authorization_servers"] == ["https://accounts.google.com"]
    assert data["bearer_methods_supported"] == ["header"]
    assert "openid" in data["scopes_supported"]
    assert "email" in data["scopes_supported"]
    assert "profile" in data["scopes_supported"]


def test_oauth_well_known_custom_auth_server(monkeypatch):
    """Verify custom authorization server URL is used."""
    app, am = create_oauth_app(monkeypatch, OAUTH_AUTHORIZATION_SERVER="https://custom-auth.example.com")
    client = app.test_client()

    response = client.get("/.well-known/oauth-protected-resource")
    data = json.loads(response.data)
    assert data["authorization_servers"] == ["https://custom-auth.example.com"]


def test_oauth_well_known_not_registered_when_disabled(monkeypatch):
    """Verify endpoint doesn't exist when OAuth is off."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    am.security_preflight()

    client = app.test_client()
    response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 404


# ==================== OAuth Token Validation Tests ====================


def test_parse_oauth_token_valid(monkeypatch, mocker):
    """Mock userinfo returning valid data, assert User returned with correct roles."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("some-oauth-token")
    assert isinstance(user, User)
    assert user.name == "zeb@lacallegroup.com"
    assert "reader" in user.roles


def test_parse_oauth_token_wrong_domain(monkeypatch, mocker):
    """Token from unauthorized domain returns None."""
    app, am = create_oauth_app(monkeypatch)

    userinfo = {**VALID_USERINFO, "hd": "evil.com", "email": "hacker@evil.com"}
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("evil-token")
    assert user is None


def test_parse_oauth_token_multiple_domains(monkeypatch, mocker):
    """Test all three allowed domains work."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    for domain, email in [
        ("lacallegroup.com", "zeb@lacallegroup.com"),
        ("continued.com", "jane@continued.com"),
        ("simucase.com", "bob@simucase.com"),
    ]:
        userinfo = {**VALID_USERINFO, "hd": domain, "email": email}
        mock_resp = mocker.Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = userinfo
        mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

        # Clear cache between iterations
        am._oauth_userinfo_cache.clear()

        user = am._parse_oauth_token(f"token-for-{domain}")
        assert user is not None, f"Expected user for domain {domain}"
        assert user.name == email


def test_parse_oauth_token_unverified_email(monkeypatch, mocker):
    """Unverified email returns None."""
    app, am = create_oauth_app(monkeypatch)

    userinfo = {**VALID_USERINFO, "email_verified": False}
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("unverified-token")
    assert user is None


def test_parse_oauth_token_invalid_token(monkeypatch, mocker):
    """Userinfo returns 401, assert returns None."""
    app, am = create_oauth_app(monkeypatch)

    mock_resp = mocker.Mock()
    mock_resp.status_code = 401
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("invalid-token")
    assert user is None


def test_parse_oauth_token_network_error(monkeypatch, mocker):
    """Network error during userinfo call returns None."""
    import requests

    app, am = create_oauth_app(monkeypatch)

    mocker.patch(
        "zsuite.webservice.auth.http_requests.get",
        side_effect=requests.ConnectionError("connection refused"),
    )

    user = am._parse_oauth_token("network-error-token")
    assert user is None


def test_parse_oauth_token_missing_email(monkeypatch, mocker):
    """Userinfo response with no email field returns None."""
    app, am = create_oauth_app(monkeypatch)

    userinfo = {
        "sub": "1234567890",
        "email_verified": True,
        "hd": "lacallegroup.com",
    }
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("no-email-token")
    assert user is None


def test_parse_oauth_token_empty_email(monkeypatch, mocker):
    """Userinfo response with empty email string returns None."""
    app, am = create_oauth_app(monkeypatch)

    userinfo = {
        "sub": "1234567890",
        "email": "",
        "email_verified": True,
        "hd": "lacallegroup.com",
    }
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("empty-email-token")
    assert user is None


def test_parse_oauth_token_malformed_json(monkeypatch, mocker):
    """Userinfo response with non-JSON body returns None."""
    app, am = create_oauth_app(monkeypatch)

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("No JSON object could be decoded")
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("bad-json-token")
    assert user is None


def test_parse_oauth_token_caching(monkeypatch, mocker):
    """Call twice with same token, verify userinfo endpoint called only once."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    # First call - should hit the endpoint
    user1 = am._parse_oauth_token("cached-token")
    assert user1 is not None

    # Second call - should use cache
    user2 = am._parse_oauth_token("cached-token")
    assert user2 is not None
    assert user2.name == user1.name

    # Verify HTTP call was made only once
    mock_get.assert_called_once()


def test_parse_oauth_token_invalid_cached(monkeypatch, mocker):
    """Invalid tokens are also cached to avoid repeated calls."""
    app, am = create_oauth_app(monkeypatch)

    mock_resp = mocker.Mock()
    mock_resp.status_code = 401
    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    # First call
    user1 = am._parse_oauth_token("bad-cached-token")
    assert user1 is None

    # Second call - should use cache
    user2 = am._parse_oauth_token("bad-cached-token")
    assert user2 is None

    # Verify HTTP call was made only once
    mock_get.assert_called_once()


def test_parse_oauth_token_no_hd_claim(monkeypatch, mocker):
    """Personal Google account (no hd claim) rejected when domains configured."""
    app, am = create_oauth_app(monkeypatch)

    userinfo = {
        "sub": "9999",
        "email": "someone@gmail.com",
        "email_verified": True,
        # no "hd" claim -- personal account
    }
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("personal-token")
    assert user is None


def test_parse_oauth_token_no_domains_restriction(monkeypatch, mocker):
    """When OAUTH_ALLOWED_DOMAINS is empty, any domain is accepted."""
    app, am = create_oauth_app(monkeypatch, OAUTH_ALLOWED_DOMAINS="", OAUTH_DEFAULT_ROLES="reader")

    userinfo = {
        "sub": "9999",
        "email": "anyone@anywhere.com",
        "email_verified": True,
        "hd": "anywhere.com",
    }
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("open-token")
    assert isinstance(user, User)
    assert user.name == "anyone@anywhere.com"


# ==================== OAuth Roles Tests ====================


def test_oauth_roles_from_file(monkeypatch, tmp_path):
    """Test email-to-role mapping from YAML file."""
    roles_yaml = tmp_path / "oauth_roles.yaml"
    roles_yaml.write_text(
        "default_roles:\n"
        "  - reader\n"
        "users:\n"
        "  - email: zeb@lacallegroup.com\n"
        "    roles: [admin, developer]\n"
        "  - email: jane@continued.com\n"
        "    roles: [developer]\n"
    )

    role_map, default_roles = load_oauth_roles(str(roles_yaml))
    assert role_map["zeb@lacallegroup.com"] == ["admin", "developer"]
    assert role_map["jane@continued.com"] == ["developer"]
    assert default_roles == ["reader"]


def test_oauth_default_roles(monkeypatch, mocker):
    """Test fallback to default_roles when email not in mapping."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="viewer,reader")

    userinfo = {**VALID_USERINFO, "email": "newperson@lacallegroup.com"}
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("new-user-token")
    assert user is not None
    assert "viewer" in user.roles
    assert "reader" in user.roles


def test_oauth_roles_file_not_found(monkeypatch):
    """Test OAuthError raised when roles file not found."""
    with pytest.raises(OAuthError, match="OAuth roles file not found"):
        load_oauth_roles("/nonexistent/oauth_roles.yaml")


def test_oauth_roles_file_with_mapped_user(monkeypatch, mocker, tmp_path):
    """Test that users in the role map get their specific roles, not defaults."""
    roles_yaml = tmp_path / "oauth_roles.yaml"
    roles_yaml.write_text(
        "default_roles:\n  - reader\nusers:\n  - email: zeb@lacallegroup.com\n    roles: [admin, developer]\n"
    )

    app, am = create_oauth_app(monkeypatch, OAUTH_ROLES_FILE=str(roles_yaml))

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("zeb-token")
    assert user is not None
    assert "admin" in user.roles
    assert "developer" in user.roles
    assert "reader" not in user.roles  # should NOT get default roles


def test_oauth_roles_file_defaults_for_unmapped(monkeypatch, mocker, tmp_path):
    """Test that unmapped users get default_roles from the file."""
    roles_yaml = tmp_path / "oauth_roles.yaml"
    roles_yaml.write_text("default_roles:\n  - reader\nusers:\n  - email: zeb@lacallegroup.com\n    roles: [admin]\n")

    app, am = create_oauth_app(monkeypatch, OAUTH_ROLES_FILE=str(roles_yaml))

    userinfo = {**VALID_USERINFO, "email": "other@lacallegroup.com"}
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = userinfo
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("other-token")
    assert user is not None
    assert "reader" in user.roles
    assert "admin" not in user.roles


# ==================== 401 Response Tests ====================


def test_oauth_401_includes_www_authenticate(monkeypatch, mocker):
    """When OAuth enabled, 401 responses include the WWW-Authenticate header."""
    app, am = create_oauth_app(monkeypatch)

    # Mock userinfo to return invalid so we get a 401
    mock_resp = mocker.Mock()
    mock_resp.status_code = 401
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    client = app.test_client()
    response = client.get("/private", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert "oauth-protected-resource" in response.headers["WWW-Authenticate"]
    assert "cartographer.example.com" in response.headers["WWW-Authenticate"]


def test_oauth_401_no_header_when_disabled(monkeypatch):
    """When OAuth disabled, 401 responses don't include WWW-Authenticate."""
    app = HALOFlask(__name__)

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    am.security_preflight()

    client = app.test_client()
    response = client.get("/private", headers={"Authorization": "Bearer bad-token"})
    assert response.status_code == 401
    assert "WWW-Authenticate" not in response.headers


# ==================== Integration / Coexistence Tests ====================


def test_get_user_chain_persistent_token_priority(monkeypatch, mocker):
    """Persistent token takes priority over OAuth."""
    app, am = create_oauth_app(monkeypatch)

    # Should NOT call userinfo because persistent token matches first
    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get")

    client = app.test_client()
    response = client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})
    assert response.status_code == 200

    # Verify OAuth was never called
    mock_get.assert_not_called()


def test_oauth_coexists_with_persistent_tokens(monkeypatch, mocker):
    """Both persistent tokens and OAuth work in same app simultaneously."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="admin")

    # Test 1: Persistent token works
    client = app.test_client()
    response = client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})
    assert response.status_code == 200

    # Test 2: OAuth token works
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    response = client.get("/private", headers={"Authorization": "Bearer oauth-token-here"})
    assert response.status_code == 200


def test_oauth_user_on_private_any_endpoint(monkeypatch, mocker):
    """OAuth user can access endpoint requiring any authenticated user."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    client = app.test_client()
    response = client.get("/private_any", headers={"Authorization": "Bearer oauth-token"})
    assert response.status_code == 200


def test_oauth_user_missing_role_gets_403(monkeypatch, mocker):
    """OAuth user without required role gets 403."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    client = app.test_client()
    # /private requires "admin" role, but user only has "reader"
    response = client.get("/private", headers={"Authorization": "Bearer oauth-token"})
    assert response.status_code == 403


# ==================== Security Preflight Tests ====================


def test_oauth_preflight_missing_resource_url(monkeypatch):
    """Preflight fails if OAUTH_RESOURCE_URL not set."""
    monkeypatch.setenv("OAUTH_ENABLED", "true")
    monkeypatch.setenv("OAUTH_ALLOWED_DOMAINS", "lacallegroup.com")
    # Deliberately not setting OAUTH_RESOURCE_URL

    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    with pytest.raises(OAuthError, match="OAUTH_RESOURCE_URL is not configured"):
        am.security_preflight()


def test_oauth_preflight_missing_roles_file_warns(monkeypatch):
    """Preflight raises error if OAUTH_ROLES_FILE set but file doesn't exist."""
    monkeypatch.setenv("OAUTH_ENABLED", "true")
    monkeypatch.setenv("OAUTH_ALLOWED_DOMAINS", "lacallegroup.com")
    monkeypatch.setenv("OAUTH_RESOURCE_URL", "https://example.com")
    monkeypatch.setenv("OAUTH_ROLES_FILE", "/nonexistent/roles.yaml")

    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    with pytest.raises(OAuthError, match="OAuth roles file not found"):
        AuthManager(app, persistent_tokens=TEST_TOKENS)


def test_oauth_preflight_no_domains_warns(monkeypatch, caplog):
    """Preflight warns when OAUTH_ALLOWED_DOMAINS is empty."""
    monkeypatch.setenv("OAUTH_ENABLED", "true")
    monkeypatch.setenv("OAUTH_RESOURCE_URL", "https://example.com")
    # Not setting OAUTH_ALLOWED_DOMAINS

    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    with caplog.at_level("WARNING"):
        am.security_preflight()

    assert "OAUTH_ALLOWED_DOMAINS is not set" in caplog.text


# ==================== X-Forwarded-Access-Token Tests ====================


def test_forwarded_token_valid(monkeypatch, mocker):
    """X-Forwarded-Access-Token header is validated as an OAuth token."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="admin")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    client = app.test_client()
    response = client.get("/private", headers={"X-Forwarded-Access-Token": "proxy-oauth-token"})
    assert response.status_code == 200


def test_forwarded_token_invalid(monkeypatch, mocker):
    """Invalid X-Forwarded-Access-Token returns 401."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="admin")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 401
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    client = app.test_client()
    response = client.get("/private", headers={"X-Forwarded-Access-Token": "bad-token"})
    assert response.status_code == 401


def test_forwarded_token_ignored_when_oauth_disabled(monkeypatch):
    """X-Forwarded-Access-Token is ignored when OAuth is not enabled."""
    app = HALOFlask(__name__)

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    am.security_preflight()

    client = app.test_client()
    response = client.get("/private", headers={"X-Forwarded-Access-Token": "some-token"})
    assert response.status_code == 401


def test_forwarded_token_authorization_header_takes_precedence(monkeypatch, mocker):
    """Authorization header is checked before X-Forwarded-Access-Token."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="admin")

    # Persistent token in Authorization header should work without hitting userinfo
    client = app.test_client()
    response = client.get(
        "/private",
        headers={
            "Authorization": "Bearer abc1234567890123",
            "X-Forwarded-Access-Token": "some-oauth-token",
        },
    )
    assert response.status_code == 200


def test_forwarded_token_missing_role_gets_403(monkeypatch, mocker):
    """OAuth user via forwarded token without required role gets 403."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    client = app.test_client()
    # /private requires "admin" role, but user only has "reader"
    response = client.get("/private", headers={"X-Forwarded-Access-Token": "proxy-oauth-token"})
    assert response.status_code == 403


# ==================== Token Audience Validation Tests ====================


def _mock_oauth_responses(mocker, tokeninfo=None, tokeninfo_status=200, userinfo=None, userinfo_status=200):
    """Mock http_requests.get to serve both the tokeninfo and userinfo endpoints by URL."""

    def fake_get(url, **kwargs):
        resp = mocker.Mock()
        if "tokeninfo" in url:
            resp.status_code = tokeninfo_status
            resp.json.return_value = tokeninfo or {}
        else:
            resp.status_code = userinfo_status
            resp.json.return_value = userinfo or {}
        return resp

    return mocker.patch("zsuite.webservice.auth.http_requests.get", side_effect=fake_get)


def test_oauth_audience_allowed(monkeypatch, mocker):
    """Token issued to an allowed client ID authenticates."""
    app, am = create_oauth_app(
        monkeypatch, OAUTH_DEFAULT_ROLES="reader", OAUTH_ALLOWED_CLIENT_IDS="client-123.apps.googleusercontent.com"
    )
    _mock_oauth_responses(mocker, tokeninfo={"aud": "client-123.apps.googleusercontent.com"}, userinfo=VALID_USERINFO)

    user = am._parse_oauth_token("aud-ok-token")
    assert isinstance(user, User)
    assert user.name == "zeb@lacallegroup.com"


def test_oauth_audience_rejected(monkeypatch, mocker):
    """Token issued to a different OAuth application is rejected before userinfo is consulted."""
    app, am = create_oauth_app(
        monkeypatch, OAUTH_DEFAULT_ROLES="reader", OAUTH_ALLOWED_CLIENT_IDS="client-123.apps.googleusercontent.com"
    )
    mock_get = _mock_oauth_responses(
        mocker, tokeninfo={"aud": "evil-app.apps.googleusercontent.com"}, userinfo=VALID_USERINFO
    )

    user = am._parse_oauth_token("aud-bad-token")
    assert user is None
    # Only tokeninfo should have been called; userinfo never consulted
    assert mock_get.call_count == 1
    assert "tokeninfo" in mock_get.call_args[0][0]


def test_oauth_audience_multiple_client_ids(monkeypatch, mocker):
    """Any client ID in the comma-separated allowlist is accepted."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader", OAUTH_ALLOWED_CLIENT_IDS="client-a, client-b")
    _mock_oauth_responses(mocker, tokeninfo={"aud": "client-b"}, userinfo=VALID_USERINFO)

    user = am._parse_oauth_token("aud-second-client-token")
    assert user is not None


def test_oauth_audience_tokeninfo_error_fails_closed(monkeypatch, mocker):
    """Tokeninfo returning an error rejects the token."""
    app, am = create_oauth_app(monkeypatch, OAUTH_ALLOWED_CLIENT_IDS="client-123")
    _mock_oauth_responses(mocker, tokeninfo_status=400, userinfo=VALID_USERINFO)

    assert am._parse_oauth_token("expired-token") is None


def test_oauth_no_client_ids_skips_tokeninfo(monkeypatch, mocker):
    """Without OAUTH_ALLOWED_CLIENT_IDS, behavior is unchanged: only userinfo is called."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    user = am._parse_oauth_token("legacy-token")
    assert user is not None
    mock_get.assert_called_once()
    assert "userinfo" in mock_get.call_args[0][0]


def test_oauth_preflight_warns_without_client_ids(monkeypatch, caplog):
    """Preflight logs critical when OAUTH_ALLOWED_CLIENT_IDS is not set."""
    monkeypatch.delenv("OAUTH_ALLOWED_CLIENT_IDS", raising=False)
    app, am = create_oauth_app(monkeypatch)

    with caplog.at_level("CRITICAL"):
        am.security_preflight()
    assert "OAUTH_ALLOWED_CLIENT_IDS is not set" in caplog.text


# ==================== Cache Hardening Tests ====================


def test_oauth_cache_keys_are_hashed(monkeypatch, mocker):
    """Raw OAuth tokens are never used as cache keys."""
    import hashlib

    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = VALID_USERINFO
    mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    token = "raw-oauth-token-value"
    user = am._parse_oauth_token(token)
    assert user is not None
    assert token not in am._oauth_userinfo_cache
    assert hashlib.sha256(token.encode()).hexdigest() in am._oauth_userinfo_cache


def test_oauth_invalid_tokens_use_negative_cache(monkeypatch, mocker):
    """Invalid tokens land in the negative cache, not the positive cache."""
    import hashlib

    app, am = create_oauth_app(monkeypatch)

    mock_resp = mocker.Mock()
    mock_resp.status_code = 401
    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get", return_value=mock_resp)

    token = "invalid-token-value"
    assert am._parse_oauth_token(token) is None
    assert am._parse_oauth_token(token) is None
    mock_get.assert_called_once()  # second call served from negative cache

    digest = hashlib.sha256(token.encode()).hexdigest()
    assert digest in am._oauth_negative_cache
    assert digest not in am._oauth_userinfo_cache


def test_oauth_garbage_tokens_do_not_evict_valid_users(monkeypatch, mocker):
    """Spraying invalid tokens churns only the negative cache; valid entries survive."""
    app, am = create_oauth_app(monkeypatch, OAUTH_DEFAULT_ROLES="reader")

    valid_resp = mocker.Mock()
    valid_resp.status_code = 200
    valid_resp.json.return_value = VALID_USERINFO
    invalid_resp = mocker.Mock()
    invalid_resp.status_code = 401

    def fake_get(url, headers=None, **kwargs):
        token = (headers or {}).get("Authorization", "")
        return valid_resp if "good-token" in token else invalid_resp

    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get", side_effect=fake_get)

    assert am._parse_oauth_token("good-token") is not None
    calls_after_valid = mock_get.call_count

    # Spray more garbage tokens than the negative cache can hold
    for i in range(300):
        assert am._parse_oauth_token(f"garbage-token-{i}") is None

    # The valid token is still served from the positive cache -- no new HTTP call
    assert am._parse_oauth_token("good-token") is not None
    assert mock_get.call_count == calls_after_valid + 300
