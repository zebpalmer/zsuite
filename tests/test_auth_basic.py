"""Tests for HTTP Basic auth support in AuthManager."""

import base64
import hashlib

import pytest
from werkzeug.security import generate_password_hash

from zsuite.exceptions import BasicAuthError
from zsuite.webservice import AuthManager, HALOFlask, auth_required, public_endpoint
from zsuite.webservice.auth import User, load_basic_auth_users

TEST_TOKENS = [
    {
        "username": "alice",
        "roles": ["admin", "developer"],
        "tokens": ["abc1234567890123", "xyz9876543210987"],
    },
]

# Low-iteration pbkdf2 keeps the test suite fast; production uses werkzeug's default (scrypt)
HASH_METHOD = "pbkdf2:sha256:1000"
ALICE_PASSWORD = "alice-s3cret-password"
BOB_PASSWORD = "bob-s3cret-password"
ALICE_HASH = generate_password_hash(ALICE_PASSWORD, method=HASH_METHOD)
BOB_HASH = generate_password_hash(BOB_PASSWORD, method=HASH_METHOD)


def basic_header(username, password):
    """Build an Authorization header for HTTP Basic auth."""
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def write_creds_file(tmp_path):
    """Write a Basic auth credentials YAML file and return its path."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text(
        "users:\n"
        "  - username: alice\n"
        f'    password_hash: "{ALICE_HASH}"\n'
        "    roles: [admin, developer]\n"
        "  - username: bob\n"
        f'    password_hash: "{BOB_HASH}"\n'
        "    roles: [reader]\n"
    )
    return str(creds_yaml)


def create_basic_auth_app(monkeypatch, tmp_path, roles_resolver=None, **env_overrides):
    """Helper to create a Flask app with Basic auth enabled."""
    monkeypatch.setenv("BASIC_AUTH_ENABLED", "true")
    monkeypatch.setenv("BASIC_AUTH_FILE", write_creds_file(tmp_path))
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

    am = AuthManager(app, persistent_tokens=TEST_TOKENS, roles_resolver=roles_resolver)
    am.security_preflight()
    return app, am


# ==================== Feature Flag Tests ====================


def test_basic_auth_disabled_by_default():
    """Verify _basic_auth_enabled is False when BASIC_AUTH_ENABLED is not set."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    assert am._basic_auth_enabled is False


def test_basic_auth_ignored_when_disabled():
    """Basic auth header is not honored when the feature is disabled."""
    app = HALOFlask(__name__)

    @app.route("/private")
    @auth_required(["admin"])
    def private_route():
        return "Private", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    am.security_preflight()

    client = app.test_client()
    response = client.get("/private", headers=basic_header("alice", ALICE_PASSWORD))
    assert response.status_code == 401


# ==================== Credential Validation Tests ====================


def test_valid_credentials(monkeypatch, tmp_path):
    """Valid username and password authenticate and satisfy role checks."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers=basic_header("alice", ALICE_PASSWORD))
    assert response.status_code == 200


def test_wrong_password(monkeypatch, tmp_path):
    """Wrong password returns 401."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers=basic_header("alice", "wrong-password"))
    assert response.status_code == 401


def test_unknown_username(monkeypatch, tmp_path):
    """Unknown username returns 401."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers=basic_header("mallory", ALICE_PASSWORD))
    assert response.status_code == 401


def test_username_case_insensitive(monkeypatch, tmp_path):
    """Usernames are matched case-insensitively."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers=basic_header("ALICE", ALICE_PASSWORD))
    assert response.status_code == 200


def test_missing_role_gets_403(monkeypatch, tmp_path):
    """Authenticated user without the required role gets 403."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    # /private requires "admin" role, but bob only has "reader"
    response = client.get("/private", headers=basic_header("bob", BOB_PASSWORD))
    assert response.status_code == 403


def test_any_authenticated_endpoint(monkeypatch, tmp_path):
    """Basic auth user can access endpoint requiring any authenticated user."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private_any", headers=basic_header("bob", BOB_PASSWORD))
    assert response.status_code == 200


def test_user_injected_with_roles(monkeypatch, tmp_path):
    """Authenticated user is parsed with the roles from the credentials file."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    with app.test_request_context(headers=basic_header("alice", ALICE_PASSWORD)):
        user = am.get_user()
    assert isinstance(user, User)
    assert user.name == "alice"
    assert user.roles == {"admin", "developer"}


# ==================== Malformed Header Tests ====================


def test_malformed_base64(monkeypatch, tmp_path):
    """Invalid base64 in the Basic header returns 401."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers={"Authorization": "Basic not-valid-base64!!!"})
    assert response.status_code == 401


def test_no_colon_in_credentials(monkeypatch, tmp_path):
    """Decoded credentials without a colon separator return 401."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    creds = base64.b64encode(b"no-colon-here").decode()
    client = app.test_client()
    response = client.get("/private", headers={"Authorization": f"Basic {creds}"})
    assert response.status_code == 401


def test_empty_password(monkeypatch, tmp_path):
    """Empty password returns 401."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers=basic_header("alice", ""))
    assert response.status_code == 401


def test_empty_username(monkeypatch, tmp_path):
    """Empty username returns 401."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers=basic_header("", ALICE_PASSWORD))
    assert response.status_code == 401


# ==================== WWW-Authenticate Challenge Tests ====================


def test_401_includes_basic_challenge(monkeypatch, tmp_path):
    """401 responses advertise the Basic challenge when Basic auth is enabled."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted", charset="UTF-8"'


def test_401_challenge_custom_realm(monkeypatch, tmp_path):
    """BASIC_AUTH_REALM config var sets the challenge realm."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path, BASIC_AUTH_REALM="Example Internal")
    client = app.test_client()
    response = client.get("/private")
    assert 'Basic realm="Example Internal"' in response.headers["WWW-Authenticate"]


def test_401_includes_both_challenges_with_oauth(monkeypatch, tmp_path):
    """When Basic auth and OAuth are both enabled, 401 advertises both challenges."""
    app, am = create_basic_auth_app(
        monkeypatch,
        tmp_path,
        OAUTH_ENABLED="true",
        OAUTH_RESOURCE_URL="https://api.example.com",
        OAUTH_ALLOWED_DOMAINS="lacallegroup.com",
    )
    client = app.test_client()
    response = client.get("/private")
    assert response.status_code == 401
    challenges = response.headers.get_all("WWW-Authenticate")
    assert any(c.startswith("Basic ") for c in challenges)
    assert any("oauth-protected-resource" in c for c in challenges)


# ==================== Cache Tests ====================


def test_valid_credentials_cached(monkeypatch, tmp_path, mocker):
    """Repeated requests with the same credentials verify the password hash only once."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    mock_check = mocker.patch("zsuite.webservice.auth.check_password_hash", return_value=True)

    client = app.test_client()
    assert client.get("/private", headers=basic_header("alice", ALICE_PASSWORD)).status_code == 200
    assert client.get("/private", headers=basic_header("alice", ALICE_PASSWORD)).status_code == 200
    mock_check.assert_called_once()


def test_invalid_credentials_use_negative_cache(monkeypatch, tmp_path, mocker):
    """Repeated bad credentials only trigger one hash verification."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    mock_check = mocker.patch("zsuite.webservice.auth.check_password_hash", return_value=False)

    client = app.test_client()
    assert client.get("/private", headers=basic_header("alice", "bad-password")).status_code == 401
    assert client.get("/private", headers=basic_header("alice", "bad-password")).status_code == 401
    mock_check.assert_called_once()


def test_cache_keys_are_hashed(monkeypatch, tmp_path):
    """Raw credentials are never used as cache keys."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)

    client = app.test_client()
    assert client.get("/private", headers=basic_header("alice", ALICE_PASSWORD)).status_code == 200

    decoded = f"alice:{ALICE_PASSWORD}"
    assert decoded not in am._basic_auth_cache
    assert ALICE_PASSWORD not in am._basic_auth_cache
    assert hashlib.sha256(decoded.encode()).hexdigest() in am._basic_auth_cache


# ==================== Coexistence Tests ====================


def test_coexists_with_persistent_tokens(monkeypatch, tmp_path):
    """Bearer tokens still work when Basic auth is enabled."""
    app, am = create_basic_auth_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/private", headers={"Authorization": "Bearer abc1234567890123"})
    assert response.status_code == 200


def test_basic_header_does_not_hit_oauth(monkeypatch, tmp_path, mocker):
    """A Basic header is handled by Basic auth, never sent to the OAuth provider."""
    app, am = create_basic_auth_app(
        monkeypatch,
        tmp_path,
        OAUTH_ENABLED="true",
        OAUTH_RESOURCE_URL="https://api.example.com",
        OAUTH_ALLOWED_DOMAINS="lacallegroup.com",
    )
    mock_get = mocker.patch("zsuite.webservice.auth.http_requests.get")

    client = app.test_client()
    response = client.get("/private", headers=basic_header("alice", ALICE_PASSWORD))
    assert response.status_code == 200
    mock_get.assert_not_called()


def test_roles_resolver_applies_to_basic_auth(monkeypatch, tmp_path):
    """A configured roles_resolver replaces the file-derived roles."""

    def resolver(username):
        return {"admin"} if username == "bob" else set()

    app, am = create_basic_auth_app(monkeypatch, tmp_path, roles_resolver=resolver)
    client = app.test_client()

    # bob only has "reader" in the file, but the resolver grants "admin"
    response = client.get("/private", headers=basic_header("bob", BOB_PASSWORD))
    assert response.status_code == 200

    # alice has "admin" in the file, but the resolver strips all roles
    response = client.get("/private", headers=basic_header("alice", ALICE_PASSWORD))
    assert response.status_code == 403


# ==================== Credentials File Tests ====================


def test_load_basic_auth_users(tmp_path):
    """Credentials file is loaded into a lowercase-keyed user map."""
    users = load_basic_auth_users(write_creds_file(tmp_path))
    assert users["alice"]["password_hash"] == ALICE_HASH
    assert users["alice"]["roles"] == ["admin", "developer"]
    assert users["bob"]["roles"] == ["reader"]


def test_load_basic_auth_users_lowercases_usernames(tmp_path):
    """Usernames in the file are lowercased."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text(f'users:\n  - username: Alice\n    password_hash: "{ALICE_HASH}"\n    roles: [admin]\n')
    users = load_basic_auth_users(str(creds_yaml))
    assert "alice" in users


def test_load_basic_auth_users_file_not_found():
    """Missing credentials file raises BasicAuthError."""
    with pytest.raises(BasicAuthError, match="Basic auth credentials file not found"):
        load_basic_auth_users("/nonexistent/basic_auth.yaml")


def test_load_basic_auth_users_rejects_plaintext_password(tmp_path):
    """A 'password' key (plaintext) raises BasicAuthError."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text("users:\n  - username: alice\n    password: plaintext-oops\n    roles: [admin]\n")
    with pytest.raises(BasicAuthError, match="plaintext passwords are not supported"):
        load_basic_auth_users(str(creds_yaml))


def test_load_basic_auth_users_rejects_missing_hash(tmp_path):
    """An entry without a password_hash raises BasicAuthError."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text("users:\n  - username: alice\n    roles: [admin]\n")
    with pytest.raises(BasicAuthError, match="needs a 'password_hash'"):
        load_basic_auth_users(str(creds_yaml))


def test_load_basic_auth_users_rejects_non_hash_value(tmp_path):
    """A password_hash that doesn't look like a werkzeug hash raises BasicAuthError."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text("users:\n  - username: alice\n    password_hash: plaintext-oops\n    roles: [admin]\n")
    with pytest.raises(BasicAuthError, match="needs a 'password_hash'"):
        load_basic_auth_users(str(creds_yaml))


def test_load_basic_auth_users_rejects_missing_username(tmp_path):
    """An entry without a username raises BasicAuthError."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text(f'users:\n  - password_hash: "{ALICE_HASH}"\n    roles: [admin]\n')
    with pytest.raises(BasicAuthError, match="missing 'username'"):
        load_basic_auth_users(str(creds_yaml))


# ==================== Security Preflight Tests ====================


def test_preflight_requires_creds_file(monkeypatch):
    """Preflight fails if BASIC_AUTH_ENABLED is set without BASIC_AUTH_FILE."""
    monkeypatch.setenv("BASIC_AUTH_ENABLED", "true")

    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    with pytest.raises(BasicAuthError, match="BASIC_AUTH_FILE is not configured"):
        am.security_preflight()


def test_preflight_requires_users_loaded(monkeypatch, tmp_path):
    """Preflight fails if the credentials file contains no users."""
    creds_yaml = tmp_path / "basic_auth.yaml"
    creds_yaml.write_text("users: []\n")
    monkeypatch.setenv("BASIC_AUTH_ENABLED", "true")
    monkeypatch.setenv("BASIC_AUTH_FILE", str(creds_yaml))

    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    with pytest.raises(BasicAuthError, match="no Basic auth users were loaded"):
        am.security_preflight()


def test_init_fails_on_missing_creds_file(monkeypatch):
    """AuthManager construction fails if BASIC_AUTH_FILE doesn't exist."""
    monkeypatch.setenv("BASIC_AUTH_ENABLED", "true")
    monkeypatch.setenv("BASIC_AUTH_FILE", "/nonexistent/basic_auth.yaml")

    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    def test_route():
        return "Test", 200

    with pytest.raises(BasicAuthError, match="Basic auth credentials file not found"):
        AuthManager(app, persistent_tokens=TEST_TOKENS)
