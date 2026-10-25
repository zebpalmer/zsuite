"""Tests for the AuthManager roles_resolver hook."""

import pytest

from zsuite.webservice import AuthManager, HALOFlask, auth_required
from zsuite.webservice.auth import User

from .test_auth import TEST_TOKENS, generate_test_token, temp_signing_keys

ALICE_TOKEN = "abc1234567890123"  # persistent token for alice (roles: admin, developer)
BOB_TOKEN = "mno7654321098765"  # persistent token for bob (roles: sysadmin)


def create_resolver_app(roles_resolver):
    """Create a test app with a roles_resolver and admin/any-auth endpoints."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS, roles_resolver=roles_resolver)

    @app.route("/admin")
    @auth_required(roles=["admin"])
    def admin_route():
        return "Admin", 200

    @app.route("/any-auth")
    @auth_required
    def any_auth_route():
        return "Authenticated", 200

    am.security_preflight()
    return app


def test_resolver_replaces_roles():
    """Resolver output replaces token-derived roles in both directions."""
    resolver_roles = {"alice": {"viewer"}, "bob": {"admin"}}
    client = create_resolver_app(resolver_roles.get).test_client()

    # alice's token grants admin, but the resolver demotes her to viewer
    response = client.get("/admin", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 403

    # bob's token grants only sysadmin, but the resolver promotes him to admin
    response = client.get("/admin", headers={"Authorization": f"Bearer {BOB_TOKEN}"})
    assert response.status_code == 200


def test_resolver_none_leaves_token_roles(monkeypatch):
    """A resolver returning None leaves the token-derived roles untouched."""
    client = create_resolver_app(lambda _name: None).test_client()

    # Avoid NoneType signing keys when the JWT fallback runs
    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    # alice keeps admin from her token
    response = client.get("/admin", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 200

    # bob keeps sysadmin only, so admin is still forbidden
    response = client.get("/admin", headers={"Authorization": f"Bearer {BOB_TOKEN}"})
    assert response.status_code == 403


def test_resolver_empty_set_forbids_roles():
    """A resolver returning an empty set means authenticated but no roles (403)."""
    client = create_resolver_app(lambda _name: set()).test_client()

    # Role-protected endpoint is forbidden, not unauthorized
    response = client.get("/admin", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 403

    # Endpoint requiring only authentication still works
    response = client.get("/any-auth", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 200


def test_resolver_exception_fails_closed(caplog):
    """A resolver exception must fail closed to no roles, never 500 or fall back."""

    def broken_resolver(name):
        raise RuntimeError("role database unavailable")

    client = create_resolver_app(broken_resolver).test_client()

    # alice's token grants admin, but the failed resolver must not fall back to it
    caplog.set_level("DEBUG")
    response = client.get("/admin", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 403
    assert "roles_resolver failed for alice" in caplog.text

    # Identity survives, so authentication-only endpoints still work
    response = client.get("/any-auth", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 200


def test_resolver_invalid_return_type_fails_closed():
    """A resolver returning an invalid type fails closed to no roles."""
    client = create_resolver_app(lambda _name: "admin").test_client()

    response = client.get("/admin", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 403


def test_default_none_resolver_is_noop(monkeypatch):
    """Default roles_resolver=None preserves existing behavior exactly."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/admin")
    @auth_required(roles=["admin"])
    def admin_route():
        return "Admin", 200

    am.security_preflight()
    client = app.test_client()

    _, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)

    response = client.get("/admin", headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
    assert response.status_code == 200
    response = client.get("/admin", headers={"Authorization": f"Bearer {BOB_TOKEN}"})
    assert response.status_code == 403
    response = client.get("/admin")
    assert response.status_code == 401


def test_resolver_applies_to_jwt_identities(monkeypatch):
    """Resolver applies to JWT identities (Teleport header and Bearer JWT)."""
    client = create_resolver_app(lambda name: {"admin"} if name == "jwt_user" else set()).test_client()

    private_key, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)
    token = generate_test_token(private_key, {"username": "jwt_user", "roles": ["nobody"]})

    # Teleport JWT assertion header
    response = client.get("/admin", headers={"Teleport-Jwt-Assertion": token})
    assert response.status_code == 200

    # Bearer JWT in the Authorization header
    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_resolver_receives_lowercased_name(monkeypatch):
    """Resolver receives User.name, which is always lowercased."""
    seen = []

    def recording_resolver(name):
        seen.append(name)
        return None

    client = create_resolver_app(recording_resolver).test_client()

    private_key, public_key = temp_signing_keys()
    monkeypatch.setenv("JWT_SIGNING_KEY", public_key)
    token = generate_test_token(private_key, {"username": "Mixed.Case@LacalleGroup.com", "roles": ["admin"]})

    response = client.get("/admin", headers={"Teleport-Jwt-Assertion": token})
    assert response.status_code == 200
    assert seen == ["mixed.case@lacallegroup.com"]


def test_apply_roles_resolver_does_not_mutate_original_user():
    """Resolved roles go on a new User so cached User objects are never mutated."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS, roles_resolver=lambda _name: {"resolved"})
    original = User("cached_user", ["original"])

    resolved = am._apply_roles_resolver(original)

    assert resolved is not original
    assert resolved.roles == {"resolved"}
    assert original.roles == {"original"}


def test_apply_roles_resolver_passthrough():
    """_apply_roles_resolver passes through None users and no-resolver configs."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)
    assert am._apply_roles_resolver(None) is None

    user = User("someone", ["admin"])
    assert am._apply_roles_resolver(user) is user

    app2 = HALOFlask(__name__)
    am2 = AuthManager(app2, persistent_tokens=TEST_TOKENS, roles_resolver=lambda _name: {"x"})
    assert am2._apply_roles_resolver(None) is None


@pytest.mark.parametrize("return_value", [["admin"], {"admin"}])
def test_resolver_accepts_list_or_set(return_value):
    """Resolver may return a list or set; both are normalized by User."""
    client = create_resolver_app(lambda _name: return_value).test_client()

    response = client.get("/admin", headers={"Authorization": f"Bearer {BOB_TOKEN}"})
    assert response.status_code == 200


def test_resolver_stored_when_auth_disabled(monkeypatch):
    """The resolver is stored even with AUTH_ENABLED=False.

    get_user() applies the resolver unconditionally, so the attribute must exist
    on the disabled-auth path too — regression test for the assignment living
    inside the AUTH_ENABLED branch and raising AttributeError.
    """
    monkeypatch.setenv("AUTH_ENABLED", "False")
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS, roles_resolver=lambda _name: {"resolved"})

    assert am._apply_roles_resolver(User("someone", ["token-role"])).roles == {"resolved"}

    app2 = HALOFlask(__name__)
    am2 = AuthManager(app2, persistent_tokens=TEST_TOKENS)
    assert am2._apply_roles_resolver(None) is None
