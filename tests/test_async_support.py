"""Tests for async endpoint support in HALOFlask and AuthManager"""

import asyncio

import pytest

from zsuite.webservice import AuthManager, HALOFlask, auth_required, public_endpoint
from zsuite.webservice.halo_flask import current_user, skip_logging

TEST_TOKENS = [
    {
        "username": "async_user",
        "roles": ["admin", "developer"],
        "tokens": ["async_token_1234567890"],
    },
    {
        "username": "basic_user",
        "roles": ["user"],
        "tokens": ["basic_token_0987654321"],
    },
]


@pytest.fixture
def async_client(monkeypatch):
    """Create a test client with async endpoint support."""
    monkeypatch.setenv("AUTH_ENABLED", "True")
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/async_public")
    @public_endpoint
    async def async_public():
        await asyncio.sleep(0.001)
        return {"status": "public", "message": "async works"}

    @app.route("/async_protected")
    @auth_required(["admin"])
    async def async_protected():
        await asyncio.sleep(0.001)
        user = current_user()
        return {"status": "protected", "username": user.name}

    @app.route("/async_no_roles")
    @auth_required
    async def async_no_roles():
        await asyncio.sleep(0.001)
        return {"status": "authenticated"}

    @app.route("/async_with_skip_logging")
    @skip_logging
    @public_endpoint
    async def async_with_skip_logging():
        await asyncio.sleep(0.001)
        return {"status": "logged"}

    @app.route("/sync_endpoint")
    @auth_required(["admin"])
    def sync_endpoint():
        user = current_user()
        return {"status": "sync", "username": user.name}

    am.security_preflight()
    return app.test_client()


def test_async_public_endpoint(async_client):
    """Test that async public endpoints work without authentication."""
    response = async_client.get("/async_public")
    assert response.status_code == 200
    assert response.json["status"] == "public"
    assert response.json["message"] == "async works"


def test_async_protected_endpoint_no_auth(async_client):
    """Test that async protected endpoints require authentication."""
    response = async_client.get("/async_protected")
    assert response.status_code == 401


def test_async_protected_endpoint_with_auth(async_client):
    """Test that async protected endpoints work with valid authentication."""
    response = async_client.get("/async_protected", headers={"Authorization": "Bearer async_token_1234567890"})
    assert response.status_code == 200
    assert response.json["status"] == "protected"
    assert response.json["username"] == "async_user"


def test_async_protected_endpoint_wrong_role(async_client):
    """Test that async protected endpoints enforce role requirements."""
    # basic_user doesn't have admin role
    response = async_client.get("/async_protected", headers={"Authorization": "Bearer basic_token_0987654321"})
    assert response.status_code == 403


def test_async_auth_required_no_roles(async_client):
    """Test async endpoint with auth_required but no specific roles."""
    response = async_client.get("/async_no_roles", headers={"Authorization": "Bearer basic_token_0987654321"})
    assert response.status_code == 200
    assert response.json["status"] == "authenticated"


def test_async_json_serialization(async_client):
    """Test automatic JSON serialization for async endpoints."""
    response = async_client.get("/async_public")
    assert response.status_code == 200
    assert "application/json" in response.content_type
    assert isinstance(response.json, dict)


def test_async_with_current_user(async_client):
    """Test that current_user() works in async endpoints."""
    response = async_client.get("/async_protected", headers={"Authorization": "Bearer async_token_1234567890"})
    assert response.status_code == 200
    assert response.json["username"] == "async_user"


def test_async_skip_logging_decorator(async_client):
    """Test that skip_logging decorator works with async endpoints."""
    # Just verify the endpoint works - checking actual logging behavior
    # would require inspecting logs which is tested elsewhere
    response = async_client.get("/async_with_skip_logging")
    assert response.status_code == 200
    assert response.json["status"] == "logged"


def test_sync_and_async_coexist(async_client):
    """Test that sync and async endpoints can coexist in the same app."""
    # Test async endpoint
    async_response = async_client.get("/async_protected", headers={"Authorization": "Bearer async_token_1234567890"})
    assert async_response.status_code == 200
    assert async_response.json["status"] == "protected"

    # Test sync endpoint
    sync_response = async_client.get("/sync_endpoint", headers={"Authorization": "Bearer async_token_1234567890"})
    assert sync_response.status_code == 200
    assert sync_response.json["status"] == "sync"


def test_async_dict_return():
    """Test async endpoint returning dict."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return {"key": "value"}

    client = app.test_client()
    response = client.get("/test")
    assert response.status_code == 200
    assert response.json["key"] == "value"


def test_async_list_return():
    """Test async endpoint returning list."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return [1, 2, 3]

    client = app.test_client()
    response = client.get("/test")
    assert response.status_code == 200
    assert response.json == [1, 2, 3]


def test_async_tuple_with_status():
    """Test async endpoint returning tuple with status code."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return {"created": True}, 201

    client = app.test_client()
    response = client.get("/test")
    assert response.status_code == 201
    assert response.json["created"] is True


def test_async_tuple_with_headers():
    """Test async endpoint returning tuple with headers."""
    app = HALOFlask(__name__)

    @app.route("/test")
    @public_endpoint
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return {"data": "test"}, 200, {"X-Custom": "header"}

    client = app.test_client()
    response = client.get("/test")
    assert response.status_code == 200
    assert response.json["data"] == "test"
    assert response.headers.get("X-Custom") == "header"


def test_async_auth_required_with_roles_kwarg():
    """Test async endpoint with auth_required using roles keyword argument."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @auth_required(roles=["admin"])
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return {"status": "ok"}

    am.security_preflight()
    client = app.test_client()
    response = client.get("/test", headers={"Authorization": "Bearer async_token_1234567890"})
    assert response.status_code == 200


def test_async_auth_required_with_roles_positional():
    """Test async endpoint with auth_required using roles as positional argument."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @auth_required(["admin"])
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return {"status": "ok"}

    am.security_preflight()
    client = app.test_client()
    response = client.get("/test", headers={"Authorization": "Bearer async_token_1234567890"})
    assert response.status_code == 200


def test_async_multiple_decorators():
    """Test async endpoint with multiple decorators stacked."""
    app = HALOFlask(__name__)
    am = AuthManager(app, persistent_tokens=TEST_TOKENS)

    @app.route("/test")
    @skip_logging
    @auth_required(["admin"])
    async def test_endpoint():
        await asyncio.sleep(0.001)
        return {"status": "ok"}

    am.security_preflight()
    client = app.test_client()
    response = client.get("/test", headers={"Authorization": "Bearer async_token_1234567890"})
    assert response.status_code == 200
    assert response.json["status"] == "ok"
