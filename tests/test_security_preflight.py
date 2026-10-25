import pytest

from zsuite.exceptions import MissingRBACError
from zsuite.webservice import AuthManager, HALOFlask, auth_required

TEST_TOKENS = {
    "TEST_TOKEN_FOR_SERVICE_ONE": {"username": "service1", "roles": ["admin"]},
    "TEST_TOKEN_FOR_SERVICE_TWO": {"username": "service2", "roles": ["editor", "user"]},
}


@pytest.fixture
def app():
    app = HALOFlask(__name__)
    return app


@pytest.fixture
def auth_manager(app):
    return AuthManager(app)


def test_missing_rbac_decorators(auth_manager):
    def dummy_route():
        pass

    auth_manager.app.add_url_rule("/dummy", "dummy", dummy_route)

    with pytest.raises(MissingRBACError):
        auth_manager.security_preflight()


def test_no_persistent_tokens(auth_manager, monkeypatch):
    monkeypatch.setenv("AUTH_TOKENS_FILE", "some_file_path")
    auth_manager.persistent_tokens = None

    with pytest.raises(ValueError):
        auth_manager.security_preflight()


def test_no_signing_keys(auth_manager, monkeypatch):
    monkeypatch.setenv("JWKS_URL", "some_url")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    auth_manager._signing_keys = None

    with pytest.raises(ValueError):
        auth_manager.security_preflight()


def test_successful_preflight(auth_manager):
    @auth_required
    def dummy_route():
        pass

    auth_manager.app.add_url_rule("/dummy", "dummy", dummy_route)

    # Assuming other conditions are met
    auth_manager.security_preflight()  # Should not raise any exception
