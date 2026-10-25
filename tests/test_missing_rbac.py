import pytest

from zsuite.exceptions import MissingRBACError
from zsuite.webservice import AuthManager, HALOFlask, auth_required, public_endpoint


def test_check_all_endpoints_have_rbac():
    app = HALOFlask(__name__)

    @app.route("/endpoint_missing_decorator")
    def endpoint_missing_decorator():
        return "This endpoint has no RBAC defined"

    @app.route("/public")
    @public_endpoint
    def endpoint_is_public():
        return "This endpoint is public"

    @app.route("/private")
    @auth_required
    def private_endpoint():
        return "this endpoint is private"

    with pytest.raises(MissingRBACError) as excinfo:
        AuthManager(app)  # Attempt to initialize AuthManager with missing auth decorators
    assert "endpoint_missing_decorator" in str(excinfo.value)

    # Simulate the decorator being added after the fact
    endpoint_missing_decorator._rbac_is_defined = True

    # This time it should not raise an exception
    AuthManager(app)


def test_route_registered_after_preflight_is_refused():
    """The per-request backstop must catch undecorated routes that slip past the startup check."""
    app = HALOFlask(__name__)
    am = AuthManager(app)
    am.security_preflight()

    # Registered after preflight -- the startup gate never saw it
    @app.route("/sneaky")
    def sneaky():
        return "should never serve"

    client = app.test_client()
    response = client.get("/sneaky")
    assert response.status_code == 500


def test_auth_required_outermost_overrides_public_flag():
    """auth_required must explicitly mark a view protected, even over a stale public flag."""

    @auth_required(["admin"])
    @public_endpoint
    def closed_view():
        return "closed"

    assert closed_view._is_public is False
    assert closed_view._rbac_is_defined is True


def test_public_endpoint_outermost_overrides_auth_required():
    @public_endpoint
    @auth_required(["admin"])
    def open_view():
        return "open"

    assert open_view._is_public is True


def test_stacked_auth_required_over_public_is_enforced():
    """End-to-end: a stale public flag must not open an auth_required endpoint."""
    app = HALOFlask(__name__)
    am = AuthManager(app)

    @app.route("/locked")
    @auth_required(["admin"])
    @public_endpoint
    def locked():
        return "locked", 200

    am.security_preflight()
    client = app.test_client()
    response = client.get("/locked")
    assert response.status_code == 401
