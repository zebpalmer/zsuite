from zsuite.webservice import AuthManager, HALOFlask, public_endpoint


def test_route_redirect(monkeypatch):
    app = HALOFlask(__name__)

    @app.route("/trailing_slash/")
    @public_endpoint
    def has_slash():
        return "Hello, World!"

    @app.route("/no_slash")
    @public_endpoint
    def no_slash():
        return "Hello, World!"

    monkeypatch.setenv("AUTH_DISABLED", "true")
    am = AuthManager(app)
    am.security_preflight()

    # Create a test client
    client = app.test_client()

    # Test if accessing the route without trailing slash returns 308
    rv = client.get("/trailing_slash")
    assert rv.status_code == 308
    assert rv.headers["Location"].endswith("/trailing_slash/")

    # Test if accessing a route with extra trailing slash returns 308
    rv = client.get("/no_slash/")
    assert rv.status_code == 308
    assert rv.headers["Location"].endswith("/no_slash")

    # Test if accessing a non-existent route returns 404
    rv = client.get("/non_existent_endpoint")
    assert rv.status_code == 404

    # Test if accessing the correct route works
    rv = client.get("/trailing_slash/")
    assert rv.status_code == 200

    # follow redirect
    rv = client.get("/no_slash/", follow_redirects=True)
    assert rv.status_code == 200
    assert rv.request.path == "/no_slash"
