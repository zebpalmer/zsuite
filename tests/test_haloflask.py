from unittest.mock import patch

import pytest

from zsuite.webservice import HALOFlask  # replace 'your_module' with the actual module name


# Mock the logging
@pytest.fixture
def mock_logger():
    with patch("logging.Logger.info") as mock_log:
        yield mock_log


@pytest.fixture
def client(mock_logger, monkeypatch):
    monkeypatch.setenv("ACCESS_LOGGING_ENABLED", "true")
    app = HALOFlask(__name__)

    @app.route("/test")
    def test_route():
        return "Test", 200

    client = app.test_client()
    return client


def test_access_logging(client, mock_logger):
    response = client.get("/test")
    assert response.status_code == 200

    # Now check if the logger was called with a log line that includes the expected parts.
    # Note: This is a loose check. You can make it stricter based on your requirements.
    mock_logger.assert_called()
    log_line = mock_logger.call_args[0][0]
    assert "GET /test" in log_line
    assert "200 OK" in log_line
    assert "ms" in log_line


@pytest.fixture
def tuple_app(monkeypatch):
    monkeypatch.setenv("ACCESS_LOGGING_ENABLED", "false")
    monkeypatch.setenv("PROXY_FIX_ENABLED", "false")
    app = HALOFlask(__name__)

    @app.route("/dict-only")
    def dict_only():
        return ({"a": 1},)

    @app.route("/dict-status")
    def dict_status():
        return {"a": 1}, 201

    @app.route("/dict-headers")
    def dict_headers():
        return {"a": 1}, {"X-Custom": "yes"}

    @app.route("/dict-status-headers")
    def dict_status_headers():
        return {"a": 1}, 202, {"X-Custom": "yes"}

    @app.route("/list-status")
    def list_status():
        return [1, 2, 3], 200

    return app.test_client()


def test_make_response_single_element_tuple(tuple_app):
    response = tuple_app.get("/dict-only")
    assert response.status_code == 200
    assert response.get_json() == {"a": 1}


def test_make_response_dict_with_status(tuple_app):
    response = tuple_app.get("/dict-status")
    assert response.status_code == 201
    assert response.get_json() == {"a": 1}


def test_make_response_dict_with_headers(tuple_app):
    response = tuple_app.get("/dict-headers")
    assert response.status_code == 200
    assert response.headers["X-Custom"] == "yes"
    assert response.get_json() == {"a": 1}


def test_make_response_dict_with_status_and_headers(tuple_app):
    response = tuple_app.get("/dict-status-headers")
    assert response.status_code == 202
    assert response.headers["X-Custom"] == "yes"
    assert response.get_json() == {"a": 1}


def test_make_response_list_with_status(tuple_app):
    response = tuple_app.get("/list-status")
    assert response.status_code == 200
    assert response.get_json() == [1, 2, 3]


def test_skip_logging_suppresses_access_log(monkeypatch):
    from zsuite.webservice import skip_logging

    monkeypatch.setenv("ACCESS_LOGGING_ENABLED", "true")
    monkeypatch.setenv("PROXY_FIX_ENABLED", "false")
    app = HALOFlask(__name__)

    @app.route("/quiet")
    @skip_logging
    def quiet():
        return "ok", 200

    with patch("logging.info") as mock_info:
        response = app.test_client().get("/quiet")
        assert response.status_code == 200
        logged = [call.args[0] for call in mock_info.call_args_list if call.args]
        assert not any("GET /quiet" in str(line) for line in logged)


def test_current_ws_returns_app(monkeypatch):
    from zsuite.webservice import current_ws

    monkeypatch.setenv("ACCESS_LOGGING_ENABLED", "false")
    monkeypatch.setenv("PROXY_FIX_ENABLED", "false")
    app = HALOFlask(__name__)

    @app.route("/whoami")
    def whoami():
        return {"name": current_ws().name}, 200

    response = app.test_client().get("/whoami")
    assert response.status_code == 200
    assert response.get_json()["name"] == __name__
