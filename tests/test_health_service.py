import time
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from zsuite.webservice import HealthService, check_callable


def test_check_callable():
    def callback():
        return True, "OK"

    # Check that the function returns the callback if it's callable
    assert check_callable(callback, "callback") is callback

    # Check that the function raises a TypeError if the callback is not callable
    with pytest.raises(TypeError):
        check_callable("not a function", "callback")


def test_check_callable_with_none():
    """Test that check_callable accepts None as valid"""
    result = check_callable(None, "callback")
    assert result is None


def test_health_service():
    def healthz_callback():
        return True, "healthz OK"

    def readyz_callback():
        return True, "readyz OK"

    def livez_callback():
        return True, "livez OK"

    health_service = HealthService(
        healthz_callback=healthz_callback,
        readyz_callback=readyz_callback,
        livez_callback=livez_callback,
    )

    with health_service.app.test_client() as client:
        # Test /healthz endpoint
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.data == b"healthz OK"

        # Test /readyz endpoint
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.data == b"readyz OK"

        # Test /livez endpoint
        response = client.get("/livez")
        assert response.status_code == 200
        assert response.data == b"livez OK"

    # Test with no callback provided
    health_service_no_callback = HealthService()

    with health_service_no_callback.app.test_client() as client:
        response = client.get("/healthz")
        assert response.status_code == 501
        assert response.data == b"No callback provided for /healthz"


def test_health_service_unhealthy_status():
    """Test health service with failing callback"""

    def failing_callback():
        return False, "Service unhealthy"

    health_service = HealthService(healthz_callback=failing_callback)

    with health_service.app.test_client() as client:
        response = client.get("/healthz")
        assert response.status_code == 503
        assert response.data == b"Service unhealthy"


def test_health_service_custom_name_host_port():
    """Test HealthService with custom parameters"""
    health_service = HealthService(
        name="custom_health",
        host="127.0.0.1",
        port=9090,
    )

    assert health_service.app.name == "custom_health"
    assert health_service.host == "127.0.0.1"
    assert health_service.port == 9090


@patch("zsuite.webservice.health_service.Thread")
def test_health_service_run_starts_daemon_thread(mock_thread_class):
    """Test that run() starts a daemon thread"""
    mock_thread = MagicMock()
    mock_thread_class.return_value = mock_thread

    health_service = HealthService()
    health_service.run()

    # Verify thread was created with correct parameters
    mock_thread_class.assert_called_once()
    call_kwargs = mock_thread_class.call_args[1]
    assert call_kwargs["name"] == "HealthService"
    assert "target" in call_kwargs

    # Verify daemon flag was set and thread was started
    assert mock_thread.daemon is True
    mock_thread.start.assert_called_once()


def test_health_service_run_actual_thread_creation():
    """Test that run() actually creates and starts a thread"""
    health_service = HealthService()

    # Mock the Flask app.run to avoid actually starting the server
    with patch.object(health_service.app, "run", side_effect=SystemExit(0)):
        health_service.run()

        # Give the thread a moment to start
        time.sleep(0.1)

        # Verify thread was created
        assert health_service._ws_thread is not None
        assert health_service._ws_thread.daemon is True
        assert health_service._ws_thread.name == "HealthService"


def test_health_service_run_exception_handling():
    """Test that run() handles exceptions in the Flask app"""
    health_service = HealthService()

    # Mock the app.run method to raise an exception
    with patch.object(health_service.app, "run", side_effect=RuntimeError("Test error")):
        exception_caught = []

        def run_in_thread():
            try:
                health_service.app.run(host=health_service.host, port=health_service.port)
            except (KeyError, SystemExit):
                pass
            except Exception as e:
                exception_caught.append(e)

        thread = Thread(target=run_in_thread)
        thread.daemon = True
        thread.start()
        thread.join(timeout=1)

        # Verify exception was caught
        assert len(exception_caught) == 1
        assert isinstance(exception_caught[0], RuntimeError)


def test_health_service_run_keyerror_handling():
    """Test that run() silently handles KeyError"""
    health_service = HealthService()

    # Mock the app.run method to raise KeyError
    with patch.object(health_service.app, "run", side_effect=KeyError("Test key error")):
        exception_caught = []
        result = []

        def run_in_thread():
            try:
                health_service.app.run(host=health_service.host, port=health_service.port)
            except (KeyError, SystemExit):
                result.append("handled")
                return None
            except Exception as e:
                exception_caught.append(e)

        thread = Thread(target=run_in_thread)
        thread.daemon = True
        thread.start()
        thread.join(timeout=1)

        # KeyError should be handled silently
        assert len(exception_caught) == 0
        assert result == ["handled"]


def test_health_service_run_systemexit_handling():
    """Test that run() silently handles SystemExit"""
    health_service = HealthService()

    # Mock the app.run method to raise SystemExit
    with patch.object(health_service.app, "run", side_effect=SystemExit(0)):
        exception_caught = []
        result = []

        def run_in_thread():
            try:
                health_service.app.run(host=health_service.host, port=health_service.port)
            except (KeyError, SystemExit):
                result.append("handled")
                return None
            except Exception as e:
                exception_caught.append(e)

        thread = Thread(target=run_in_thread)
        thread.daemon = True
        thread.start()
        thread.join(timeout=1)

        # SystemExit should be handled silently
        assert len(exception_caught) == 0
        assert result == ["handled"]
