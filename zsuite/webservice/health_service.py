"""Health status webservice for daemons"""

import logging
from functools import partial
from threading import Thread

from flask import Flask

__all__ = ["HealthService"]


def check_callable(callback, callback_name):
    """Validate that a callback is callable or None.

    :param callback: Function to validate. Can be None or a callable.
    :type callback: callable | None
    :param callback_name: Name of the callback for error messages.
    :type callback_name: str
    :returns: The original callback if valid.
    :rtype: callable | None
    :raises TypeError: If callback is not None and not callable.
    """
    if callback is not None and not callable(callback):
        raise TypeError(f"{callback_name} should be a function")
    return callback


def _route_handler(callback, route):
    """Handle health check route requests.

    Executes the callback function and returns appropriate HTTP status codes based
    on the callback result. Returns 200 for healthy status, 503 for unhealthy.

    :param callback: Health check callback function that returns (status, message) tuple.
    :type callback: callable | None
    :param route: Route path for error messages.
    :type route: str
    :returns: Tuple of (message, status_code).
    :rtype: tuple[str, int]
    """
    if callback:
        status, message = callback()
        return message, 200 if status else 503
    else:
        return f"No callback provided for {route}", 501


class HealthService:
    """Flask-based health check service for Kubernetes liveness, readiness, and startup probes.

    Provides HTTP endpoints that conform to Kubernetes probe specifications:
    - /healthz: General health check (startup probe)
    - /readyz: Readiness check (indicates service can accept traffic)
    - /livez: Liveness check (indicates service should be restarted if failing)

    The service runs in a daemon thread and does not block the main application.

    **Callback Functions:**

    All callback functions should return a tuple of (status: bool, message: str):
    - status: True if check passes (returns HTTP 200), False if fails (returns HTTP 503)
    - message: Descriptive message about the health check status

    **Example:**

    .. code-block:: python

        def my_health_check():
            # Check database connection, etc.
            if all_systems_ok:
                return True, "Service healthy"
            return False, "Database connection failed"


        health = HealthService(
            port=8080,
            healthz_callback=my_health_check,
            readyz_callback=my_readiness_check,
            livez_callback=my_liveness_check,
        )
        health.run()

    .. note::
        These endpoints are unauthenticated by design (Kubernetes probes cannot
        authenticate) and bind to all interfaces by default. The 0.0.0.0 default
        is deliberate and load-bearing: kubelet httpGet probes connect to the pod
        IP, not localhost, so a loopback bind would break liveness/readiness
        probes for every consumer. Pass ``host`` explicitly to restrict the bind
        when the service is not probed over the pod network. Callback messages
        should not include sensitive internal details.
    """

    def __init__(
        self,
        name="health_service",
        host="0.0.0.0",
        port=8080,
        healthz_callback=None,
        readyz_callback=None,
        livez_callback=None,
    ):
        """Initialize the HealthService with optional health check callbacks.

        :param name: Name of the Flask application.
        :type name: str
        :param host: Host address to bind the service to. Defaults to all interfaces.
        :type host: str
        :param port: Port number for the service to listen on.
        :type port: int
        :param healthz_callback: Callback for /healthz endpoint (startup/general health).
                                 Should return (bool, str) tuple.
        :type healthz_callback: callable | None
        :param readyz_callback: Callback for /readyz endpoint (readiness probe).
                                Should return (bool, str) tuple.
        :type readyz_callback: callable | None
        :param livez_callback: Callback for /livez endpoint (liveness probe).
                               Should return (bool, str) tuple.
        :type livez_callback: callable | None
        :raises TypeError: If any callback is provided but not callable.
        """
        self.app = Flask(name)
        self.route_map = {
            "/healthz": check_callable(healthz_callback, "healthz_callback"),
            "/readyz": check_callable(readyz_callback, "readyz_callback"),
            "/livez": check_callable(livez_callback, "livez_callback"),
        }
        self._ws_thread = None
        self.host = host
        self.port = port
        self._setup_routes()

    def _setup_routes(self):
        """Register health check routes with the Flask application.

        Creates HTTP GET endpoints for /healthz, /readyz, and /livez that invoke
        their respective callback functions.
        """
        for route_path, route_callback in self.route_map.items():
            handler = partial(_route_handler, route_callback, route_path)
            handler.__name__ = f"{route_path.strip('/')}__handler"  # Give each function a unique name
            self.app.route(route_path, methods=["GET"])(handler)

    def run(self):
        """Start the Flask health service in a daemon thread.

        Launches the health check service in a background daemon thread that will
        automatically terminate when the main application exits. The service is
        non-blocking and runs independently of the main application.

        .. note::
            The service runs as a daemon thread and will not prevent the application
            from exiting. Exceptions during startup are logged but do not propagate.
        """
        logging.info("HealthService is running")

        # Define a function that will start the Flask app
        def start_app():
            try:
                self.app.run(host=self.host, port=self.port)
            except (KeyError, SystemExit):
                logging.info("HealthService is shutting down")
            except Exception:
                logging.exception("HealthService encountered an exception")
                raise

        # Create a daemon thread that will run start_app
        self._ws_thread = Thread(target=start_app, name="HealthService")
        self._ws_thread.daemon = True
        self._ws_thread.start()
