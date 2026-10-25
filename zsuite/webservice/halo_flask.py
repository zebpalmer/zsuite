"""Custom Flask application with automatic JSON serialization and access logging."""

import inspect
import logging
import time
from functools import wraps

from flask import Flask, current_app, request
from werkzeug.middleware.proxy_fix import ProxyFix

from ..config import config_bool
from ..json_utils import json_dump

__all__ = [
    "HALOFlask",
    "current_user",
    "current_user_name",
    "current_ws",
    "skip_logging",
]


class HALOFlask(Flask):
    """Custom Flask application with automatic JSON serialization and access logging.

    Extends Flask with features for production deployments:
    - Automatic JSON serialization for dict/list responses
    - Access logging in nginx-style format with request timing
    - ProxyFix middleware for proper header handling behind proxies
    - Integration points for service container (svc) and authentication (auth_manager)

    :cvar svc: Service container reference, set by SVC.__init__().
    :vartype svc: SVC | None
    :cvar auth_manager: Authentication manager reference, set by AuthManager.__init__().
    :vartype auth_manager: AuthManager | None

    **Configuration Variables:**

    - ACCESS_LOGGING_ENABLED: Enable request/response logging (default: False)
    - PROXY_FIX_ENABLED: Enable ProxyFix middleware (default: True)

    **Example:**

    .. code-block:: python

        app = HALOFlask(__name__)


        @app.route("/api/data")
        def get_data():
            # Automatic JSON serialization
            return {"status": "ok", "data": [1, 2, 3]}


        # Access log output:
        # 192.168.1.1 - GET /api/data 200 45ms
    """

    svc = None
    auth_manager = None

    def __init__(self, *args, **kwargs):
        """Initialize HALOFlask application with optional access logging and proxy fix.

        Configures middleware based on configuration variables. Access logging tracks
        request timing and logs in nginx-compatible format. ProxyFix ensures correct
        remote_addr when behind reverse proxies.

        :param args: Positional arguments passed to Flask.__init__().
        :param kwargs: Keyword arguments passed to Flask.__init__().
        """
        super().__init__(*args, **kwargs)
        if config_bool("ACCESS_LOGGING_ENABLED", False):
            self.before_request(self.start_timer)
            self.after_request(self.log_request)
        proxy_fix_enabled = config_bool("PROXY_FIX_ENABLED", None)
        if proxy_fix_enabled is None:
            logging.warning(
                "PROXY_FIX_ENABLED is not set and defaults to true: X-Forwarded-* headers are trusted, "
                "so request.remote_addr can be spoofed by clients unless this service is behind a "
                "trusted reverse proxy. Set PROXY_FIX_ENABLED explicitly to silence this warning."
            )
            proxy_fix_enabled = True
        if proxy_fix_enabled:
            self.wsgi_app = ProxyFix(self.wsgi_app)

    def start_timer(self):
        """Start request timer for access logging.

        Called automatically via before_request if ACCESS_LOGGING_ENABLED is True.
        Sets request.start_time for calculating request duration.
        """
        request.start_time = time.time()

    def log_request(self, response):
        """Log request details in nginx-style format with timing information.

        Called automatically via after_request if ACCESS_LOGGING_ENABLED is True.
        Logs format: "{remote_addr} - {method} {path} {status} {elapsed_time}ms"

        Can be skipped for specific endpoints using the @skip_logging decorator.

        :param response: Flask response object to log and return.
        :type response: Response
        :returns: Unmodified response object.
        :rtype: Response

        **Example log output:**

        .. code-block:: text

            192.168.1.1 - GET /api/users?page=1 200 45ms
            10.0.0.5 - POST /api/login 401 12ms
        """
        if not getattr(request, "skip_logging", False):
            # Current time in seconds
            current_time = time.time()
            # Calculate elapsed time since the start of the request
            # noinspection PyUnresolvedReferences
            elapsed_time = round((current_time - request.start_time) * 1000)  # Convert to ms

            # Construct full path without the extra '?'
            full_path = request.path
            if request.query_string:
                full_path = f"{full_path}?{request.query_string.decode('utf-8')}"

            # Build the log line (nginx-style)
            log_line = f"{request.remote_addr} - {request.method} {full_path} {response.status} {elapsed_time}ms"
            logging.info(log_line)
        return response

    def make_response(self, rv):
        """Create response with automatic JSON serialization for dict/list returns.

        Overrides Flask's make_response to automatically serialize dictionaries and
        lists to JSON with proper Content-Type headers. Handles all Flask response
        tuple formats: (response,), (response, status), (response, headers),
        (response, status, headers).

        :param rv: Response value from view function. Can be dict, list, tuple, string,
                   or Response object.
        :type rv: dict | list | tuple | str | Response
        :returns: Flask Response object with JSON mimetype if applicable.
        :rtype: Response

        **Example:**

        .. code-block:: python

            @app.route("/data")
            def get_data():
                # These all automatically become JSON responses
                return {"key": "value"}
                return [1, 2, 3]
                return {"key": "value"}, 201
                return {"key": "value"}, {"X-Custom": "header"}
                return {"key": "value"}, 201, {"X-Custom": "header"}
        """
        is_json = None

        # Handle tuple formats: (response,), (response, status), (response, headers), (response, status, headers)
        if isinstance(rv, tuple):
            if len(rv) == 1:
                # (response,) -- unwrap: Flask rejects 1-tuples outright
                data = rv[0]
                if isinstance(data, dict | list):
                    is_json = True
                    data = json_dump(data)
                rv = data
            elif len(rv) == 2:
                # Could be (response, status) or (response, headers)
                data, second = rv
                if isinstance(data, dict | list):
                    is_json = True
                    data = json_dump(data)
                    rv = (data, second)
            elif len(rv) == 3:
                # (response, status, headers)
                data, status, headers = rv
                if isinstance(data, dict | list):
                    is_json = True
                    data = json_dump(data)
                    rv = (data, status, headers)
        elif isinstance(rv, dict | list):
            # Simple dict/list response
            is_json = True
            rv = json_dump(rv)

        response = super().make_response(rv)
        if is_json:
            response.mimetype = "application/json"
        return response


def current_ws() -> HALOFlask:
    """Get the current HALOFlask application instance with correct type hint.

    Type-safe wrapper around Flask's current_app that returns HALOFlask instead of
    generic Flask type. Use this instead of current_app when accessing HALOFlask-specific
    attributes like svc or auth_manager.

    :returns: Current HALOFlask application instance.
    :rtype: HALOFlask

    **Example:**

    .. code-block:: python

        def my_function():
            app = current_ws()
            config = app.svc.config  # Type hints work correctly
            auth = app.auth_manager  # Type hints work correctly

    .. note::
        This function exists solely for proper type hinting. Flask's current_app
        type hint returns Flask, not HALOFlask, which causes type checker issues
        when accessing custom attributes.
    """
    return current_app  # type: ignore


def current_user():
    """Get the currently authenticated User object from the request context.

    Returns the User object injected by AuthManager during authentication. Available
    only after successful authentication on protected endpoints.

    :returns: Authenticated User object, or None if no user authenticated or endpoint
              is public.
    :rtype: User | None

    **Example:**

    .. code-block:: python

        @app.route("/profile")
        @auth_required
        def profile():
            user = current_user()
            return {"username": user.name, "roles": list(user.roles)}
    """
    return request.environ.get("user", None)


def current_user_name():
    """Get the username of the currently authenticated user.

    Convenience function that returns just the username string instead of the full
    User object. Returns None if no user is authenticated.

    :returns: Username string in lowercase, or None if no user authenticated.
    :rtype: str | None

    **Example:**

    .. code-block:: python

        @app.route("/welcome")
        @auth_required
        def welcome():
            username = current_user_name()
            return f"Welcome, {username}!"
    """
    user = request.environ.get("user", None)
    if user:
        return user.name
    return None


def skip_logging(f):
    """Decorator to exclude specific endpoints from access logging.

    Use for health check endpoints or other high-frequency routes where access logging
    would be noisy or unnecessary. Only has effect when ACCESS_LOGGING_ENABLED is True.

    :param f: View function to exclude from logging.
    :type f: callable
    :returns: Decorated function that sets skip_logging flag on request.
    :rtype: callable

    **Example:**

    .. code-block:: python

        @app.route("/health")
        @skip_logging
        @public_endpoint
        def health_check():
            return {"status": "ok"}


        # Health check requests will not appear in access logs
    """
    # Check if the function is async
    if inspect.iscoroutinefunction(f):

        @wraps(f)
        async def async_decorated_function(*args, **kwargs):
            request.skip_logging = True
            return await f(*args, **kwargs)

        return async_decorated_function
    else:

        @wraps(f)
        def decorated_function(*args, **kwargs):
            request.skip_logging = True
            return f(*args, **kwargs)

        return decorated_function
