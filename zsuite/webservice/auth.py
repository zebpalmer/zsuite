"""Flask authentication middleware"""

import base64
import hashlib
import inspect
import logging
from collections.abc import Callable
from functools import wraps

import jwt
import requests as http_requests
from cachetools import TTLCache, cached
from flask import Response, abort, redirect, request
from werkzeug.security import check_password_hash

from ..config import config_bool, config_var
from ..exceptions import BasicAuthError, MissingRBACError, OAuthError, ZSuiteException
from ..file_utils import debug_file_path
from ..jwks import get_jwks_from_url
from ..logs import log_or_print
from ..yaml import load_and_decrypt_yaml
from .halo_flask import HALOFlask

__all__ = ["AuthManager", "User", "auth_required", "public_endpoint"]


class User:
    """User object for storing authentication and authorization information.

    Represents an authenticated user with a username and assigned roles. Roles are
    stored as a set for efficient membership testing during authorization checks.

    :param username: Username, automatically converted to lowercase for consistency.
    :type username: str
    :param roles: Set or list of role names assigned to the user. If None, user has
                  no roles. Converted to set internally.
    :type roles: set | list | None
    :raises ValueError: If roles is not None, list, or set.

    **Example:**

    .. code-block:: python

        user = User("john.doe", ["admin", "developer"])
        print(user.roles)  # {'admin', 'developer'}
    """

    def __init__(self, username: str, roles: set | list | None):
        """Initialize User object with username and roles.

        :param username: Username, automatically converted to lowercase for consistency.
        :type username: str
        :param roles: Set or list of role names assigned to the user. If None, user has
                      no roles. Converted to set internally.
        :type roles: set | list | None
        :raises ValueError: If roles is not None, list, or set.
        """
        self.name = username.lower()
        if roles is not None:
            if isinstance(roles, set):
                pass
            elif isinstance(roles, list):
                roles = set(roles)
            else:
                raise ValueError(f"roles must be None, list or set, not {type(roles)}")
        else:
            roles = set()
        self.roles = roles

    def __repr__(self):
        roles = ",".join(self.roles) if self.roles else None
        return f"User(name='{self.name}', roles={roles})"

    def to_dict(self):
        """Convert user object to dictionary representation.

        :returns: Dictionary with 'name' and 'roles' keys.
        :rtype: dict
        """
        return {"name": self.name, "roles": list(self.roles)}


class AuthManager:
    """Flask authentication middleware supporting JWT tokens, API tokens, and OAuth.

    Provides role-based access control (RBAC) for Flask applications with support for:
    - Teleport JWT assertions
    - Bearer tokens (JWT or API tokens)
    - Persistent API tokens from file
    - JWKS URL or static JWT signing keys
    - OAuth 2.1 token validation via provider userinfo endpoint
    - HTTP Basic auth against a file of hashed passwords
    - Configurable authentication failure logging
    - Pluggable application-managed roles via ``roles_resolver``

    Authentication is enforced via before_request middleware that validates tokens and
    checks role requirements for each endpoint. Endpoints must be decorated with
    @auth_required or @public_endpoint.

    When OAuth is enabled (``OAUTH_ENABLED=true``), AuthManager automatically
    registers a ``/.well-known/oauth-protected-resource`` discovery endpoint (RFC 9728),
    includes ``WWW-Authenticate`` headers in 401 responses, validates opaque OAuth tokens
    via the provider's userinfo endpoint, and maps authenticated emails to roles via an
    optional YAML roles file.

    Any client that obtains a valid Google access token and sends it as a Bearer token
    can authenticate, including MCP clients, CLI tools, SPAs, and other OAuth consumers.
    For browser-based user login or MCP clients that require Dynamic Client Registration,
    deploy an OAuth proxy (e.g. mcp-oauth-proxy, oauth2-proxy) in front of the service.
    Tokens forwarded via the ``X-Forwarded-Access-Token`` header are automatically
    validated when OAuth is enabled.

    **OAuth Configuration Variables:**

    - ``OAUTH_ENABLED``: Feature flag to enable OAuth support (default: False)
    - ``OAUTH_PROVIDER``: Provider name for logging (default: ``"google"``)
    - ``OAUTH_USERINFO_URL``: Userinfo endpoint URL
      (default: ``"https://openidconnect.googleapis.com/v1/userinfo"``)
    - ``OAUTH_ALLOWED_DOMAINS``: Comma-separated list of allowed hosted domains
      (e.g. ``"lacallegroup.com,continued.com,simucase.com"``)
    - ``OAUTH_ROLES_FILE``: Path to encrypted YAML file mapping emails to roles
    - ``OAUTH_DEFAULT_ROLES``: Comma-separated default roles for authenticated users
    - ``OAUTH_RESOURCE_URL``: Public URL of this server (required when OAuth enabled)
    - ``OAUTH_AUTHORIZATION_SERVER``: OAuth authorization server URL
      (default: ``"https://accounts.google.com"``)
    - ``OAUTH_SCOPES``: Comma-separated scopes (default: ``"openid,email,profile"``)
    - ``OAUTH_ALLOWED_CLIENT_IDS``: Comma-separated OAuth client IDs this service accepts
      tokens for. Strongly recommended -- without it, an access token issued to *any*
      OAuth application (e.g. a third-party app a user signed in to with Google) is
      accepted as authentication for that user (confused-deputy risk).
    - ``OAUTH_TOKENINFO_URL``: Token introspection endpoint used to validate the token
      audience (default: ``"https://oauth2.googleapis.com/tokeninfo"``)

    When Basic auth is enabled (``BASIC_AUTH_ENABLED=true``), requests with an
    ``Authorization: Basic`` header are validated against an encrypted YAML file of
    usernames and password hashes, and 401 responses include a
    ``WWW-Authenticate: Basic`` challenge. Passwords are stored only as hashes --
    generate them with ``werkzeug.security.generate_password_hash``. Because Basic
    auth sends the credential with every request, only enable it on services served
    over TLS.

    **Basic Auth Configuration Variables:**

    - ``BASIC_AUTH_ENABLED``: Feature flag to enable HTTP Basic auth (default: False)
    - ``BASIC_AUTH_FILE``: Path to encrypted YAML file of usernames, password hashes,
      and roles (required when enabled)
    - ``BASIC_AUTH_REALM``: Realm sent in the ``WWW-Authenticate`` challenge
      (default: ``"Restricted"``)

    :ivar _preflight_completed: Per-instance flag indicating security preflight
        completion. Declared at class level only as a default; security_preflight()
        shadows it with an instance attribute. Never assign it on the class -- that
        would disarm the preflight gate for every AuthManager in the process.
    :vartype _preflight_completed: bool | None
    """

    # Shared dict, but @cached keys entries by `self`, so behavior is an
    # effectively per-instance 15-minute cache for signing_keys.
    _cache = TTLCache(maxsize=100, ttl=900)
    # Preflight state: class-level values are only the fail-closed DEFAULTS for
    # instances that never ran security_preflight(). security_preflight() shadows
    # them with instance attributes -- never assign these on the class itself.
    _preflight_completed = None
    _preflight_failed = False

    def __init__(
        self,
        app: HALOFlask,
        persistent_tokens=None,
        persistent_token_file=None,
        roles_resolver: Callable[[str], set[str] | None] | None = None,
    ):
        """Initialize authentication middleware and register with Flask app.

        Validates all endpoints have RBAC decorators and optionally loads persistent
        API tokens. If AUTH_ENABLED is False, authentication is disabled and auth_manager
        is set to None on the app.

        :param app: Flask application instance to protect with authentication.
        :type app: HALOFlask
        :param persistent_tokens: Dictionary of pre-loaded persistent tokens in format
                                  [{"username": str, "roles": list, "tokens": list}].
                                  Mutually exclusive with persistent_token_file.
        :type persistent_tokens: dict | None
        :param persistent_token_file: Path to YAML file containing persistent tokens.
                                      Mutually exclusive with persistent_tokens.
        :type persistent_token_file: str | Path | None
        :param roles_resolver: Optional callable that resolves roles from application-managed
                               data (e.g. the app's own database). Receives the authenticated
                               user's name (lowercased email) and returns the user's roles as
                               a set, or None to leave the token-derived roles untouched.
                               When it returns a set, that set **replaces** the token-derived
                               roles; an empty set means authenticated with no roles.
                               Applied to every authenticated identity (Teleport JWT, API
                               token, OAuth). If the resolver raises, authorization fails
                               closed: the user keeps their identity but gets no roles.
                               Called once per authenticated request -- zsuite does not
                               cache results, so caching/freshness is the resolver's concern.
        :type roles_resolver: Callable[[str], set[str] | None] | None
        :raises MissingRBACError: If any endpoints lack @auth_required or @public_endpoint decorators.
        :raises ValueError: If both persistent_tokens and persistent_token_file provided.

        .. note::
            Call security_preflight() after registering all blueprints to complete setup.
            This is required -- until it has completed successfully, all requests are
            refused with 503.
        """
        # Check all endpoints have auth decorators
        # do this prior to checking AUTH_ENABLED so that we can
        # check for missing decorators during development w/ Auth Disabled
        check_all_endpoints_have_rbac(app)

        # Optional app-provided roles resolver (see __init__ docstring). Set
        # unconditionally: get_user() reads it even when auth is disabled.
        self._roles_resolver = roles_resolver

        # Check if auth is enabled
        if config_bool("AUTH_ENABLED", True) is False:
            logging.warning("---WARNING--- Authentication is disabled by config ---WARNING---")
            app.auth_manager = None
        else:
            # Allow setting auth fail events to a different log level
            log_level = str(config_var("AUTH_FAIL_LOG_LEVEL", config_var("LOG_LEVEL", "INFO"))).lower()
            if log_level not in {"debug", "info", "warning", "error", "critical"}:
                logging.warning(f"Invalid AUTH_FAIL_LOG_LEVEL {log_level!r}, falling back to 'warning'")
                log_level = "warning"
            self._auth_fail_log_level = log_level

            self._token_users = get_token_users(persistent_token_file, persistent_tokens)

            # Make a local reference to the app
            self.app = app

            # Register the auth manager with the app
            app.auth_manager = self

            # Inject the middleware into every request
            self.app.before_request(self.check_auth)

            # Initialize OAuth support if enabled
            self._oauth_enabled = config_bool("OAUTH_ENABLED", False)
            if self._oauth_enabled:
                self._setup_oauth()

            # Initialize HTTP Basic auth support if enabled
            self._basic_auth_enabled = config_bool("BASIC_AUTH_ENABLED", False)
            if self._basic_auth_enabled:
                self._setup_basic_auth()

    def security_preflight(self):
        """Perform security validation checks before starting the application.

        Must be called after all blueprints are registered. Validates:
        - JWT_SIGNING_KEY and JWKS_URL are not both set
        - All endpoints have RBAC decorators
        - Persistent tokens are loaded if AUTH_TOKENS_FILE is set
        - Signing keys are loaded if JWKS_URL is set

        :raises ValueError: If security configuration is invalid.

        .. note::
            Calling this is required: until it has completed successfully,
            :meth:`check_auth` refuses every request with 503 (fail closed). If it
            raises, the failure is recorded and requests remain refused even if the
            caller swallows the exception and starts the app anyway.
        """
        if config_bool("AUTH_ENABLED", True):
            logging.info("Security preflight...")
            try:
                self._run_preflight_checks()
            except Exception as e:
                # Record the failure so check_auth refuses all requests even if the
                # caller swallows this exception and starts the app anyway
                self._preflight_failed = True
                logging.critical(f"FATAL ERROR: Security preflight failed: {e}")
                log_or_print(
                    "Security preflight failed, see logs for details -- refusing all connections",
                    level="CRITICAL",
                )
                raise

            # wrap-up
            self._preflight_failed = False
            self._preflight_completed = True
            logging.info("Security preflight complete")
        else:
            self._preflight_completed = False
            logging.warning("Authentication is disabled")

    def _run_preflight_checks(self):
        """Run the individual security preflight validation checks.

        :raises ValueError: If security configuration is invalid.
        :raises MissingRBACError: If any endpoints lack RBAC decorators.
        :raises OAuthError: If OAuth configuration is invalid.
        """
        # Check security config
        logging.debug("validating security config")
        self._validate_jwt_config()

        # Check all endpoints have auth decorators
        logging.debug("Checking all endpoints have auth decorators")
        check_all_endpoints_have_rbac(self.app)

        # Check for persistent tokens
        if config_var("AUTH_TOKENS_FILE", None) and not self._token_users:
            msg = "AUTH_TOKENS_FILE is set but no persistent tokens are loaded"
            logging.critical(msg)
            raise ValueError(msg)
        if config_var("JWKS_URL", None) and not self.signing_keys:
            msg = "JWKS_URL is set but no signing keys are loaded"
            logging.critical(msg)
            raise ValueError(msg)

        # Check OAuth config
        if self._oauth_enabled:
            logging.debug("Validating OAuth config")
            if not config_var("OAUTH_RESOURCE_URL", None):
                msg = "OAUTH_ENABLED is set but OAUTH_RESOURCE_URL is not configured"
                logging.critical(msg)
                raise OAuthError(msg)
            if not config_var("OAUTH_ALLOWED_DOMAINS", None):
                logging.warning(
                    "OAUTH_ALLOWED_DOMAINS is not set -- any authenticated user from the "
                    "OAuth provider can access this service"
                )
            if not config_var("OAUTH_ALLOWED_CLIENT_IDS", None):
                logging.critical(
                    "OAUTH_ALLOWED_CLIENT_IDS is not set -- access tokens issued to ANY OAuth "
                    "application will be accepted for allowed users (confused-deputy risk). "
                    "Set it to this service's OAuth client ID(s)."
                )
            if config_var("OAUTH_ROLES_FILE", None) and not self._oauth_role_map:
                msg = "OAUTH_ROLES_FILE is set but no OAuth roles were loaded"
                logging.critical(msg)
                raise OAuthError(msg)
            logging.info(
                f"OAuth enabled: provider={config_var('OAUTH_PROVIDER', 'google')}, "
                f"allowed_domains={config_var('OAUTH_ALLOWED_DOMAINS', 'ANY')}"
            )

        # Check Basic auth config
        if self._basic_auth_enabled:
            self._validate_basic_auth_config()

    def _validate_basic_auth_config(self):
        """Validate Basic auth configuration during the security preflight.

        :raises BasicAuthError: If Basic auth is enabled without a usable credentials file.
        """
        logging.debug("Validating Basic auth config")
        if not config_var("BASIC_AUTH_FILE", None):
            msg = "BASIC_AUTH_ENABLED is set but BASIC_AUTH_FILE is not configured"
            logging.critical(msg)
            raise BasicAuthError(msg)
        if not self._basic_auth_users:
            msg = "BASIC_AUTH_FILE is set but no Basic auth users were loaded"
            logging.critical(msg)
            raise BasicAuthError(msg)
        logging.warning(
            "HTTP Basic auth is enabled -- the credential is sent with every request. "
            "Only expose this service over TLS."
        )
        logging.info(f"Basic auth enabled for {len(self._basic_auth_users)} users")

    @staticmethod
    def _validate_jwt_config() -> None:
        """Validate JWT signing config and warn loudly about risky verification settings.

        :raises ValueError: If JWT_SIGNING_KEY and JWKS_URL are both set.
        """
        if config_var("JWT_SIGNING_KEY", None) and config_var("JWKS_URL", None):
            msg = "JWT_SIGNING_KEY and JWKS_URL are both set, only one can be used"
            logging.critical(msg)
            raise ValueError(msg)

        jwt_keys_configured = config_var("JWT_SIGNING_KEY", None) or config_var("JWKS_URL", None)
        if jwt_keys_configured and not config_var("JWT_AUDIENCE", None):
            logging.critical(
                "JWT_AUDIENCE is not set -- JWTs minted for other services with the same signing keys "
                "(e.g. the same Teleport cluster) will be accepted by this service. Set JWT_AUDIENCE "
                "to this service's audience to prevent cross-service token replay."
            )
        if config_bool("JWT_VERIFY_EXPIRE", True) is False:
            logging.critical(
                "JWT_VERIFY_EXPIRE is disabled -- expired JWTs will be accepted. "
                "This should never be disabled in production."
            )

    @property
    @cached(_cache)
    def signing_keys(self):
        """Get JWT signing keys from config or JWKS URL with TTL caching.

        Returns keys from JWT_SIGNING_KEY config if set, otherwise fetches from JWKS_URL.
        Results are cached for 15 minutes to reduce external requests.

        :returns: List of JWT signing keys.
        :rtype: list[str]
        """
        jwt_signing_key = config_var("JWT_SIGNING_KEY", None)
        jwks_url = config_var("JWKS_URL", None)
        if jwt_signing_key:
            return [jwt_signing_key]
        elif jwks_url:
            return get_jwks_from_url(config_var("JWKS_URL"))
        return None

    def check_auth(self):
        """Authenticate and authorize requests before routing to endpoints.

        Called automatically via Flask's before_request. Validates:
        1. Security preflight has completed successfully (503 for every request if not)
        2. Endpoint exists (404 if not, with trailing slash redirect handling)
        3. HTTP method is allowed (405 if not)
        4. Endpoint is public or user has required roles
        5. User authentication via JWT or API token

        Injects authenticated User object into request.environ['user'] on success.

        :raises HTTPException: 401 (unauthorized), 403 (forbidden), 404 (not found),
                               405 (method not allowed), 500 (internal error), or
                               503 (security preflight not completed).
        """
        # Fail closed unless the security preflight has been run successfully
        if self._preflight_failed:
            logging.critical("Security preflight failed, refusing all connections")
            abort(503, "Service Unavailable")
        if self._preflight_completed is None:
            logging.critical(
                "Security preflight not called, refusing all connections -- "
                "call security_preflight() after registering all blueprints"
            )
            abort(503, "Service Unavailable")

        # Get and validate the view function for the current request
        # This may return a redirect response or a view function
        result = self._get_view_function()

        # If we got a redirect response (not a view function), return it immediately
        if hasattr(result, "status_code"):  # It's a Response object
            return result

        # Check if the endpoint is public or requires authentication
        return self._check_endpoint_access(result)

    def _get_view_function(self):
        """Get and validate the view function for the current request.

        Handles endpoint lookup and HTTP method validation. If endpoint doesn't exist,
        checks for trailing slash redirects.

        :returns: View function for the current request, or redirect response.
        :rtype: callable | Response
        :raises HTTPException: 404 (not found), 405 (method not allowed).
        """
        view_func = self.app.view_functions.get(request.endpoint)

        if view_func is None:
            # This will either abort or return a redirect response
            return self._validate_http_method()

        return view_func

    def _validate_http_method(self):
        """Validate HTTP method is allowed for the current path.

        Checks if the URL path exists with other HTTP methods. If it does, raises 405.
        If not, checks for trailing slash redirect, otherwise raises 404.

        :returns: Redirect response if trailing slash redirect is needed.
        :rtype: Response
        :raises HTTPException: 404 (not found), 405 (method not allowed).
        """
        # Check if the URL path exists with other HTTP methods
        valid_methods = []
        for rule in self.app.url_map.iter_rules():
            if rule.rule == request.path:
                valid_methods.extend(rule.methods)

        if valid_methods:
            # Route exists but doesn't support the current method
            logging.debug(f"Method not allowed for {request.url}")
            abort(405, description="Method Not Allowed")
        else:
            # No route matches the path - check for trailing slash redirect
            new_path = self._check_redirect()
            if new_path:
                return redirect(new_path, code=308)
            else:
                logging.debug(f"Endpoint for {request.url} does not exist")
                abort(404, "Not Found")

    def _check_endpoint_access(self, view_func):
        """Check if user has access to the endpoint.

        Validates if endpoint is public or if authenticated user has required roles.

        :param view_func: View function to check access for.
        :type view_func: callable
        :returns: None to continue to endpoint.
        :rtype: None
        :raises HTTPException: 401 (unauthorized), 403 (forbidden), 500 (internal error).
        """
        # Backstop for views that slipped past the startup RBAC check (e.g. routes
        # registered after security_preflight()) -- refuse rather than serve them
        # to any authenticated user with no role restriction.
        _ensure_rbac(view_func)

        # Check if the endpoint is public
        is_public = getattr(view_func, "_is_public", False)
        if is_public:
            return None  # continue on to call the decorated endpoint

        # Get required roles for the endpoint
        try:
            required_roles = set(getattr(view_func, "_required_roles", []))
        except Exception as e:
            logging.warning(f"Exception: {e}")
            abort(500, "Internal Server Error: Error processing required roles")

        # Authenticate user and verify they have required roles
        try:
            user = self.get_user()
        except Exception as e:
            logging.warning(f"get_user() exception: {e}")
            abort(500, "Internal Server Error")
        else:
            if self._user_authorized(user, required_roles):
                return None  # continue on to call the decorated endpoint

        # catch-all - this should never be reached
        logging.warning("Internal Server Error: check_auth() reached end of function")
        abort(500, "Internal Server Error: Reached end of check_auth() with no return")

    def _user_authorized(self, user: User, required_roles: set) -> bool:
        """Validate user has required roles and inject into request environ.

        :param user: Authenticated user object or None.
        :type user: User | None
        :param required_roles: Set of role names required for the endpoint.
        :type required_roles: set
        :returns: True if authorized (never returns False, aborts instead).
        :rtype: bool
        :raises HTTPException: 401 if no user, 403 if user lacks required role.
        """
        authorized = None
        if not user:
            msg = f"Authentication Failed (No User Found): {request.remote_addr} on {request.url}"
            self.log_auth_failure(msg)
            # Advertise every enabled challenge scheme (multiple WWW-Authenticate
            # headers are valid per RFC 9110)
            challenges = []
            if self._basic_auth_enabled:
                challenges.append(f'Basic realm="{self._basic_auth_realm}", charset="UTF-8"')
            if self._oauth_enabled:
                resource_url = config_var("OAUTH_RESOURCE_URL")
                challenges.append(f'Bearer resource_metadata="{resource_url}/.well-known/oauth-protected-resource"')
            if challenges:
                response = Response("Authentication Failed", status=401)
                for challenge in challenges:
                    response.headers.add("WWW-Authenticate", challenge)
                abort(response)
            abort(401, "Authentication Failed")
        elif has_required_role(user, required_roles):
            request.environ["user"] = user
            authorized = True  # continue on to call the decorated endpoint
        else:
            has_roles = ",".join(user.roles)
            needed_roles = ",".join(required_roles)
            msg = (
                f"Forbidden: {user.name} from {request.remote_addr} on {request.endpoint}"
                f" -- has roles: {has_roles} required roles: {needed_roles}"
            )
            self.log_auth_failure(msg)
            abort(403, "Forbidden - Required role not found")
        return authorized

    def get_user(self) -> User:
        """Extract and validate user from request headers.

        Checks for authentication in the following order:

        1. Teleport-Jwt-Assertion header (JWT)
        2. Authorization header with a ``Basic`` scheme — HTTP Basic auth against the
           configured credentials file. Only checked when BASIC_AUTH_ENABLED.
        3. Authorization header (any other scheme) — tries each method in order:

           a. Persistent API token (O(1) dict lookup)
           b. JWT token (JWKS validation)
           c. OAuth opaque token via provider userinfo (if OAUTH_ENABLED)

        4. X-Forwarded-Access-Token header — OAuth token forwarded by a reverse
           proxy (e.g. mcp-oauth-proxy, oauth2-proxy). Only checked when OAuth is enabled.

        If a ``roles_resolver`` was configured, it is applied to the authenticated user
        before returning (see :meth:`_apply_roles_resolver`).

        :returns: Authenticated User object or None if authentication fails.
        :rtype: User | None
        """
        user = None
        if "Teleport-Jwt-Assertion" in request.headers:
            token = request.headers["Teleport-Jwt-Assertion"]
            user = self._parse_jwt(token)
        elif "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if self._basic_auth_enabled and auth_header.startswith("Basic "):
                user = self._parse_basic_auth(auth_header)
            else:
                token = token_from_auth_header(auth_header)
                user = self._parse_api_token(token)  # try api token
                if not user:  # try jwt
                    user = self._parse_jwt(token)
                if not user and self._oauth_enabled:  # try oauth
                    user = self._parse_oauth_token(token)
        elif self._oauth_enabled and "X-Forwarded-Access-Token" in request.headers:
            token = request.headers["X-Forwarded-Access-Token"]
            user = self._parse_oauth_token(token)
        return self._apply_roles_resolver(user)

    def _apply_roles_resolver(self, user: User | None) -> User | None:
        """Apply the configured roles resolver to an authenticated user.

        No-op when no resolver is configured or authentication failed (user is None).
        Otherwise calls the resolver with the user's name and applies the result:

        - set returned: **replaces** the token-derived roles (an empty set means
          authenticated with no roles, so role-protected endpoints return 403)
        - None returned: token-derived roles are left untouched (per-user opt-out)
        - resolver raises: fails closed -- the user keeps their identity but gets no
          roles; the error is logged via :meth:`log_auth_failure`

        A new User object is always returned when roles change so that User objects
        cached by token parsers (e.g. the OAuth userinfo cache) are never mutated.

        :param user: Authenticated user, or None if authentication failed.
        :type user: User | None
        :returns: User with resolved roles applied, or the unmodified input.
        :rtype: User | None
        """
        if user is None or self._roles_resolver is None:
            return user
        try:
            resolved_roles = self._roles_resolver(user.name)
            if resolved_roles is None:
                return user
            return User(user.name, resolved_roles)
        except Exception as e:
            msg = f"roles_resolver failed for {user.name}: {type(e).__name__}: {e} -- failing closed with no roles"
            self.log_auth_failure(msg)
            return User(user.name, set())

    def _parse_api_token(self, token) -> User | None:
        """Validate API token and return associated User object.

        :param token: API token string to validate.
        :type token: str
        :returns: User object if token is valid, None otherwise.
        :rtype: User | None
        """
        user = self._token_users.get(_hash_token(token))
        if user:
            logging.debug(f"Token ID {user.name}:{_token_id(token)} logged in")
        return user

    def _parse_jwt(self, token, options=None) -> User | None:
        """Decode and validate JWT token, returning User object.

        Attempts to decode the JWT with each available signing key. Validates
        expiration and audience based on configuration.

        :param token: JWT token string to decode.
        :type token: str
        :param options: JWT decoding options. If None, uses defaults from config
                        (JWT_VERIFY_EXPIRE, JWT_AUDIENCE).
        :type options: dict | None
        :returns: User object with username and roles from JWT payload, or None if invalid.
        :rtype: User | None
        """
        if options is None:
            options = {
                "verify_exp": config_bool("JWT_VERIFY_EXPIRE", True),
                "verify_aud": bool(config_var("JWT_AUDIENCE", False)),
            }

        jwt_kwargs = {"algorithms": ["RS256"], "options": options}
        if config_var("JWT_AUDIENCE", False):
            jwt_kwargs["audience"] = config_var("JWT_AUDIENCE", False)
        if not self.signing_keys:
            return None
        for key in self.signing_keys:
            try:
                payload = jwt.decode(token, key, **jwt_kwargs)
            except jwt.PyJWTError as e:  # Try the next signing key (e.g. during JWKS key rotation)
                logging.debug(f"JWT Exception {type(e).__name__} for token {_token_id(token)}")
                continue
            username = payload.get("username")
            if not username:
                self.log_auth_failure(f"JWT signature is valid but 'username' claim is missing: {_token_id(token)}")
                return None
            roles = payload.get("roles", [])
            logging.debug(f"Valid JWT for {username}")
            return User(username, roles)

        return None  # no signing key validated the token

    def log_auth_failure(self, msg):
        """Log authentication failure at the configured log level.

        Uses AUTH_FAIL_LOG_LEVEL config variable to determine log level (defaults to
        LOG_LEVEL or INFO).

        :param msg: Authentication failure message to log.
        :type msg: str
        """
        getattr(logging, self._auth_fail_log_level)(msg)

    def _check_redirect(self):
        """Check if endpoint exists with opposite trailing slash configuration.

        Flask normally handles trailing slash redirects automatically, but this
        middleware breaks that behavior, requiring manual checking.

        :returns: New path with toggled trailing slash if route exists, None otherwise.
        :rtype: str | None
        """
        # Toggle the trailing slash
        new_path = request.path + "/" if not request.path.endswith("/") else request.path[:-1]

        # Search for the alternative rule
        for rule in self.app.url_map.iter_rules():
            if rule.rule == new_path:
                return new_path
        return None

    # ==================== OAuth Support ====================

    def _setup_oauth(self):
        """Configure OAuth support: load roles, initialize cache, register discovery endpoint.

        Called from ``__init__`` when ``OAUTH_ENABLED`` is truthy. Registers the
        ``/.well-known/oauth-protected-resource`` endpoint on the Flask app for MCP
        client discovery and initializes the userinfo response cache.

        :raises OAuthError: If OAuth roles file cannot be loaded.
        """
        provider = config_var("OAUTH_PROVIDER", "google")
        logging.info(f"Initializing OAuth support (provider: {provider})")

        # Load allowed domains as a set for O(1) lookup
        domains_str = config_var("OAUTH_ALLOWED_DOMAINS", "")
        self._oauth_allowed_domains = {d.strip().lower() for d in domains_str.split(",") if d.strip()}

        # Load allowed OAuth client IDs for token audience validation
        client_ids_str = config_var("OAUTH_ALLOWED_CLIENT_IDS", "")
        self._oauth_allowed_client_ids = {c.strip() for c in client_ids_str.split(",") if c.strip()}
        self._oauth_tokeninfo_url = config_var("OAUTH_TOKENINFO_URL", "https://oauth2.googleapis.com/tokeninfo")

        # Load default roles
        default_roles_str = config_var("OAUTH_DEFAULT_ROLES", "")
        self._oauth_default_roles = [r.strip() for r in default_roles_str.split(",") if r.strip()]

        # Load OAuth role mapping from YAML file
        roles_file = config_var("OAUTH_ROLES_FILE", None)
        if roles_file:
            self._oauth_role_map, self._oauth_default_roles_from_file = load_oauth_roles(roles_file)
            # File-based default_roles override config var default_roles
            if self._oauth_default_roles_from_file:
                self._oauth_default_roles = self._oauth_default_roles_from_file
        else:
            self._oauth_role_map = {}

        # TTL caches for token validation results, keyed by SHA-256 token digest so raw
        # tokens never sit in the process heap. Valid and invalid tokens are cached
        # separately: the negative cache has a short TTL and can be churned by
        # unauthenticated garbage tokens without evicting legitimate users' entries.
        self._oauth_userinfo_cache = TTLCache(maxsize=256, ttl=300)
        self._oauth_negative_cache = TTLCache(maxsize=256, ttl=60)

        # Store the userinfo URL
        self._oauth_userinfo_url = config_var("OAUTH_USERINFO_URL", "https://openidconnect.googleapis.com/v1/userinfo")

        # Register the .well-known/oauth-protected-resource endpoint
        self._register_oauth_discovery_endpoint()

    def _register_oauth_discovery_endpoint(self):
        """Register the OAuth Protected Resource Metadata endpoint on the Flask app.

        Creates a public ``GET /.well-known/oauth-protected-resource`` endpoint that
        returns RFC 9728 metadata, enabling MCP clients (Claude Code/Desktop) to
        discover the authorization server and initiate the OAuth flow.
        """
        resource_url = config_var("OAUTH_RESOURCE_URL", "")
        auth_server = config_var("OAUTH_AUTHORIZATION_SERVER", "https://accounts.google.com")
        scopes = config_var("OAUTH_SCOPES", "openid,email,profile")

        def oauth_protected_resource_view():
            return {
                "resource": resource_url,
                "authorization_servers": [auth_server],
                "bearer_methods_supported": ["header"],
                "scopes_supported": [s.strip() for s in scopes.split(",")],
            }

        # Set RBAC flags so check_all_endpoints_have_rbac passes
        oauth_protected_resource_view._is_public = True
        oauth_protected_resource_view._rbac_is_defined = True

        self.app.add_url_rule(
            "/.well-known/oauth-protected-resource",
            endpoint="oauth_protected_resource",
            view_func=oauth_protected_resource_view,
            methods=["GET"],
        )
        logging.info("Registered /.well-known/oauth-protected-resource endpoint")

    def _parse_oauth_token(self, token: str) -> User | None:
        """Validate an opaque OAuth access token via the provider's userinfo endpoint.

        Calls the configured userinfo URL with the token to resolve the user's identity.
        Results are cached by SHA-256 token digest to avoid redundant HTTP calls:
        valid tokens for 5 minutes, invalid tokens for 60 seconds (separate cache).

        Validates:
        - Token audience is allowed (if ``OAUTH_ALLOWED_CLIENT_IDS`` is configured)
        - Token is accepted by the userinfo endpoint (HTTP 200)
        - Email is verified (``email_verified: true``)
        - Hosted domain (``hd``) is in the allowed domains list (if configured)

        :param token: Opaque OAuth access token from the Authorization header.
        :type token: str
        :returns: User object if token is valid and authorized, None otherwise.
        :rtype: User | None
        """
        token_key = _hash_token(token)

        # Check the positive cache first, then the short-lived negative cache
        cached_user = self._oauth_userinfo_cache.get(token_key)
        if cached_user is not None:
            return cached_user
        if token_key in self._oauth_negative_cache:
            return None

        # Verify the token was issued to one of this service's OAuth clients
        # before resolving the identity
        user = None
        if self._verify_token_audience(token):
            user = self._fetch_oauth_user(token)

        # Cache the result
        if user is not None:
            self._oauth_userinfo_cache[token_key] = user
        else:
            self._oauth_negative_cache[token_key] = True
        return user

    def _verify_token_audience(self, token: str) -> bool:
        """Verify an access token was issued to one of this service's OAuth clients.

        Calls the provider's tokeninfo endpoint (``OAUTH_TOKENINFO_URL``) and checks
        the token's ``aud`` claim against ``OAUTH_ALLOWED_CLIENT_IDS``. Without this
        check, an access token issued to *any* OAuth application (e.g. a third-party
        app a user signed in to with Google) would authenticate that user to this
        service (confused deputy).

        Returns True without checking when ``OAUTH_ALLOWED_CLIENT_IDS`` is not
        configured -- :meth:`security_preflight` logs a critical warning in that case.

        :param token: Opaque OAuth access token.
        :type token: str
        :returns: True if the token's audience is allowed (or no allowlist configured).
        :rtype: bool
        """
        if not self._oauth_allowed_client_ids:
            return True

        try:
            resp = http_requests.get(self._oauth_tokeninfo_url, params={"access_token": token}, timeout=10)
        except http_requests.RequestException as e:
            logging.warning(f"OAuth tokeninfo request failed: {e}")
            return False

        if resp.status_code != 200:
            logging.debug(f"OAuth tokeninfo returned {resp.status_code} for token {_token_id(token)}")
            return False

        try:
            aud = resp.json().get("aud", "")
        except (ValueError, TypeError):
            logging.warning("OAuth tokeninfo response is not valid JSON")
            return False

        if aud not in self._oauth_allowed_client_ids:
            self.log_auth_failure(f"OAuth token audience {aud!r} is not in OAUTH_ALLOWED_CLIENT_IDS")
            return False
        return True

    def _fetch_oauth_user(self, token: str) -> User | None:
        """Fetch user information from the OAuth provider's userinfo endpoint.

        :param token: Opaque OAuth access token.
        :type token: str
        :returns: User object if token is valid and authorized, None otherwise.
        :rtype: User | None
        """
        try:
            resp = http_requests.get(
                self._oauth_userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
        except http_requests.RequestException as e:
            logging.warning(f"OAuth userinfo request failed: {e}")
            return None

        if resp.status_code != 200:
            logging.debug(f"OAuth userinfo returned {resp.status_code}")
            return None

        try:
            userinfo = resp.json()
        except (ValueError, TypeError):
            logging.warning("OAuth userinfo response is not valid JSON")
            return None

        email = userinfo.get("email", "").lower()
        email_verified = userinfo.get("email_verified", False)
        hd = userinfo.get("hd", "").lower()

        # Validate email is present and verified
        if not email or not email_verified:
            logging.debug(f"OAuth: email missing or not verified (email={email!r}, verified={email_verified})")
            return None

        # Validate hosted domain if allowed domains are configured
        if self._oauth_allowed_domains and hd not in self._oauth_allowed_domains:
            logging.debug(f"OAuth: domain '{hd}' not in allowed domains for {email}")
            return None

        # Resolve roles: check role map first, fall back to default roles
        roles = self._oauth_role_map.get(email, self._oauth_default_roles)

        logging.debug(f"OAuth: authenticated {email} (domain: {hd})")
        return User(email, list(roles))

    # ==================== HTTP Basic Auth Support ====================

    def _setup_basic_auth(self):
        """Configure HTTP Basic auth: load credentials and initialize verification caches.

        Called from ``__init__`` when ``BASIC_AUTH_ENABLED`` is truthy. Loads the
        credentials file immediately so a bad file fails at startup, not on first request.

        :raises BasicAuthError: If the Basic auth credentials file cannot be loaded.
        """
        logging.info("Initializing HTTP Basic auth support")
        self._basic_auth_realm = config_var("BASIC_AUTH_REALM", "Restricted")

        creds_file = config_var("BASIC_AUTH_FILE", None)
        self._basic_auth_users = load_basic_auth_users(creds_file) if creds_file else {}

        # TTL caches for verification results, keyed by SHA-256 digest of the decoded
        # credential pair so raw passwords never sit in the process heap. Password
        # hashing is deliberately slow (~100ms), so without the positive cache every
        # request would pay that cost. The negative cache has a short TTL and absorbs
        # garbage credentials without evicting legitimate users' entries.
        self._basic_auth_cache = TTLCache(maxsize=256, ttl=300)
        self._basic_auth_negative_cache = TTLCache(maxsize=256, ttl=60)

    def _parse_basic_auth(self, auth_header: str) -> User | None:
        """Validate an ``Authorization: Basic`` header against the credentials file.

        Decodes the base64 credential pair and verifies the password against the
        stored hash via :func:`werkzeug.security.check_password_hash`. Results are
        cached by SHA-256 digest of the credential pair: valid credentials for
        5 minutes, invalid for 60 seconds (separate cache).

        :param auth_header: Full Authorization header value (``Basic <base64>``).
        :type auth_header: str
        :returns: User object if credentials are valid, None otherwise.
        :rtype: User | None
        """
        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            self.log_auth_failure(f"Malformed Basic auth header from {request.remote_addr}")
            return None

        username, sep, password = decoded.partition(":")
        if not sep or not username or not password:
            self.log_auth_failure(f"Basic auth header missing username or password from {request.remote_addr}")
            return None

        # Check the positive cache first, then the short-lived negative cache
        cred_key = _hash_token(decoded)
        cached_user = self._basic_auth_cache.get(cred_key)
        if cached_user is not None:
            return cached_user
        if cred_key in self._basic_auth_negative_cache:
            return None

        user = None
        entry = self._basic_auth_users.get(username.lower())
        if entry and check_password_hash(entry["password_hash"], password):
            user = User(username, list(entry["roles"]))
            logging.debug(f"Basic auth: authenticated {user.name}")

        # Cache the result
        if user is not None:
            self._basic_auth_cache[cred_key] = user
        else:
            self._basic_auth_negative_cache[cred_key] = True
            self.log_auth_failure(f"Basic auth failed for username {username.lower()!r} from {request.remote_addr}")
        return user


def load_basic_auth_users(creds_file: str) -> dict[str, dict]:
    """Load HTTP Basic auth credentials from an encrypted YAML file.

    Passwords are stored only as hashes generated with
    :func:`werkzeug.security.generate_password_hash`:

    .. code-block:: python

        from werkzeug.security import generate_password_hash

        print(generate_password_hash(input("password: ")))

    Expected YAML format (supports ``!secret`` encrypted values):

    .. code-block:: yaml

        users:
          - username: svc-legacy
            password_hash: "scrypt:32768:8:1$..."
            roles: [reader]

    :param creds_file: Path to YAML file containing Basic auth credentials.
    :type creds_file: str
    :returns: Dictionary mapping lowercase usernames to dicts with ``password_hash``
              and ``roles`` keys.
    :rtype: dict[str, dict]
    :raises BasicAuthError: If the file cannot be loaded, an entry is missing a
                            username or password hash, or an entry contains a
                            plaintext ``password`` key.
    """
    try:
        data = load_and_decrypt_yaml(file_path=creds_file)
    except FileNotFoundError:
        logging.warning(f"Basic auth credentials file not found: {creds_file}")
        debug_file_path(creds_file)
        raise BasicAuthError(f"Basic auth credentials file not found: {creds_file}") from None
    except Exception as e:
        logging.warning(f"Failed to load Basic auth credentials file: {e}")
        debug_file_path(creds_file)
        raise BasicAuthError(f"Failed to load Basic auth credentials file: {e}") from e

    users = {}
    for entry in data.get("users", []):
        username = str(entry.get("username", "")).lower()
        if not username:
            raise BasicAuthError(f"Basic auth user entry is missing 'username': {creds_file}")
        if "password" in entry:
            raise BasicAuthError(
                f"Basic auth entry for {username!r} has a 'password' key -- plaintext passwords are not "
                "supported. Store a 'password_hash' generated with werkzeug.security.generate_password_hash"
            )
        password_hash = entry.get("password_hash", "")
        # Werkzeug hashes are 'method$salt$hash'; anything without a '$' is not a hash
        if not password_hash or "$" not in password_hash:
            raise BasicAuthError(
                f"Basic auth entry for {username!r} needs a 'password_hash' generated with "
                "werkzeug.security.generate_password_hash (e.g. 'scrypt:32768:8:1$...')"
            )
        users[username] = {"password_hash": password_hash, "roles": entry.get("roles", [])}

    logging.info(f"Loaded Basic auth credentials for {len(users)} users")
    logging.debug(f"Basic auth users: {', '.join(users)}")
    return users


def load_oauth_roles(roles_file: str) -> tuple[dict[str, list[str]], list[str]]:
    """Load OAuth email-to-role mapping from an encrypted YAML file.

    Expected YAML format:

    .. code-block:: yaml

        default_roles:
          - reader

        users:
          - email: zeb@lacallegroup.com
            roles: [admin, developer]
          - email: jane@continued.com
            roles: [developer]

    :param roles_file: Path to YAML file containing OAuth role mappings.
    :type roles_file: str
    :returns: Tuple of (role_map, default_roles) where role_map is a dict mapping
              lowercase email addresses to lists of roles, and default_roles is a list
              of roles for users not in the map.
    :rtype: tuple[dict[str, list[str]], list[str]]
    :raises OAuthError: If file cannot be loaded or parsed.
    """
    try:
        data = load_and_decrypt_yaml(file_path=roles_file)
    except FileNotFoundError:
        logging.warning(f"OAuth roles file not found: {roles_file}")
        debug_file_path(roles_file)
        raise OAuthError(f"OAuth roles file not found: {roles_file}") from None
    except Exception as e:
        logging.warning(f"Failed to load OAuth roles file: {e}")
        debug_file_path(roles_file)
        raise OAuthError(f"Failed to load OAuth roles file: {e}") from e

    default_roles = data.get("default_roles", [])
    role_map = {}
    for user_entry in data.get("users", []):
        email = user_entry.get("email", "").lower()
        roles = user_entry.get("roles", [])
        if email:
            role_map[email] = roles

    emails = list(role_map.keys())
    logging.info(f"Loaded OAuth roles for {len(emails)} users")
    logging.debug(f"OAuth role emails: {', '.join(emails)}")
    if default_roles:
        logging.info(f"OAuth default roles: {', '.join(default_roles)}")

    return role_map, default_roles


def public_endpoint(f):
    """Decorator marking an endpoint as publicly accessible without authentication.

    Use for endpoints that should be accessible without authentication or authorization.

    :param f: View function to mark as public.
    :type f: callable
    :returns: Decorated function with public access flags set.
    :rtype: callable

    **Example:**

    .. code-block:: python

        @app.route("/health")
        @public_endpoint
        def health_check():
            return {"status": "ok"}
    """
    f._is_public = True
    f._rbac_is_defined = True  # flag to indicate that the decorator was used
    return f


def auth_required(*args, **kwargs):
    """Decorator requiring authentication and optionally specific roles for an endpoint.

    Can be used with or without role requirements. When used without arguments, requires
    any valid authenticated user. When used with arguments, requires user to have at
    least one of the specified roles.

    :param roles: List or set of role names, at least one of which the user must have.
                  Can be passed as first positional arg or as keyword argument.
    :type roles: list | set | None
    :returns: Decorator function that wraps the view function.
    :rtype: callable

    **Examples:**

    .. code-block:: python

        # Require any authenticated user
        @app.route("/profile")
        @auth_required
        def profile():
            return {"user": request.environ["user"].name}


        # Require specific roles
        @app.route("/admin")
        @auth_required(roles=["admin", "superuser"])
        def admin_panel():
            return {"admin": "panel"}


        # Alternative syntax
        @app.route("/admin")
        @auth_required(["admin", "superuser"])
        def admin_panel():
            return {"admin": "panel"}
    """
    # ------------------------------------------------------------
    # DANGER ZONE
    # This is some legit juju right here
    # Don't touch this without a ton of time and patience
    # ------------------------------------------------------------

    def decorator_with_args(f, inner_roles):
        # Set roles to an empty list if None
        f._required_roles = inner_roles if inner_roles is not None else []
        # Explicitly mark the view as protected: a stale _is_public=True (from a
        # stacked @public_endpoint or a reused handler) must not override auth_required.
        f._is_public = False
        f._rbac_is_defined = True  # flag to indicate that the decorator was used

        # Check if the function is async
        if inspect.iscoroutinefunction(f):

            @wraps(f)
            async def async_decorated_function(*inner_args, **inner_kwargs):
                return await f(*inner_args, **inner_kwargs)

            return async_decorated_function
        else:

            @wraps(f)
            def decorated_function(*inner_args, **inner_kwargs):
                return f(*inner_args, **inner_kwargs)

            return decorated_function

    # Determine the roles from args or kwargs
    outer_roles = kwargs.get("roles", args[0] if args else None)

    # A bare string would be iterated character-by-character ({'a','d','m','i','n'}),
    # silently making the endpoint unreachable -- fail loudly at decoration time instead.
    if isinstance(outer_roles, str):
        raise TypeError(
            f"auth_required roles must be a list or set of role names, not a bare string: {outer_roles!r}. "
            f"Use roles=[{outer_roles!r}]."
        )

    # When used without arguments (i.e., with a function)
    if args and callable(args[0]):
        return decorator_with_args(args[0], None)
    else:
        # When used with arguments
        def decorator(f):
            return decorator_with_args(f, outer_roles)

        return decorator


def _token_id(token: str) -> str:
    """Return a short token prefix that is safe to write to logs.

    Enough to identify which configured token was presented without logging a
    usable credential.

    :param token: Token string.
    :type token: str
    :returns: First 8 characters of the token followed by an ellipsis.
    :rtype: str
    """
    if not token:
        return "<empty>"
    return f"{token[:8]}..."


def _hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token.

    Persistent API tokens are held in memory keyed by this digest so that raw
    credentials never sit in the process heap. Token files are unaffected and
    still contain the raw tokens.

    :param token: Raw token string.
    :type token: str
    :returns: SHA-256 hex digest of the token.
    :rtype: str
    """
    return hashlib.sha256(token.encode()).hexdigest()


def token_from_auth_header(auth_header):
    """Extract token from Authorization header, removing 'Bearer ' prefix if present.

    :param auth_header: Authorization header value.
    :type auth_header: str
    :returns: Token string with Bearer prefix removed if present.
    :rtype: str
    """
    if auth_header.startswith("Bearer "):
        auth_header = auth_header.split(" ")[1]
    return auth_header


def load_persistent_tokens(persistent_token_file=None):
    """Load persistent API tokens from encrypted YAML file.

    Loads tokens from file in format: {"users": [{"username": str, "roles": list,
    "tokens": list}]}. Falls back to AUTH_TOKENS_FILE config if file not specified.

    :param persistent_token_file: Path to YAML file containing persistent tokens.
                                   If None, uses AUTH_TOKENS_FILE config variable.
    :type persistent_token_file: str | Path | None
    :returns: List of user dictionaries with tokens, or None if no file specified.
    :rtype: list[dict] | None
    :raises FileNotFoundError: If specified file doesn't exist.
    :raises NotADirectoryError: If file path contains invalid directory.
    :raises Exception: If file loading or parsing fails.

    .. note::
        Logs file path debug information on errors to aid troubleshooting.
    """
    persistent_tokens = None
    if not persistent_token_file:
        persistent_token_file = config_var("AUTH_TOKENS_FILE", None)
    if not persistent_token_file:
        logging.warning("No persistent token file specified")
    else:
        try:
            persistent_tokens = load_and_decrypt_yaml(file_path=persistent_token_file)["users"]
            users = [user["username"] for user in persistent_tokens]
            logging.info(f"Loaded persistent tokens for {len(users)} users")
            logging.debug(f"Persistent token users: {','.join(users)}")
        except NotADirectoryError:
            logging.warning(f"NotADirectoryError: could not load persistent token file: {persistent_token_file}")
            debug_file_path(persistent_token_file)
            raise NotADirectoryError(f"Could not find persistent token file: {persistent_token_file}") from None
        except FileNotFoundError:
            logging.warning(f"FileNotFoundError: could not load persistent token file: {persistent_token_file}")
            debug_file_path(persistent_token_file)
            raise FileNotFoundError(f"Could not find persistent token file: {persistent_token_file}") from None
        except Exception as e:
            logging.warning(f"Exception: could not load persistent token file: {e}")
            debug_file_path(persistent_token_file)
            raise ZSuiteException(f"Could not load persistent token file: {e}") from e

    return persistent_tokens


def has_required_role(user: User, required_roles: set) -> bool:
    """Check if user has at least one of the required roles.

    :param user: User object to check roles for.
    :type user: User
    :param required_roles: Set of role names, at least one of which user must have.
                           Empty set means no specific roles required.
    :type required_roles: set
    :returns: True if no roles required or user has at least one required role.
    :rtype: bool
    """
    if not required_roles:
        return True  # no roles required
    else:
        return bool(required_roles.intersection(user.roles))


def check_all_endpoints_have_rbac(app):
    """Validate all Flask endpoints have RBAC decorators applied.

    Checks that every registered endpoint has either @auth_required or @public_endpoint
    decorator. Static endpoint is automatically ignored.

    :param app: Flask application to validate.
    :type app: Flask
    :raises MissingRBACError: If any endpoints lack RBAC decorators.
    """
    missing = set()
    ignore_endpoints = {"static"}  # Set of endpoints to ignore (static is a flask default and always ignored)

    # Get a list of endpoints that are missing RBAC
    for endpoint, view_func in app.view_functions.items():
        if not getattr(view_func, "_rbac_is_defined", False):
            missing.add(endpoint)

    # Remove ignored endpoints from the missing set
    missing -= ignore_endpoints

    # If there are missing endpoints, raise an exception
    if missing:
        msg = f"ERROR: Endpoints are missing auth decorators: {', '.join(missing)}"
        logging.warning(msg)
        raise MissingRBACError(msg)


def _ensure_rbac(view_func):
    """Ensure view function has RBAC defined, abort with 500 if missing.

    Safety check that should never trigger if check_all_endpoints_have_rbac is used.

    :param view_func: View function to validate.
    :type view_func: callable
    :raises HTTPException: 500 if RBAC not defined.
    """
    # this condition should never be true as it is checked in __init__, but just in case
    if not getattr(view_func, "_rbac_is_defined", False):
        logging.warning(f"Endpoint {request.endpoint} has no RBAC defined")
        abort(500, "Internal Server Error: No RBAC defined for endpoint")


def _get_users_from_tokens(persistent_tokens):
    """Convert persistent token data into User objects indexed by token.

    :param persistent_tokens: List of user dictionaries with username, roles, and tokens.
    :type persistent_tokens: list[dict]
    :returns: Dictionary mapping SHA-256 token digests to User objects.
    :rtype: dict[str, User]
    :raises ValueError: If any token is shorter than 16 characters.
    """
    # Load persistent tokens into a dict for faster lookup, keyed by digest so
    # raw credentials are not kept in memory
    token_users = {}
    if persistent_tokens:
        for raw in persistent_tokens:
            user = User(raw["username"], raw["roles"])
            for token in raw["tokens"]:
                if len(token) < 16:
                    msg = f"Token for {user.name} is too short, must be at least 16 characters"
                    logging.critical(msg)
                    raise ValueError(msg)
                token_users[_hash_token(token)] = user
    return token_users


def get_token_users(persistent_token_file, persistent_tokens):
    """Load and prepare persistent API tokens for authentication.

    Loads tokens from file or dict and converts to User objects indexed by token.
    Falls back to AUTH_TOKENS_FILE config if neither parameter provided.

    :param persistent_token_file: Path to YAML file containing tokens.
    :type persistent_token_file: str | Path | None
    :param persistent_tokens: Pre-loaded token data. Mutually exclusive with
                              persistent_token_file.
    :type persistent_tokens: list[dict] | None
    :returns: Dictionary mapping SHA-256 token digests to User objects.
    :rtype: dict[str, User]
    :raises ValueError: If both persistent_tokens and persistent_token_file provided.
    :raises ValueError: If any token is shorter than 16 characters.
    """
    # Load persistent tokens if provided
    token_users = {}
    if persistent_tokens and persistent_token_file:
        raise ValueError("persistent_tokens and persistent_token_file are mutually exclusive")
    if not persistent_tokens and not persistent_token_file and config_var("AUTH_TOKENS_FILE", None):
        persistent_token_file = config_var("AUTH_TOKENS_FILE")
    if persistent_token_file:
        persistent_tokens = load_persistent_tokens(persistent_token_file)
    if persistent_tokens:
        token_users = _get_users_from_tokens(persistent_tokens)
    return token_users
