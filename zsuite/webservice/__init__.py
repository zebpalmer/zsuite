"""Web service utilities for Flask applications.

This module provides Flask middleware, authentication, and web service helpers.
Requires installation with the webservice extra: install zsuite[webservice]
"""

# Check for required dependencies
try:
    import flask
    import werkzeug
except ImportError as e:
    raise ImportError("Web service dependencies not found: install zsuite[webservice]") from e

from .auth import (
    AuthManager,
    User,
    auth_required,
    public_endpoint,
)
from .halo_flask import (
    HALOFlask,
    current_user,
    current_user_name,
    current_ws,
    skip_logging,
)
from .health_service import HealthService, check_callable
from .mongodb_utils import VALID_MONGO_OPERATORS, sanitize_mongo_query, validate_mongo_query

__all__ = [
    "VALID_MONGO_OPERATORS",
    "AuthManager",
    "HALOFlask",
    "HealthService",
    "User",
    "auth_required",
    "check_callable",
    "current_user",
    "current_user_name",
    "current_ws",
    "public_endpoint",
    "sanitize_mongo_query",
    "skip_logging",
    "validate_mongo_query",
]
