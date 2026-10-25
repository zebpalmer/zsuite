class ZSuiteException(Exception):
    """Base exception for zsuite."""


class UndeterminedBool(ZSuiteException):
    """Raised when a boolean value cannot be determined."""


class EncryptedValueError(ZSuiteException):
    """Raised when an encrypted value cannot be decrypted."""


class MissingVaultKey(ZSuiteException):
    """Raised when a VAULT_KEY environment variable is missing."""


class CircuitBreakerTripped(ZSuiteException):
    """Raised when a circuit breaker trips."""


class StaleFile(ZSuiteException):
    """Raised when a file is older than the expected freshness window."""


class FileNotFound(ZSuiteException):
    """Raised when a file cannot be found in any of the specified locations."""


class ConfigurationError(ZSuiteException, ValueError):
    """Raised for missing or invalid configuration.

    Also inherits ValueError so callers catching ValueError for a missing config var keep working.
    """


class MissingRBACError(ZSuiteException):
    """Raised when a webservice endpoint has no RBAC configuration."""


class MongoQueryError(ZSuiteException):
    """Raised for unsafe MongoDB query structures (potential NoSQL injection)."""


class OAuthError(ZSuiteException):
    """Raised for OAuth configuration or validation errors."""


class BasicAuthError(ZSuiteException):
    """Raised for HTTP Basic auth configuration errors."""
