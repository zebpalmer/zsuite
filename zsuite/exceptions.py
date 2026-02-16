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
