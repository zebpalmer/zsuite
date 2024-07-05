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
