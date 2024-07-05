class ZSuiteException(Exception):
    """Base exception for zsuite."""


class UndeterminedBool(ZSuiteException):
    """Raised when a boolean value cannot be determined."""
