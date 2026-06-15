from __future__ import annotations


class ScannerError(Exception):
    """Base class for all scanner errors."""


class ConfigError(ScannerError):
    """Raised when configuration is missing or invalid."""


class ValidationError(ScannerError):
    """Raised when user input (IPs, credentials_env, payload) is invalid."""


class ProbeError(ScannerError):
    """Raised when a Phase 1 probe fails unexpectedly."""


class NetworkError(ScannerError):
    """Transient connectivity failure. Safe to retry."""


class ScanTimeoutError(NetworkError):
    """A phase or probe exceeded its allotted time budget."""


class AuthFailure(ScannerError):
    """Authentication was rejected (wrong credentials / no authorization).

    Terminal by design: the controllers must NOT retry on this error because
    repeated attempts can lock out accounts and never succeed.
    """


class AuthorizationError(AuthFailure):
    """Authenticated successfully but lacks permission for the operation."""


class ExtractionError(ScannerError):
    """Raised when Phase 3 data extraction fails."""


class QueueError(ScannerError):
    """Raised on RabbitMQ publish/consume failures."""


class DatabaseError(ScannerError):
    """Raised on PostgreSQL connection or query failures."""


class CryptoError(ScannerError):
    """Raised when credential encryption/decryption fails."""
