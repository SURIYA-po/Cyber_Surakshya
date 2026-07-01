"""Exceptions raised by memory providers."""


class MemoryError(Exception):
    """Base exception for memory layer failures."""


class MemoryRecordNotFoundError(MemoryError):
    """Raised when a requested memory record does not exist."""


class MemoryRecordAlreadyExistsError(MemoryError):
    """Raised when storing a duplicate memory record is not allowed."""


class MemoryValidationError(MemoryError):
    """Raised when memory input is invalid for a provider operation."""
