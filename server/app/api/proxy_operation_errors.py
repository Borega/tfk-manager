from __future__ import annotations


class ProxyOperationError(RuntimeError):
    def __init__(self, error_code: str, message: str, status: int = 400, details: dict[str, object] | None = None):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.status = status
        self.details = details or {}
