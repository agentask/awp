"""The single {code, detail, retryable} error grammar shared by sync and
async paths (core §2.6) — a Python counterpart to internal/apperr."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Error(Exception):
    code: str
    detail: str
    retryable: bool = False

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "detail": self.detail, "retryable": self.retryable}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Error":
        return Error(code=d["code"], detail=d.get("detail", ""), retryable=bool(d.get("retryable", False)))


CODE_UNSUPPORTED_BODY = "unsupported_body"
CODE_UNAUTHORIZED_DELEGATION = "unauthorized_delegation"
CODE_CAPACITY = "capacity"
CODE_REFUSED = "refused"
CODE_INTERNAL = "internal"

CODE_MALFORMED = "malformed"
CODE_EXPIRED = "expired"
CODE_UNAUTHORIZED = "unauthorized"
