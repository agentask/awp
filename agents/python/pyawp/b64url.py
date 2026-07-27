"""base64url, unpadded — the encoding core §0 mandates for every signature
and raw key (RFC 4648 §5), matching Go's base64.RawURLEncoding exactly."""

from __future__ import annotations

import base64


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
