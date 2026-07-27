"""base64url, unpadded — the encoding core §0 mandates for every signature
and raw key (RFC 4648 §5), matching Go's base64.RawURLEncoding exactly.

Content-Digest (httpsig.py) deliberately does NOT use this module — it is
standard, padded base64 (base64.StdEncoding on the Go side), a different
encoding for a different header. Do not conflate the two.
"""

from __future__ import annotations

import base64


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
