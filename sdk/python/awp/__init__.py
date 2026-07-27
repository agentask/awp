"""awp is the AWP reference Python SDK: a thin client for sending
envelopes and calling sync tools, plus the identity/envelope/manifest/
delegation/httpsig primitives it's built from.

"Thin" is deliberate: unlike a full daemon, this client keeps no on-disk
state, runs no retry/outbox state machine, and does not receive envelopes
on its own — it is for third-party Python programs that want to speak AWP
directly (sign, send, verify) without running one. Domain indexes are
cached in memory for the lifetime of the Client only.

See README.md for what this package does and does not do.
"""

from .client import CallOptions, Client, RemoteRejectedError, SessionInfo, ToolCallError
from .envelope import Envelope
from .identity import Index

__all__ = [
    "CallOptions",
    "Client",
    "Envelope",
    "Index",
    "RemoteRejectedError",
    "SessionInfo",
    "ToolCallError",
]
