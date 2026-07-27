"""A minimal xAI Grok client: plain httpx against the OpenAI-compatible
/v1/chat/completions endpoint. No LLM SDK dependency — this repo's general
minimal-dependency ethos (see root CLAUDE.md: "no cgo anywhere", "do NOT
pull a [...] library") applies just as well to a single HTTP call like
this one, and matches agents/go/llm.go and agents/rust/src/llm.rs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

import httpx

XAI_ENDPOINT = "https://api.x.ai/v1/chat/completions"


class ChatMessage(TypedDict):
    role: str
    content: str


class LLMError(Exception):
    pass


@dataclass
class GrokClient:
    """Calls the xAI chat completions endpoint."""

    api_key: str
    model: str
    http: httpx.Client | None = None

    def __post_init__(self) -> None:
        if self.http is None:
            self.http = httpx.Client(timeout=60.0)

    def complete(self, system_prompt: str, history: list[ChatMessage], user_content: str) -> str:
        """Sends system_prompt plus history (prior turns) plus a final
        user message with user_content, and returns the model's reply
        text."""
        messages: list[ChatMessage] = [{"role": "system", "content": system_prompt}]
        messages.extend(history)
        messages.append({"role": "user", "content": user_content})

        req_body = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        assert self.http is not None
        try:
            resp = self.http.post(
                XAI_ENDPOINT,
                json=req_body,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as e:
            raise LLMError(f"llm: request failed: {e}") from e

        if resp.status_code != 200:
            raise LLMError(f"llm: xAI returned status {resp.status_code}: {resp.text}")

        try:
            out = resp.json()
        except Exception as e:
            raise LLMError(f"llm: parse response: {e}") from e

        choices = out.get("choices") or []
        if not choices:
            raise LLMError(f"llm: no choices in response: {resp.text}")
        return str(choices[0]["message"]["content"])
