"""Typed shapes for request ``_meta``: audit context, attestation, origin tags.

SEP-2817 inspiration (draft): client-asserted AI invocation audit context
(``turnId``, ``userIntent`` / ``invocationReason``, optional ``model``).
Those fields are explicitly **not** authorization evidence.

Channel-policy attestation is a separate HMAC envelope used for enforcement.

ROPE-lite origin labels follow the paper's structural trust idea
(arXiv:2608.27496): a sensitive value should trace to the user, a source the
user named, or the user's own records — not to attacker-writable tool output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

OriginLabel = Literal["user", "named_source", "records", "untrusted_tool"]
TRUSTED_ORIGINS: frozenset[str] = frozenset({"user", "named_source", "records"})

# Public demo key. Not a secret. Override with META_GATE_HMAC_KEY if you want.
DEMO_HMAC_KEY = b"mcp-meta-gate-demo-key-not-a-secret"

OUTBOUND_TOOLS: frozenset[str] = frozenset({"send_sms", "post_github"})

# (channel, allowed destination classes, sensitive argument names, dest arg)
TOOL_POLICY: dict[str, tuple[str, frozenset[str], tuple[str, ...], str]] = {
    "send_sms": ("sms", frozenset({"user_owned_sms"}), ("to", "body"), "to"),
    "post_github": (
        "github",
        frozenset({"private_repo"}),
        ("repo", "visibility", "body"),
        "repo",
    ),
}


def hmac_key_from_env() -> bytes:
    raw = os.environ.get("META_GATE_HMAC_KEY")
    if raw:
        return raw.encode("utf-8")
    return DEMO_HMAC_KEY


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. ``Z`` and offsets are accepted."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def canonical_dumps(payload: Mapping[str, Any]) -> bytes:
    """Stable JSON bytes for HMAC. Same bytes on the MCP host/client and MCP server."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hmac_hex(key: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(key, canonical_dumps(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AiInvocation:
    """SEP-2817-shaped audit context. Never used to allow or deny."""

    turn_id: str
    user_intent: str
    invocation_reason: str
    model: str | None = None

    def to_meta(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "turnId": self.turn_id,
            "userIntent": self.user_intent,
            "invocationReason": self.invocation_reason,
        }
        if self.model:
            data["model"] = self.model
        return data

    @classmethod
    def from_meta(cls, data: Mapping[str, Any] | None) -> AiInvocation | None:
        if not data:
            return None
        turn_id = str(data.get("turnId") or data.get("turn_id") or "").strip()
        if not turn_id:
            return None
        return cls(
            turn_id=turn_id,
            user_intent=str(data.get("userIntent") or data.get("user_intent") or ""),
            invocation_reason=str(
                data.get("invocationReason") or data.get("invocation_reason") or ""
            ),
            model=(str(data["model"]) if data.get("model") else None),
        )


@dataclass(frozen=True)
class ChannelPolicyAttestation:
    """HMAC envelope that *is* enforcement evidence.

    Binds channel, destination class, expiry, nonce, tool, and destination so
    an SMS attestation cannot be replayed onto ``post_github``.
    """

    channel: str
    destination_class: str
    expires_at: str
    nonce: str
    tool: str
    destination: str
    mac: str = ""

    def unsigned_payload(self) -> dict[str, str]:
        return {
            "channel": self.channel,
            "destination": self.destination,
            "destinationClass": self.destination_class,
            "expiresAt": self.expires_at,
            "nonce": self.nonce,
            "tool": self.tool,
        }

    def sign(self, key: bytes) -> ChannelPolicyAttestation:
        return ChannelPolicyAttestation(
            channel=self.channel,
            destination_class=self.destination_class,
            expires_at=self.expires_at,
            nonce=self.nonce,
            tool=self.tool,
            destination=self.destination,
            mac=hmac_hex(key, self.unsigned_payload()),
        )

    def verify(self, key: bytes) -> bool:
        if not self.mac:
            return False
        expected = hmac_hex(key, self.unsigned_payload())
        return hmac.compare_digest(self.mac, expected)

    def to_meta(self) -> dict[str, str]:
        data = self.unsigned_payload()
        data["mac"] = self.mac
        return data

    @classmethod
    def from_meta(cls, data: Mapping[str, Any] | None) -> ChannelPolicyAttestation | None:
        if not data:
            return None
        try:
            return cls(
                channel=str(data["channel"]),
                destination_class=str(
                    data.get("destinationClass") or data.get("destination_class") or ""
                ),
                expires_at=str(data.get("expiresAt") or data.get("expires_at") or ""),
                nonce=str(data.get("nonce") or ""),
                tool=str(data.get("tool") or ""),
                destination=str(data.get("destination") or ""),
                mac=str(data.get("mac") or data.get("signature") or ""),
            )
        except KeyError:
            return None


def unwrap_params(request: Mapping[str, Any]) -> dict[str, Any]:
    """Accept a full JSON-RPC ``tools/call`` or the inner ``params`` object."""
    if "params" in request and isinstance(request["params"], Mapping):
        return dict(request["params"])
    return dict(request)


def request_meta(params: Mapping[str, Any]) -> dict[str, Any]:
    meta = params.get("_meta")
    return dict(meta) if isinstance(meta, Mapping) else {}


def origin_for(arg_name: str, meta: Mapping[str, Any]) -> str | None:
    """Resolve a ROPE-lite label for one argument.

    Per-arg ``originTags`` win. ``_meta.origin`` may be a string default or a
    mapping of argument → label (or ``{label, source}``).
    """
    tags = meta.get("originTags") or meta.get("origin_tags") or {}
    if isinstance(tags, Mapping) and arg_name in tags:
        return _label_of(tags[arg_name])

    origin = meta.get("origin")
    if isinstance(origin, Mapping):
        if arg_name in origin:
            return _label_of(origin[arg_name])
        if "default" in origin:
            return _label_of(origin["default"])
        if "label" in origin:
            return _label_of(origin["label"])
        return None
    if isinstance(origin, str) and origin.strip():
        return origin.strip()
    return None


def _label_of(value: Any) -> str | None:
    if isinstance(value, Mapping):
        label = value.get("label") or value.get("origin")
        return str(label) if label else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None
