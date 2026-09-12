"""Wire-shaped types for request `_meta`, origin tags, and gate decisions.

Field names follow the drafts they are inspired by. This is an educational
sample, not a conformance suite.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

OriginKind = Literal["user", "named_source", "records", "untrusted_tool"]
TRUSTED_ORIGINS: frozenset[str] = frozenset({"user", "named_source", "records"})

AI_INVOCATION_KEYS = (
    "aiInvocation",
    "io.modelcontextprotocol/aiInvocation",
)
ATTESTATION_KEYS = (
    "channelPolicyAttestation",
    "io.modelcontextprotocol/channel-policy-attestation",
)
ORIGIN_TAG_KEYS = (
    "originTags",
    "io.modelcontextprotocol/originTags",
)

DEFAULT_ATTESTATION_SECRET = os.environ.get(
    "META_GATE_ATTESTATION_SECRET", "demo-not-a-production-secret"
)
DEFAULT_ISSUER = os.environ.get("META_GATE_TRUSTED_ISSUER", "mcp-host/demo")
DEFAULT_REPUTATION_THRESHOLD = 0.85


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. ``Z`` and offsets are accepted."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def canonical_json(value: Any) -> bytes:
    """Stable bytes for HMAC. Same bytes must be signed and verified."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def first_meta(meta: Mapping[str, Any] | None, keys: tuple[str, ...]) -> Any:
    if not meta:
        return None
    for key in keys:
        if key in meta:
            return meta[key]
    return None


@dataclass(frozen=True)
class Reason:
    """One explainable finding. ``field`` is a dotted path when possible."""

    code: str
    message: str
    field: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class AiInvocation:
    """SEP-2817-shaped client-asserted audit context.

    AUDIT ONLY. An MCP server must never allow or deny from these fields.
    """

    turn_id: str
    user_intent: str
    invocation_reason: str = "user_initiated"
    model: str | None = None

    def to_wire(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "turnId": self.turn_id,
            "userIntent": self.user_intent,
            "invocationReason": self.invocation_reason,
        }
        if self.model:
            payload["model"] = self.model
        return payload

    @classmethod
    def from_wire(cls, data: Mapping[str, Any] | None) -> AiInvocation | None:
        if not isinstance(data, Mapping):
            return None
        turn_id = data.get("turnId") or data.get("turn_id")
        user_intent = data.get("userIntent") or data.get("user_intent")
        if not turn_id:
            return None
        return cls(
            turn_id=str(turn_id),
            user_intent=str(user_intent or ""),
            invocation_reason=str(data.get("invocationReason") or data.get("invocation_reason") or "user_initiated"),
            model=(str(data["model"]) if data.get("model") else None),
        )


@dataclass(frozen=True)
class ChannelPolicyAttestation:
    """Per-send enforcement proof. Inspired by channel-policy attestation.

    This is the door key. The MCP server *does* authorize from a verified
    envelope. HMAC-SHA256 is a demo MAC — not WebAuthn, not SEP-3004.
    """

    channel: str
    tool_name: str
    issuer: str
    issued_at: str
    expires_at: str
    nonce: str
    template_valid: bool = True
    opted_in: bool = True
    schema_valid: bool = True
    sender_reputation: float = 0.94
    reputation_threshold: float = DEFAULT_REPUTATION_THRESHOLD
    mac: str = ""

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "expiresAt": self.expires_at,
            "issuedAt": self.issued_at,
            "issuer": self.issuer,
            "nonce": self.nonce,
            "optInState": {"optedIn": self.opted_in},
            "schemaCorrectness": {"valid": self.schema_valid},
            "senderReputation": {
                "score": self.sender_reputation,
                "threshold": self.reputation_threshold,
            },
            "templateValidity": {"valid": self.template_valid},
            "toolName": self.tool_name,
        }

    def compute_mac(self, secret: str) -> str:
        digest = hmac.new(secret.encode("utf-8"), canonical_json(self.unsigned_payload()), hashlib.sha256)
        return digest.hexdigest()

    def signed(self, secret: str) -> ChannelPolicyAttestation:
        return ChannelPolicyAttestation(
            **{**asdict(self), "mac": self.compute_mac(secret)},
        )

    def to_wire(self) -> dict[str, Any]:
        payload = self.unsigned_payload()
        payload["mac"] = self.mac
        return payload

    def verify_mac(self, secret: str) -> bool:
        if not self.mac:
            return False
        expected = self.compute_mac(secret)
        return hmac.compare_digest(expected, self.mac)

    @classmethod
    def from_wire(cls, data: Mapping[str, Any] | None) -> ChannelPolicyAttestation | None:
        if not isinstance(data, Mapping):
            return None
        opt_in = data.get("optInState") or {}
        schema = data.get("schemaCorrectness") or {}
        reputation = data.get("senderReputation") or {}
        template = data.get("templateValidity") or {}
        tool_name = data.get("toolName") or data.get("tool_name")
        channel = data.get("channel")
        issuer = data.get("issuer")
        if not (tool_name and channel and issuer):
            return None
        return cls(
            channel=str(channel),
            tool_name=str(tool_name),
            issuer=str(issuer),
            issued_at=str(data.get("issuedAt") or data.get("issued_at") or ""),
            expires_at=str(data.get("expiresAt") or data.get("expires_at") or ""),
            nonce=str(data.get("nonce") or ""),
            template_valid=bool(template.get("valid", data.get("template_valid", False))),
            opted_in=bool(opt_in.get("optedIn", data.get("opted_in", False))),
            schema_valid=bool(schema.get("valid", data.get("schema_valid", False))),
            sender_reputation=float(reputation.get("score", data.get("sender_reputation", 0.0))),
            reputation_threshold=float(
                reputation.get("threshold", data.get("reputation_threshold", DEFAULT_REPUTATION_THRESHOLD))
            ),
            mac=str(data.get("mac") or ""),
        )


@dataclass(frozen=True)
class HostPolicy:
    """What the MCP host/client interceptor is willing to attest."""

    issuer: str = DEFAULT_ISSUER
    allowed_channels: frozenset[str] = field(default_factory=lambda: frozenset({"sms"}))
    allowed_tools: frozenset[str] = field(default_factory=lambda: frozenset({"send_sms"}))
    attestation_ttl_seconds: int = 300

    def may_attest(self, tool_name: str, channel: str) -> bool:
        return tool_name in self.allowed_tools and channel in self.allowed_channels


@dataclass(frozen=True)
class ServerPolicy:
    """What the MCP server gate requires before an outbound tool runs."""

    trusted_issuers: frozenset[str] = field(default_factory=lambda: frozenset({DEFAULT_ISSUER}))
    attestation_secret: str = DEFAULT_ATTESTATION_SECRET
    require_attestation_for_outbound: bool = True
    fail_closed_missing_origin: bool = True


@dataclass
class ToolCall:
    """Minimal MCP ``tools/call`` request the interceptor stamps and the gate sees."""

    name: str
    arguments: dict[str, Any]
    meta: dict[str, Any] = field(default_factory=dict)
    request_id: str | int = 1

    def to_rpc(self) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/call",
            "params": {
                "name": self.name,
                "arguments": self.arguments,
                "_meta": self.meta,
            },
        }

    @classmethod
    def from_rpc(cls, message: Mapping[str, Any]) -> ToolCall:
        params = message.get("params") or {}
        return cls(
            name=str(params.get("name") or ""),
            arguments=dict(params.get("arguments") or {}),
            meta=dict(params.get("_meta") or {}),
            request_id=message.get("id", 1),
        )

    def ai_invocation(self) -> AiInvocation | None:
        return AiInvocation.from_wire(first_meta(self.meta, AI_INVOCATION_KEYS))

    def attestation(self) -> ChannelPolicyAttestation | None:
        return ChannelPolicyAttestation.from_wire(first_meta(self.meta, ATTESTATION_KEYS))

    def origin_tags(self) -> dict[str, str]:
        raw = first_meta(self.meta, ORIGIN_TAG_KEYS) or {}
        if not isinstance(raw, Mapping):
            return {}
        return {str(k): str(v) for k, v in raw.items()}

    def turn_id(self) -> str | None:
        invocation = self.ai_invocation()
        return invocation.turn_id if invocation else None


@dataclass(frozen=True)
class AuditEntry:
    """Server-side decision record. ``turnId`` is correlation, not a grant."""

    turn_id: str | None
    tool_name: str
    allowed: bool
    reasons: tuple[Reason, ...]
    attestation_present: bool
    ai_invocation_logged: bool
    used_ai_invocation_for_authz: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "turnId": self.turn_id,
            "toolName": self.tool_name,
            "allowed": self.allowed,
            "attestationPresent": self.attestation_present,
            "aiInvocationLogged": self.ai_invocation_logged,
            "usedAiInvocationForAuthz": self.used_ai_invocation_for_authz,
            "reasons": [r.to_dict() for r in self.reasons],
        }


@dataclass(frozen=True)
class GateDecision:
    """Allow or SEP-2643-shaped deny. Audit fields never decide this."""

    allowed: bool
    tool_name: str
    turn_id: str | None
    reasons: tuple[Reason, ...]
    result: dict[str, Any] | None = None
    denial: dict[str, Any] | None = None
    audit: AuditEntry | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "allowed": self.allowed,
            "toolName": self.tool_name,
            "turnId": self.turn_id,
            "reasons": [r.to_dict() for r in self.reasons],
        }
        if self.result is not None:
            payload["result"] = self.result
        if self.denial is not None:
            payload["denial"] = self.denial
        if self.audit is not None:
            payload["audit"] = self.audit.to_dict()
        return payload
