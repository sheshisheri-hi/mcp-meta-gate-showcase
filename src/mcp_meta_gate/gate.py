"""MCP server gate: attest + origin enforce; aiInvocation is audit only.

The MCP server always records ``turnId`` and reason from ``_meta.aiInvocation``.
It never allow/denies from that text. Sensitive outbound tools require a valid
channel-policy attestation and ROPE-lite trusted origins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .denials import (
    AuthorizationDenial,
    authorization_denial,
    hint_destination_class,
    hint_obtain_attestation,
    hint_relabel_origin,
)
from .demo_tools import execute_tool
from .models import (
    OUTBOUND_TOOLS,
    TOOL_POLICY,
    TRUSTED_ORIGINS,
    AiInvocation,
    ChannelPolicyAttestation,
    hmac_key_from_env,
    origin_for,
    parse_utc,
    request_meta,
    unwrap_params,
)


@dataclass
class AuditLog:
    """In-memory audit trail. Correlation only — not an allow-list."""

    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(
        self,
        *,
        turn_id: str | None,
        user_intent: str,
        invocation_reason: str,
        tool: str,
        verdict: str,
        classification: str | None = None,
    ) -> dict[str, Any]:
        entry = {
            "turnId": turn_id,
            "userIntent": user_intent,
            "invocationReason": invocation_reason,
            "tool": tool,
            "verdict": verdict,
            "classification": classification,
            "auditOnly": True,
        }
        self.entries.append(entry)
        return entry

    def turn_ids(self) -> list[str | None]:
        return [e.get("turnId") for e in self.entries]


@dataclass(frozen=True)
class GateDecision:
    verdict: str
    tool_name: str
    turn_id: str | None
    audit: dict[str, Any]
    denial: AuthorizationDenial | None = None
    result: dict[str, Any] | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    def to_jsonrpc(self, request_id: Any = None) -> dict[str, Any]:
        if self.denial is not None:
            return self.denial.to_jsonrpc(request_id)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": _preview(self.result)}],
                "structuredContent": self.result or {},
                "isError": False,
                "_meta": {"turnId": self.turn_id, "decision": "allow"},
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "tool": self.tool_name,
            "turnId": self.turn_id,
            "allowed": self.allowed,
            "denial": self.denial.to_dict() if self.denial else None,
            "result": self.result,
            "audit": self.audit,
        }


class ServerGate:
    """Enforcement point on the MCP server. Audit ≠ authorization."""

    def __init__(
        self,
        *,
        hmac_key: bytes | None = None,
        audit: AuditLog | None = None,
        now: datetime | None = None,
        execute: bool = True,
    ) -> None:
        self.hmac_key = hmac_key if hmac_key is not None else hmac_key_from_env()
        self.audit = audit if audit is not None else AuditLog()
        self._now = now
        self.execute = execute

    def clock(self) -> datetime:
        if self._now is not None:
            now = self._now
            return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    def handle_tools_call(self, request: Mapping[str, Any]) -> dict[str, Any]:
        decision = self.evaluate(request)
        return decision.to_jsonrpc(request.get("id"))

    def evaluate(self, request: Mapping[str, Any]) -> GateDecision:
        params = unwrap_params(request)
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), Mapping) else {}
        meta = request_meta(params)

        # --- AUDIT ONLY. Read, log later, never branch on these strings. ---
        invocation = AiInvocation.from_meta(
            meta.get("aiInvocation") if isinstance(meta.get("aiInvocation"), Mapping) else None
        )
        turn_id = invocation.turn_id if invocation else None
        user_intent = invocation.user_intent if invocation else ""
        invocation_reason = invocation.invocation_reason if invocation else ""
        # --- end audit extract ---

        denial = self._enforce(tool_name, arguments, meta, turn_id)
        verdict = "deny" if denial else "allow"
        audit_row = self.audit.record(
            turn_id=turn_id,
            user_intent=user_intent,
            invocation_reason=invocation_reason,
            tool=tool_name,
            verdict=verdict,
            classification=denial.classification if denial else None,
        )
        if denial:
            return GateDecision(
                verdict="deny",
                tool_name=tool_name,
                turn_id=turn_id,
                audit=audit_row,
                denial=denial,
            )
        result = None
        if self.execute and tool_name:
            result = execute_tool(tool_name, arguments)
        return GateDecision(
            verdict="allow",
            tool_name=tool_name,
            turn_id=turn_id,
            audit=audit_row,
            result=result,
        )

    def _enforce(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        meta: Mapping[str, Any],
        turn_id: str | None,
    ) -> AuthorizationDenial | None:
        """Authorization. Intentionally does not read userIntent / invocationReason."""
        if tool_name not in OUTBOUND_TOOLS:
            return authorization_denial(
                "unknown_outbound_tool",
                f"MCP server refused unknown tool {tool_name!r}.",
                turn_id=turn_id,
                field="params.name",
            )

        channel, allowed_classes, sensitive, dest_field = TOOL_POLICY[tool_name]
        raw = meta.get("channelPolicyAttestation") or meta.get("channel_policy_attestation")
        attestation = ChannelPolicyAttestation.from_meta(
            raw if isinstance(raw, Mapping) else None
        )
        if attestation is None:
            return authorization_denial(
                "missing_channel_attestation",
                (
                    f"Outbound tool '{tool_name}' requires a valid "
                    "channelPolicyAttestation. aiInvocation is audit-only and "
                    "cannot authorize this call."
                ),
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )

        if not attestation.verify(self.hmac_key):
            return authorization_denial(
                "invalid_channel_attestation",
                "channelPolicyAttestation MAC did not verify on the MCP server.",
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation.mac",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )

        if attestation.tool != tool_name:
            return authorization_denial(
                "attestation_tool_mismatch",
                (
                    f"Attestation is bound to tool '{attestation.tool}', "
                    f"not '{tool_name}'."
                ),
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation.tool",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )

        if attestation.channel != channel:
            return authorization_denial(
                "channel_mismatch",
                f"Attestation channel '{attestation.channel}' is not '{channel}'.",
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation.channel",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )

        bound_dest = str(arguments.get(dest_field, ""))
        if attestation.destination and attestation.destination != bound_dest:
            return authorization_denial(
                "attestation_destination_mismatch",
                "Attestation destination does not match the tool argument.",
                turn_id=turn_id,
                field=f"arguments.{dest_field}",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )

        try:
            expiry = parse_utc(attestation.expires_at)
        except (ValueError, TypeError):
            return authorization_denial(
                "invalid_channel_attestation",
                "channelPolicyAttestation expiresAt is not a valid timestamp.",
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation.expiresAt",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )
        if expiry <= self.clock():
            return authorization_denial(
                "expired_channel_attestation",
                "channelPolicyAttestation has expired.",
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation.expiresAt",
                hints=[hint_obtain_attestation(channel, tool_name)],
            )

        if attestation.destination_class not in allowed_classes:
            return authorization_denial(
                "destination_class_denied",
                (
                    f"Destination class '{attestation.destination_class}' is not "
                    f"allowed for '{tool_name}'."
                ),
                turn_id=turn_id,
                field="_meta.channelPolicyAttestation.destinationClass",
                hints=[hint_destination_class(allowed_classes)],
            )

        return self._check_origins(sensitive, meta, turn_id)

    def _check_origins(
        self,
        sensitive: tuple[str, ...],
        meta: Mapping[str, Any],
        turn_id: str | None,
    ) -> AuthorizationDenial | None:
        for name in sensitive:
            label = origin_for(name, meta)
            if label in TRUSTED_ORIGINS:
                continue
            # Missing or untrusted_tool (or anything else) is fail-closed.
            return authorization_denial(
                "untrusted_origin",
                (
                    f"Sensitive argument '{name}' has origin {label!r}. "
                    "ROPE-lite allows only user / named_source / records."
                ),
                turn_id=turn_id,
                field=f"_meta.originTags.{name}",
                hints=[hint_relabel_origin(name)],
            )
        return None


def _preview(result: dict[str, Any] | None) -> str:
    if not result:
        return "ok"
    if result.get("tool") == "send_sms":
        return f"SMS queued to {result.get('to')} (mock)"
    if result.get("tool") == "post_github":
        return f"Posted to {result.get('repo')} (mock)"
    return "ok"
