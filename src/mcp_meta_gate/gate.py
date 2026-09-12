"""MCP server gate: log turnId, require attestation, ignore audit for authz.

The gate is the only allow/deny point. ``aiInvocation`` is written to the
audit trail and then forgotten for the decision. ROPE-lite checks where a
sensitive argument came from, not what it says.
"""

from __future__ import annotations

from typing import Any, Iterable

from .denials import structured_denial
from .models import (
    TRUSTED_ORIGINS,
    AuditEntry,
    ChannelPolicyAttestation,
    GateDecision,
    Reason,
    ServerPolicy,
    ToolCall,
    parse_utc,
    utc_now,
)


class ServerGate:
    """Evaluate a stamped ``tools/call`` on the MCP server."""

    def __init__(self, *, policy: ServerPolicy | None = None) -> None:
        self.policy = policy or ServerPolicy()
        self.audit_log: list[AuditEntry] = []

    def evaluate(self, call: ToolCall | dict[str, Any], *, now=None) -> GateDecision:
        request = call if isinstance(call, ToolCall) else ToolCall.from_rpc(call)
        from .demo_tools import execute_mock, is_outbound, spec_for

        invocation = request.ai_invocation()
        turn_id = invocation.turn_id if invocation else None
        reasons: list[Reason] = []

        spec = spec_for(request.name)
        if spec is None:
            reasons.append(
                Reason(
                    code="unknown_tool",
                    message=f"MCP server does not expose tool '{request.name}'.",
                    field="params.name",
                )
            )
            return self._deny(request, turn_id, reasons, classification="policy_blocked")

        attestation = request.attestation()
        outbound = is_outbound(request.name)

        if outbound and self.policy.require_attestation_for_outbound:
            reasons.extend(self._check_attestation(request, attestation, spec.channel, now=now))

        reasons.extend(self._check_origins(request, spec.sensitive_args))

        # Explicit non-use of audit fields. userIntent / model / invocationReason
        # are logged only. A glowing intent must never unlock an outbound tool.
        _ = invocation.user_intent if invocation else None
        _ = invocation.model if invocation else None
        _ = invocation.invocation_reason if invocation else None

        if reasons:
            return self._deny(request, turn_id, reasons, classification="policy_blocked")

        result = execute_mock(request.name, request.arguments)
        allow_reasons = (
            Reason(
                code="allowed",
                message=(
                    f"Outbound tool '{request.name}' passed channel-policy attestation "
                    f"and ROPE-lite origin checks. turnId={turn_id} logged for audit only."
                    if outbound
                    else f"Tool '{request.name}' is not outbound; attestation not required."
                ),
            ),
        )
        return self._allow(request, turn_id, allow_reasons, result)

    def _check_attestation(
        self,
        request: ToolCall,
        attestation: ChannelPolicyAttestation | None,
        expected_channel: str | None,
        *,
        now=None,
    ) -> list[Reason]:
        if attestation is None:
            return [
                Reason(
                    code="missing_attestation",
                    message=(
                        f"Outbound tool '{request.name}' requires a channel-policy "
                        "attestation. aiInvocation is a receipt, not a door key."
                    ),
                    field="params._meta.channelPolicyAttestation",
                )
            ]

        findings: list[Reason] = []
        if not attestation.verify_mac(self.policy.attestation_secret):
            findings.append(
                Reason(
                    code="invalid_attestation",
                    message="Channel-policy attestation MAC did not verify.",
                    field="params._meta.channelPolicyAttestation.mac",
                )
            )
        if attestation.issuer not in self.policy.trusted_issuers:
            findings.append(
                Reason(
                    code="untrusted_issuer",
                    message=f"Attestation issuer '{attestation.issuer}' is not trusted by this MCP server.",
                    field="params._meta.channelPolicyAttestation.issuer",
                    detail=attestation.issuer,
                )
            )
        if attestation.tool_name != request.name:
            findings.append(
                Reason(
                    code="channel_mismatch",
                    message=(
                        f"Attestation is bound to tool '{attestation.tool_name}', "
                        f"not '{request.name}'."
                    ),
                    field="params._meta.channelPolicyAttestation.toolName",
                )
            )
        if expected_channel and attestation.channel != expected_channel:
            findings.append(
                Reason(
                    code="channel_mismatch",
                    message=(
                        f"Attestation channel '{attestation.channel}' does not match "
                        f"tool channel '{expected_channel}'."
                    ),
                    field="params._meta.channelPolicyAttestation.channel",
                )
            )
        if not attestation.template_valid or not attestation.opted_in or not attestation.schema_valid:
            findings.append(
                Reason(
                    code="invalid_attestation",
                    message="Attestation policy bits are not all true (template / opt-in / schema).",
                    field="params._meta.channelPolicyAttestation",
                )
            )
        if attestation.sender_reputation < attestation.reputation_threshold:
            findings.append(
                Reason(
                    code="invalid_attestation",
                    message="Sender reputation is below the attested threshold.",
                    field="params._meta.channelPolicyAttestation.senderReputation",
                )
            )
        clock = now or utc_now()
        try:
            expires = parse_utc(attestation.expires_at)
            if clock > expires:
                findings.append(
                    Reason(
                        code="expired_attestation",
                        message=f"Attestation expired at {attestation.expires_at}.",
                        field="params._meta.channelPolicyAttestation.expiresAt",
                    )
                )
        except (TypeError, ValueError):
            findings.append(
                Reason(
                    code="invalid_attestation",
                    message="Attestation expiresAt is not a usable timestamp.",
                    field="params._meta.channelPolicyAttestation.expiresAt",
                )
            )
        return findings

    def _check_origins(self, request: ToolCall, sensitive_args: Iterable[str]) -> list[Reason]:
        tags = request.origin_tags()
        findings: list[Reason] = []
        for name in sensitive_args:
            if name not in request.arguments:
                continue
            origin = tags.get(name)
            if origin is None:
                if self.policy.fail_closed_missing_origin:
                    findings.append(
                        Reason(
                            code="missing_origin",
                            message=(
                                f"Sensitive argument '{name}' has no origin tag. "
                                "ROPE-lite fails closed."
                            ),
                            field=f"params.arguments.{name}",
                        )
                    )
                continue
            if origin not in TRUSTED_ORIGINS:
                findings.append(
                    Reason(
                        code="untrusted_origin",
                        message=(
                            f"Sensitive argument '{name}' origin is '{origin}'. "
                            "Trusted origins are user, named_source, records. "
                            "This is not an HTTP firewall check."
                        ),
                        field=f"params.arguments.{name}",
                        detail=origin,
                    )
                )
        return findings

    def _allow(
        self,
        request: ToolCall,
        turn_id: str | None,
        reasons: tuple[Reason, ...],
        result: dict[str, Any],
    ) -> GateDecision:
        entry = self._record(request, turn_id, True, reasons)
        return GateDecision(
            allowed=True,
            tool_name=request.name,
            turn_id=turn_id,
            reasons=reasons,
            result=result,
            audit=entry,
        )

    def _deny(
        self,
        request: ToolCall,
        turn_id: str | None,
        reasons: list[Reason],
        *,
        classification: str,
    ) -> GateDecision:
        packed = tuple(reasons)
        entry = self._record(request, turn_id, False, packed)
        denial = structured_denial(
            request_id=request.request_id,
            message=f"MCP server denied tools/call '{request.name}'.",
            classification=classification,
            turn_id=turn_id,
            reasons=packed,
        )
        return GateDecision(
            allowed=False,
            tool_name=request.name,
            turn_id=turn_id,
            reasons=packed,
            denial=denial,
            audit=entry,
        )

    def _record(
        self,
        request: ToolCall,
        turn_id: str | None,
        allowed: bool,
        reasons: tuple[Reason, ...],
    ) -> AuditEntry:
        entry = AuditEntry(
            turn_id=turn_id,
            tool_name=request.name,
            allowed=allowed,
            reasons=reasons,
            attestation_present=request.attestation() is not None,
            ai_invocation_logged=request.ai_invocation() is not None,
            used_ai_invocation_for_authz=False,
        )
        self.audit_log.append(entry)
        return entry
