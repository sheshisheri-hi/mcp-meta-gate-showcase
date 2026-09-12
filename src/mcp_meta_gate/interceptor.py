"""MCP host/client interceptor: stamp `_meta`. Do not decide allow/deny.

Every ``tools/call`` gets SEP-2817-shaped ``aiInvocation`` (audit only).
Outbound tools the host policy approves also get a channel-policy
attestation (enforcement). Origin tags are optional ROPE-lite labels.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping
from uuid import uuid4

from .models import (
    DEFAULT_ATTESTATION_SECRET,
    AiInvocation,
    ChannelPolicyAttestation,
    HostPolicy,
    ToolCall,
    utc_now,
)

# Host-side view of which tools leave the box. Keep in sync with demo_tools.
_OUTBOUND_CHANNELS = {
    "send_sms": "sms",
    "github_create_gist": "github",
}


class ClientInterceptor:
    """Stamps request ``_meta`` on the MCP host/client side.

    The interceptor is a mutator, not a gate. It never allow/denies a
    tool. The MCP server gate is the only place a call is admitted.
    """

    def __init__(
        self,
        *,
        policy: HostPolicy | None = None,
        secret: str = DEFAULT_ATTESTATION_SECRET,
        model: str | None = "demo-host",
    ) -> None:
        self.policy = policy or HostPolicy()
        self.secret = secret
        self.model = model

    def intercept(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        turn_id: str,
        user_intent: str,
        origin_tags: Mapping[str, str] | None = None,
        request_id: str | int = 1,
        invocation_reason: str = "user_initiated",
        outbound_channel: str | None = None,
        now=None,
    ) -> ToolCall:
        """Return a ``tools/call`` with audit (and maybe enforcement) ``_meta``."""
        invocation = AiInvocation(
            turn_id=turn_id,
            user_intent=user_intent,
            invocation_reason=invocation_reason,
            model=self.model,
        )
        meta: dict[str, Any] = {"aiInvocation": invocation.to_wire()}
        if origin_tags:
            meta["originTags"] = dict(origin_tags)

        channel = outbound_channel or _OUTBOUND_CHANNELS.get(tool_name)
        if channel and self.policy.may_attest(tool_name, channel):
            meta["channelPolicyAttestation"] = self.mint_attestation(
                tool_name, channel, now=now
            ).to_wire()

        return ToolCall(
            name=tool_name,
            arguments=dict(arguments),
            meta=meta,
            request_id=request_id,
        )

    def mint_attestation(
        self,
        tool_name: str,
        channel: str,
        *,
        now=None,
        nonce: str | None = None,
    ) -> ChannelPolicyAttestation:
        clock = now or utc_now()
        issued = clock if clock.tzinfo else clock
        expires = issued + timedelta(seconds=self.policy.attestation_ttl_seconds)
        unsigned = ChannelPolicyAttestation(
            channel=channel,
            tool_name=tool_name,
            issuer=self.policy.issuer,
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
            nonce=nonce or uuid4().hex,
        )
        return unsigned.signed(self.secret)
