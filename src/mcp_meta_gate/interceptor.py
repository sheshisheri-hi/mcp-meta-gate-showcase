"""MCP host/client interceptor: stamp audit + enforcement onto ``tools/call``.

Every call gets ``_meta.aiInvocation`` (SEP-2817-shaped, audit only).
Outbound tools the user actually authorized also get a signed
``_meta.channelPolicyAttestation``. Optional ROPE-lite origin tags travel
alongside. The interceptor never asks the MCP server to trust intent text.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping
from uuid import uuid4

from .models import (
    OUTBOUND_TOOLS,
    TOOL_POLICY,
    AiInvocation,
    ChannelPolicyAttestation,
    hmac_key_from_env,
)


class ClientInterceptor:
    """Stamps ``_meta`` on the MCP host/client before ``tools/call`` leaves."""

    def __init__(
        self,
        *,
        hmac_key: bytes | None = None,
        attestable_tools: Iterable[str] | None = None,
        ttl_seconds: int = 300,
        model: str | None = "demo-host/meta-gate",
    ) -> None:
        self.hmac_key = hmac_key if hmac_key is not None else hmac_key_from_env()
        # Default: only SMS is a user-authorized outbound channel this turn.
        self.attestable_tools = frozenset(
            attestable_tools if attestable_tools is not None else ("send_sms",)
        )
        self.ttl_seconds = ttl_seconds
        self.model = model

    def will_attest(self, tool_name: str) -> bool:
        return tool_name in OUTBOUND_TOOLS and tool_name in self.attestable_tools

    def stamp_tools_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        turn_id: str,
        user_intent: str,
        invocation_reason: str | None = None,
        model: str | None = None,
        origin: str | Mapping[str, Any] | None = None,
        origin_tags: Mapping[str, str] | None = None,
        attest: bool | None = None,
        channel: str | None = None,
        destination_class: str | None = None,
        destination: str | None = None,
        expires_at: datetime | str | None = None,
        nonce: str | None = None,
        request_id: Any = 1,
    ) -> dict[str, Any]:
        """Return a JSON-RPC ``tools/call`` with stamped ``_meta``."""
        args = dict(arguments or {})
        reason = invocation_reason or _default_reason(tool_name)
        invocation = AiInvocation(
            turn_id=turn_id,
            user_intent=user_intent,
            invocation_reason=reason,
            model=model if model is not None else self.model,
        )
        meta: dict[str, Any] = {"aiInvocation": invocation.to_meta()}
        if origin is not None:
            meta["origin"] = origin
        if origin_tags is not None:
            meta["originTags"] = dict(origin_tags)

        should_attest = self.will_attest(tool_name) if attest is None else attest
        if should_attest:
            if tool_name not in TOOL_POLICY:
                raise ValueError(f"no channel policy for tool {tool_name!r}")
            default_channel, allowed_classes, _sensitive, dest_field = TOOL_POLICY[tool_name]
            dest = destination if destination is not None else str(args.get(dest_field, ""))
            dest_class = destination_class or _infer_destination_class(tool_name, args)
            if dest_class not in allowed_classes and destination_class is None:
                # Still stamp what the MCP host/client computed; the MCP server
                # gate decides. Tests may pass an explicit class.
                dest_class = dest_class or next(iter(allowed_classes))
            expiry = _expiry_iso(expires_at, self.ttl_seconds)
            envelope = ChannelPolicyAttestation(
                channel=channel or default_channel,
                destination_class=dest_class,
                expires_at=expiry,
                nonce=nonce or secrets.token_hex(16),
                tool=tool_name,
                destination=dest,
            ).sign(self.hmac_key)
            meta["channelPolicyAttestation"] = envelope.to_meta()

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args,
                "_meta": meta,
            },
        }


def stamp_tools_call(
    tool_name: str,
    arguments: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Module-level helper using a default MCP host/client interceptor."""
    return ClientInterceptor().stamp_tools_call(tool_name, arguments, **kwargs)


def new_turn_id() -> str:
    return f"turn-{uuid4().hex[:16]}"


def _default_reason(tool_name: str) -> str:
    if tool_name == "send_sms":
        return "user_requested_sms_summary"
    if tool_name == "post_github":
        return "context_suggested_github_post"
    return f"invoke_{tool_name}"


def _infer_destination_class(tool_name: str, arguments: Mapping[str, Any]) -> str:
    if tool_name == "send_sms":
        return "user_owned_sms"
    visibility = str(arguments.get("visibility") or "public").lower()
    if visibility == "private":
        return "private_repo"
    return "public_repo"


def _expiry_iso(expires_at: datetime | str | None, ttl_seconds: int) -> str:
    if isinstance(expires_at, str):
        return expires_at
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
