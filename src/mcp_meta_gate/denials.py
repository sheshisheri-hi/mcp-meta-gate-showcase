"""SEP-2643-inspired structured authorization denials.

Thin stub: classification, retry correlation handle, remediation hints.
Not a full SEP-2643 envelope and not a claim of official MCP compliance.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any


# JSON-RPC implementation-defined server error. 2643 is a wink, not a code point.
JSONRPC_AUTHORIZATION_DENIED = -32043


@dataclass(frozen=True)
class AuthorizationDenial:
    """Structured denial the MCP host/client can act on instead of a bare error."""

    classification: str
    message: str
    retry_correlation_handle: str
    remediation_hints: tuple[dict[str, Any], ...] = ()
    turn_id: str | None = None
    field: str | None = None

    def data(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "authorization_denial",
            "classification": self.classification,
            "retryCorrelationHandle": self.retry_correlation_handle,
            "remediationHints": list(self.remediation_hints),
        }
        if self.turn_id:
            payload["turnId"] = self.turn_id
        if self.field:
            payload["field"] = self.field
        return payload

    def to_jsonrpc(self, request_id: Any = None) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": JSONRPC_AUTHORIZATION_DENIED,
            "message": self.message,
            "data": self.data(),
        }
        envelope: dict[str, Any] = {"jsonrpc": "2.0", "error": error}
        if request_id is not None:
            envelope["id"] = request_id
        return envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "message": self.message,
            "retryCorrelationHandle": self.retry_correlation_handle,
            "remediationHints": list(self.remediation_hints),
            "turnId": self.turn_id,
            "field": self.field,
        }


def authorization_denial(
    classification: str,
    message: str,
    *,
    turn_id: str | None = None,
    field: str | None = None,
    hints: list[dict[str, Any]] | None = None,
    retry_correlation_handle: str | None = None,
) -> AuthorizationDenial:
    handle = retry_correlation_handle or f"corr-{secrets.token_hex(8)}"
    return AuthorizationDenial(
        classification=classification,
        message=message,
        retry_correlation_handle=handle,
        remediation_hints=tuple(hints or ()),
        turn_id=turn_id,
        field=field,
    )


# Shared hint builders so the MCP server gate stays consistent.

def hint_obtain_attestation(channel: str, tool: str) -> dict[str, Any]:
    return {
        "type": "obtain_channel_attestation",
        "channel": channel,
        "tool": tool,
        "detail": (
            "The MCP host/client must stamp a valid _meta.channelPolicyAttestation "
            f"for outbound tool '{tool}' on channel '{channel}'."
        ),
    }


def hint_relabel_origin(field_name: str) -> dict[str, Any]:
    return {
        "type": "relabel_origin",
        "field": field_name,
        "detail": (
            "ROPE-lite: a sensitive argument whose only origin is untrusted_tool "
            "cannot reach a state-changing tool. Re-source the value from the user, "
            "a named_source, or records."
        ),
    }


def hint_destination_class(allowed: frozenset[str] | tuple[str, ...]) -> dict[str, Any]:
    return {
        "type": "use_allowed_destination_class",
        "allowed": sorted(allowed),
        "detail": "Destination class is not on the MCP server allow-list for this tool.",
    }
