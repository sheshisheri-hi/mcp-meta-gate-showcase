"""SEP-2643-inspired structured authorization denials.

Educational envelope only. Not a full SEP-2643 port and not official MCP
error-code allocation.
"""

from __future__ import annotations

from typing import Any, Iterable
from uuid import uuid4

from .models import Reason

# Application / server-error neighborhood. Not an official MCP code.
AUTHORIZATION_DENIED_CODE = -32010


def structured_denial(
    *,
    request_id: str | int | None,
    message: str,
    classification: str,
    turn_id: str | None,
    reasons: Iterable[Reason],
    remediation_hints: list[dict[str, Any]] | None = None,
    retry_handle: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC error with a SEP-2643-shaped ``authorizationDenial``."""
    reason_list = [r.to_dict() for r in reasons]
    handle = retry_handle or f"retry-{turn_id or 'unknown'}-{uuid4().hex[:8]}"
    hints = remediation_hints or _default_hints(classification, reasons)
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": AUTHORIZATION_DENIED_CODE,
            "message": message,
            "data": {
                "authorizationDenial": {
                    "classification": classification,
                    "retryHandle": handle,
                    "clientTurnId": turn_id,
                    "reasons": reason_list,
                    "remediationHints": hints,
                }
            },
        },
    }


def _default_hints(classification: str, reasons: Iterable[Reason]) -> list[dict[str, Any]]:
    codes = {r.code for r in reasons}
    hints: list[dict[str, Any]] = []
    if "missing_attestation" in codes or "invalid_attestation" in codes:
        hints.append(
            {
                "type": "attestation_required",
                "detail": "Mint a fresh channel-policy attestation on the MCP host/client interceptor for an approved outbound channel.",
            }
        )
    if "untrusted_origin" in codes or "missing_origin" in codes:
        hints.append(
            {
                "type": "origin_rejected",
                "detail": "Resupply the sensitive argument from a trusted origin (user, named_source, or records). Rewording the prompt does not change this.",
            }
        )
    if "untrusted_issuer" in codes or "expired_attestation" in codes or "channel_mismatch" in codes:
        hints.append(
            {
                "type": "url_approval",
                "detail": "Ask a human to approve this outbound channel, then retry with a new attestation bound to this tool.",
            }
        )
    if not hints:
        hints.append(
            {
                "type": "policy_blocked",
                "detail": f"MCP server policy blocked this tools/call ({classification}).",
            }
        )
    return hints
