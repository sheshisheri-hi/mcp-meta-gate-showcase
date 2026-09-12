"""MCP _meta gate: audit telemetry and enforcement proofs on the same request.

This is a thin educational sample. It is not official MCP compliance and it
does not implement full SEP-2817, SEP-2643, or ROPE.
"""

from .denials import AuthorizationDenial, authorization_denial
from .demo_tools import TOOLS, post_github, send_sms, weekend_demo_calls
from .gate import AuditLog, GateDecision, ServerGate
from .interceptor import ClientInterceptor, stamp_tools_call
from .models import (
    DEMO_HMAC_KEY,
    TRUSTED_ORIGINS,
    AiInvocation,
    ChannelPolicyAttestation,
    OriginLabel,
    parse_utc,
)

__version__ = "0.1.0"

__all__ = [
    "DEMO_HMAC_KEY",
    "TOOLS",
    "TRUSTED_ORIGINS",
    "AiInvocation",
    "AuditLog",
    "AuthorizationDenial",
    "ChannelPolicyAttestation",
    "ClientInterceptor",
    "GateDecision",
    "OriginLabel",
    "ServerGate",
    "authorization_denial",
    "parse_utc",
    "post_github",
    "send_sms",
    "stamp_tools_call",
    "weekend_demo_calls",
]
