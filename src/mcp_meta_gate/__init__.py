"""MCP meta-gate: audit telemetry in `_meta` is never authorization.

Educational sample inspired by draft SEP-2817, channel-policy attestation,
ROPE (arXiv:2608.27496), and SEP-2643. Not official compliance.
"""

from .denials import structured_denial
from .gate import ServerGate
from .interceptor import ClientInterceptor
from .models import (
    AiInvocation,
    AuditEntry,
    ChannelPolicyAttestation,
    GateDecision,
    HostPolicy,
    OriginKind,
    Reason,
    ServerPolicy,
    ToolCall,
)

__all__ = [
    "AiInvocation",
    "AuditEntry",
    "ChannelPolicyAttestation",
    "ClientInterceptor",
    "GateDecision",
    "HostPolicy",
    "OriginKind",
    "Reason",
    "ServerGate",
    "ServerPolicy",
    "ToolCall",
    "structured_denial",
]

__version__ = "0.1.0"
