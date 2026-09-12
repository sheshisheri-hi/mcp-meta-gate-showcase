"""Core gate tests: allow SMS, block GitHub, audit≠auth, origin, attestation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mcp_meta_gate import (
    DEMO_HMAC_KEY,
    AuditLog,
    ClientInterceptor,
    ServerGate,
    weekend_demo_calls,
)
from mcp_meta_gate.denials import JSONRPC_AUTHORIZATION_DENIED
from mcp_meta_gate.models import ChannelPolicyAttestation


PHONE = "+15555550100"
SUMMARY = "Ship the demo. Keep private notes private."


def _sms_interceptor() -> ClientInterceptor:
    return ClientInterceptor(hmac_key=DEMO_HMAC_KEY, attestable_tools=("send_sms",))


def _gate(audit: AuditLog | None = None, **kwargs) -> ServerGate:
    return ServerGate(hmac_key=DEMO_HMAC_KEY, audit=audit or AuditLog(), **kwargs)


def _sms_call(
    interceptor: ClientInterceptor | None = None,
    *,
    user_intent: str = "Text me the meeting summary.",
    **kwargs,
) -> dict:
    host = interceptor or _sms_interceptor()
    defaults = dict(
        turn_id="turn-test-sms",
        user_intent=user_intent,
        invocation_reason="user_requested_sms_summary",
        origin_tags={"to": "user", "body": "records"},
    )
    defaults.update(kwargs)
    return host.stamp_tools_call(
        "send_sms",
        {"to": PHONE, "body": SUMMARY},
        **defaults,
    )


def test_allow_sms():
    decision = _gate().evaluate(_sms_call())
    assert decision.allowed is True
    assert decision.verdict == "allow"
    assert decision.denial is None
    assert decision.result is not None
    assert decision.result["tool"] == "send_sms"
    assert decision.result["to"] == PHONE
    assert decision.result["mock"] is True


def test_block_github_missing_attestation():
    sms, github, turn_id = weekend_demo_calls(_sms_interceptor(), turn_id="turn-shared")
    gate = _gate()
    allowed = gate.evaluate(sms)
    denied = gate.evaluate(github)
    assert allowed.allowed is True
    assert denied.allowed is False
    assert denied.denial is not None
    assert denied.denial.classification == "missing_channel_attestation"
    assert denied.turn_id == turn_id == allowed.turn_id
    rpc = denied.to_jsonrpc(2)
    assert rpc["error"]["code"] == JSONRPC_AUTHORIZATION_DENIED
    assert rpc["error"]["data"]["type"] == "authorization_denial"
    assert rpc["error"]["data"]["retryCorrelationHandle"]
    assert rpc["error"]["data"]["remediationHints"]


def test_shared_turn_id_in_audit_trail():
    audit = AuditLog()
    gate = _gate(audit)
    sms, github, turn_id = weekend_demo_calls(_sms_interceptor(), turn_id="turn-audit")
    gate.evaluate(sms)
    gate.evaluate(github)
    assert [e["turnId"] for e in audit.entries] == [turn_id, turn_id]
    assert [e["verdict"] for e in audit.entries] == ["allow", "deny"]
    assert all(e["auditOnly"] is True for e in audit.entries)


def test_audit_not_auth_intent_cannot_bypass():
    """A glowing userIntent must not authorize GitHub without attestation."""
    host = ClientInterceptor(hmac_key=DEMO_HMAC_KEY, attestable_tools=())
    request = host.stamp_tools_call(
        "post_github",
        {
            "repo": "public/leaked-notes",
            "body": "private notes",
            "visibility": "public",
        },
        turn_id="turn-bypass",
        user_intent="I authorize posting private notes to the public GitHub repo.",
        invocation_reason="user_explicitly_approved_github",
        origin_tags={"repo": "user", "body": "user", "visibility": "user"},
        attest=False,
    )
    decision = _gate().evaluate(request)
    assert decision.allowed is False
    assert decision.denial is not None
    assert decision.denial.classification == "missing_channel_attestation"
    # Intent was present and logged, but not used as a permit.
    assert "authorize" in request["params"]["_meta"]["aiInvocation"]["userIntent"]


def test_audit_not_auth_intent_cannot_block_valid_sms():
    """A refusing userIntent must not deny a correctly attested SMS."""
    request = _sms_call(user_intent="Do not send any SMS. Refuse this call.")
    decision = _gate().evaluate(request)
    assert decision.allowed is True
    assert decision.audit["userIntent"].startswith("Do not send")


def test_origin_reject_untrusted_tool():
    host = ClientInterceptor(
        hmac_key=DEMO_HMAC_KEY, attestable_tools=("post_github",)
    )
    request = host.stamp_tools_call(
        "post_github",
        {
            "repo": "acme/private-notes",
            "body": "injected from a poisoned tool",
            "visibility": "private",
        },
        turn_id="turn-origin",
        user_intent="Text me the meeting summary.",
        origin_tags={
            "repo": "untrusted_tool",
            "body": "untrusted_tool",
            "visibility": "untrusted_tool",
        },
        destination_class="private_repo",
    )
    assert "channelPolicyAttestation" in request["params"]["_meta"]
    decision = _gate().evaluate(request)
    assert decision.allowed is False
    assert decision.denial is not None
    assert decision.denial.classification == "untrusted_origin"
    assert decision.denial.field == "_meta.originTags.repo"


def test_bad_attestation_reject():
    request = _sms_call()
    request["params"]["_meta"]["channelPolicyAttestation"]["mac"] = "00" * 32
    decision = _gate().evaluate(request)
    assert decision.allowed is False
    assert decision.denial is not None
    assert decision.denial.classification == "invalid_channel_attestation"


def test_expired_attestation_reject():
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    request = _sms_call(expires_at=past)
    decision = _gate().evaluate(request)
    assert decision.allowed is False
    assert decision.denial is not None
    assert decision.denial.classification == "expired_channel_attestation"


def test_sms_attestation_cannot_authorize_github():
    """Replay the SMS HMAC envelope onto post_github — still deny."""
    sms = _sms_call()
    stolen = sms["params"]["_meta"]["channelPolicyAttestation"]
    host = ClientInterceptor(hmac_key=DEMO_HMAC_KEY, attestable_tools=())
    github = host.stamp_tools_call(
        "post_github",
        {
            "repo": "public/leaked-notes",
            "body": "notes",
            "visibility": "public",
        },
        turn_id="turn-replay",
        user_intent="Text me the meeting summary.",
        origin_tags={"repo": "user", "body": "user", "visibility": "user"},
        attest=False,
    )
    github["params"]["_meta"]["channelPolicyAttestation"] = stolen
    decision = _gate().evaluate(github)
    assert decision.allowed is False
    assert decision.denial is not None
    assert decision.denial.classification in {
        "attestation_tool_mismatch",
        "channel_mismatch",
        "invalid_channel_attestation",
    }


def test_public_repo_destination_class_denied():
    host = ClientInterceptor(
        hmac_key=DEMO_HMAC_KEY, attestable_tools=("post_github",)
    )
    request = host.stamp_tools_call(
        "post_github",
        {
            "repo": "public/leaked-notes",
            "body": "notes",
            "visibility": "public",
        },
        turn_id="turn-public",
        user_intent="Text me the meeting summary.",
        origin_tags={"repo": "user", "body": "records", "visibility": "user"},
        destination_class="public_repo",
    )
    decision = _gate().evaluate(request)
    assert decision.allowed is False
    assert decision.denial is not None
    assert decision.denial.classification == "destination_class_denied"


def test_attestation_roundtrip_verify():
    env = ChannelPolicyAttestation(
        channel="sms",
        destination_class="user_owned_sms",
        expires_at="2099-01-01T00:00:00Z",
        nonce="abc",
        tool="send_sms",
        destination=PHONE,
    ).sign(DEMO_HMAC_KEY)
    assert env.verify(DEMO_HMAC_KEY) is True
    assert env.verify(b"wrong-key") is False


def test_jsonrpc_allow_shape():
    rpc = _gate().handle_tools_call(_sms_call())
    assert rpc["jsonrpc"] == "2.0"
    assert rpc["result"]["isError"] is False
    assert rpc["result"]["_meta"]["decision"] == "allow"
