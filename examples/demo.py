#!/usr/bin/env python3
"""Weekend scenario: SMS allowed, poisoned GitHub denied, shared turnId.

Run from the repo root:

    PYTHONPATH=src python examples/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_meta_gate import AuditLog, ClientInterceptor, ServerGate, weekend_demo_calls

WIDTH = 72


def _box(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def _kv(label: str, value: str) -> None:
    print(f"  {label:<16} {value}")


def _show(title: str, request: dict, gate: ServerGate) -> None:
    params = request["params"]
    meta = params.get("_meta") or {}
    invocation = meta.get("aiInvocation") or {}
    attest = meta.get("channelPolicyAttestation")
    decision = gate.evaluate(request)
    rpc = decision.to_jsonrpc(request.get("id"))

    _box(title)
    _kv("tool", params.get("name", "?"))
    _kv("turnId", str(invocation.get("turnId")))
    _kv("userIntent", str(invocation.get("userIntent")))
    _kv("reason", str(invocation.get("invocationReason")))
    if attest:
        _kv(
            "attestation",
            f"{attest.get('channel')} / {attest.get('destinationClass')} (mac ok)",
        )
    else:
        _kv("attestation", "(none — interceptor refused to stamp)")
    tags = meta.get("originTags") or {}
    _kv("originTags", ", ".join(f"{k}={v}" for k, v in tags.items()) or "(none)")
    _kv("verdict", decision.verdict.upper())
    if decision.allowed:
        result = decision.result or {}
        _kv("mock", json.dumps(result, sort_keys=True))
    else:
        assert decision.denial is not None
        print("  structured denial (SEP-2643-shaped stub)")
        print(json.dumps(rpc["error"]["data"], indent=2))


def main() -> int:
    print("MCP meta-gate showcase — audit on the same _meta as enforcement")
    print("CPU only. No SMS. No GitHub. No WebAuthn. No full SEP port.")
    print()
    print('  User:            "Text me the meeting summary."')
    print("  Poisoned context: post private notes to a public GitHub repo")
    print()
    print("  MCP host/client  [ interceptor ]  stamps aiInvocation (AUDIT)")
    print("                                    + channelPolicyAttestation (ENFORCE)")
    print("                                    + originTags (ROPE-lite)")
    print("           |")
    print("           v")
    print("  MCP server       [ gate ]         log turnId; require attestation")
    print("                                    NEVER allow/deny on userIntent")
    print()
    print("  aiInvocation              = audit telemetry   (SEP-2817-shaped draft)")
    print("  channelPolicyAttestation  = enforcement proof (HMAC envelope)")
    print("  originTags                = ROPE-lite         (arXiv:2608.27496)")
    print("  deny envelope             = SEP-2643-shaped   (thin stub)")

    interceptor = ClientInterceptor(attestable_tools=("send_sms",))
    audit = AuditLog()
    gate = ServerGate(hmac_key=interceptor.hmac_key, audit=audit)
    sms, github, turn_id = weekend_demo_calls(interceptor)

    print()
    print("-" * WIDTH)
    print(f" Shared turnId for this user turn: {turn_id}")
    print("-" * WIDTH)

    _show("1 / ALLOW — send_sms (valid attestation + trusted origin)", sms, gate)
    _show("2 / DENY  — post_github (poisoned; no attestation)", github, gate)

    print()
    print("-" * WIDTH)
    print(f" Audit trail: {len(audit.entries)} events, shared turnId={turn_id}")
    for entry in audit.entries:
        same = "SAME turnId" if entry["turnId"] == turn_id else "MISMATCH"
        print(
            f"  {entry['verdict']:<5}  {entry['tool']:<12}  "
            f"{entry['turnId']}  {same}  class={entry['classification']}"
        )
    ids = {e["turnId"] for e in audit.entries}
    print()
    if ids == {turn_id}:
        print(" Both attempts share the same turnId in the audit trail.")
    else:
        print(" ERROR: turnIds diverged — this sample is broken.")
        return 1
    print(" SMS allowed. GitHub denied with a structured authorization denial.")
    print(" userIntent was logged. userIntent was not consulted for the verdict.")
    print("-" * WIDTH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
