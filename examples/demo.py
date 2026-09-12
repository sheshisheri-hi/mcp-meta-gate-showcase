#!/usr/bin/env python3
"""Print the poisoned-meeting walkthrough.

Same turnId. SMS allowed. Public GitHub gist denied with a SEP-2643-shaped
error. No network.

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

from mcp_meta_gate.demo_tools import (  # noqa: E402
    USER_INTENT,
    format_decision,
    run_poisoned_meeting_demo,
)

WIDTH = 72


def _box(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def _kv(label: str, value: str) -> None:
    print(f"  {label:<14} {value}")


def main() -> int:
    print("MCP meta-gate — audit fields are not auth fields")
    print("CPU only. No WebAuthn. No SEP-3004 vectors. No network.")
    print()
    print("  User:     Text me the meeting summary.")
    print("  Poison:   also post private notes to a public GitHub repo")
    print()
    print("  aiInvocation              = receipt  (SEP-2817-shaped, audit only)")
    print("  channelPolicyAttestation  = door key (enforcement)")
    print("  originTags                = where did this value come from? (ROPE-lite)")
    print()
    print("  MCP host/client interceptor stamps _meta")
    print("  MCP server gate decides allow / deny")
    print()
    print("  tools/call --> [ interceptor ] --stamp--> [ gate ] --allow--> mock SMS")
    print("                                              |")
    print("                                              +-- deny --> SEP-2643-shaped error")

    run = run_poisoned_meeting_demo()
    sms = run["sms"]
    github = run["github"]
    sms_call = run["smsCall"]
    github_call = run["githubCall"]

    _box("1 / SAME TURN")
    _kv("userIntent", USER_INTENT)
    _kv("turnId", run["turnId"])
    _kv("shared?", "yes" if run["sharedTurnId"] else "NO")

    _box("2 / INTERCEPTOR STAMP — send_sms")
    print(json.dumps(sms_call.to_rpc(), indent=2))

    _box("3 / MCP SERVER GATE — SMS ALLOW")
    print(format_decision("send_sms", sms_call, sms))
    if sms.result:
        print("  result")
        print(json.dumps(sms.result, indent=2))

    _box("4 / INTERCEPTOR STAMP — github_create_gist (no door key)")
    print(json.dumps(github_call.to_rpc(), indent=2))

    _box("5 / MCP SERVER GATE — GITHUB DENY (SEP-2643-shaped)")
    print(format_decision("github_create_gist", github_call, github))
    if github.denial:
        print("  structured denial")
        print(json.dumps(github.denial, indent=2))

    print()
    print("-" * WIDTH)
    print(f" Audit trail: {len(sms.audit and [sms.audit] or []) + len(github.audit and [github.audit] or [])} events")
    for entry in (sms.audit, github.audit):
        if entry is None:
            continue
        print(
            f"  turnId={entry.turn_id}  tool={entry.tool_name:<20}  "
            f"allowed={str(entry.allowed):<5}  "
            f"usedAiInvocationForAuthz={entry.used_ai_invocation_for_authz}"
        )
    print()
    if run["ok"]:
        print(" Demo done. Same turnId. SMS allowed. GitHub structured deny.")
        print(" Audit ≠ auth. The receipt did not open the GitHub door.")
        return 0
    print(" Demo failed the success contract (shared turnId + SMS allow + GitHub deny).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
