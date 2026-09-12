# LinkedIn assets

Quick links for posting:

- **Repo:** https://github.com/sheshisheri-hi/mcp-meta-gate-showcase
- **Flashy HTML:** [`docs/one-pager.html`](one-pager.html)
- **Engineer README:** [`../README.md`](../README.md)

---

# LinkedIn post (copy-paste ready)

Use this as a single post, or split the **Carousel** section into slides.

---

## Post

User: “Text me the meeting summary.”

A poisoned tool in the same turn also tries:
post the private notes to a public GitHub repo.

Same `turnId`. Two `tools/call`s. Two very different `_meta` stories.

I built a tiny MCP gate that treats those as different things.

`_meta.aiInvocation` = audit. Why the model fired. Which user turn. Draft SEP-2817-shaped. The MCP server **logs** it. The MCP server must **never** allow or deny from the sentence.

`_meta.channelPolicyAttestation` = enforcement. An HMAC envelope: channel, destination class, expiry, nonce, bound to the tool and the destination. The MCP host/client stamps it only for channels the user actually asked for.

`_meta.originTags` = ROPE-lite (arXiv:2608.27496). `to` came from the user. `repo` came from an untrusted tool. Sensitive args whose only origin is `untrusted_tool` do not ship.

Result in the demo:
→ SMS allowed (valid attestation + trusted origin)
→ GitHub denied (no attestation)
→ both rows share the same `turnId`
→ deny is a SEP-2643-shaped structured error — classification, retry handle, remediation hints — not “unknown tool”

CPU only. No SMS. No GitHub network. No WebAuthn. No claim of official MCP compliance.

The one-liner I keep repeating: audit is not authorization.

If your MCP server is making allow/deny decisions by reading `userIntent`, a poisoned context will write you a nicer intent.

Repo: https://github.com/sheshisheri-hi/mcp-meta-gate-showcase

#AISecurity #MCP #AgentSecurity #LLMOps

---

## Carousel (6 slides — paste one slide per card)

**Slide 1 — Hook**
“Text me the meeting summary.”

Same turn, a poisoned tool also tries to
push private notes to a public GitHub repo.

**Slide 2 — The mix-up**
MCP `_meta` is becoming a junk drawer.

Audit telemetry and enforcement proofs
are landing on the same request.

If the MCP server treats intent text as a permit,
the attacker writes a better sentence.

**Slide 3 — Two payloads, one rule**
`aiInvocation` = audit (draft SEP-2817).
`channelPolicyAttestation` = enforcement.
`originTags` = ROPE-lite (arXiv:2608.27496).

Log the first. Verify the second. Check the third.
Never invert that.

**Slide 4 — The demo**
SMS: valid HMAC + origin `user` / `records` → ALLOW
GitHub: no attestation, origin `untrusted_tool` → DENY

Same `turnId` in the audit trail.

**Slide 5 — The deny**
Not “unknown tool.”
A SEP-2643-shaped stub:

classification
retry correlation handle
remediation hints

The model can ask for an attestation
instead of inventing a second tool.

**Slide 6 — CTA**
Audit is not authorization.

Stamp proofs on the MCP host/client.
Enforce them on the MCP server.
Ignore the poem in `userIntent`.

github.com/sheshisheri-hi/mcp-meta-gate-showcase

---

## Comment you can pin under the post

Weekend sample. Thin educational stub — not a full SEP-2817 / SEP-2643 / ROPE implementation, not official MCP compliance.

Sibling samples (different clocks): mcp-atsa-admission (connect-time door), mcp-discovery-sanitizer (don’t fold raw `tools/list` into the prompt).

Happy to walk through the deny JSON if useful.
