# LinkedIn assets

Quick links for posting:

- **Code:** https://github.com/sheshisheri-hi/mcp-meta-gate-showcase
- **One-pager:** [`docs/one-pager.html`](one-pager.html)

---

# LinkedIn post (copy-paste ready)

Use this as a single post, or split the **Carousel** section into slides.

---

## Post

https://github.com/sheshisheri-hi/mcp-meta-gate-showcase

Your MCP host/client stamps `_meta`.
Your MCP server decides allow / deny.

That split is the whole demo.

Audit fields ≠ auth fields.
SEP-2817 `turnId` ≈ the receipt.
Channel-policy attestation ≈ the door key.

A receipt does not open a door.

HTTP firewall ≠ ROPE.
A firewall asks: is this request allowed?
ROPE asks: where did this value come from?

Same user turn. Same `turnId`.
User: “Text me the meeting summary.”
Poisoned context also tries: post private notes to a public GitHub repo.

SMS → allowed. Valid door key. Trusted origin.
GitHub → blocked. Missing key. Bad origin. SEP-2643-shaped deny.

One receipt. Two doors. Only one key.

Weekend sample. CPU only. Mock SMS. Mock GitHub. No network.
Drafts (SEP-2817, SEP-2643, channel-policy attestation, ROPE) are inspiration. Not official compliance.

https://github.com/sheshisheri-hi/mcp-meta-gate-showcase

#AISecurity #MCP #AgentSecurity #LLMOps

---

## Carousel (6 slides — paste one slide per card)

**Slide 1 — Hook**
Audit fields ≠ auth fields.

`turnId` ≈ the receipt.
Attestation ≈ the door key.

https://github.com/sheshisheri-hi/mcp-meta-gate-showcase

**Slide 2 — Who does what**
MCP host/client interceptor stamps `_meta`.
MCP server gate decides allow / deny.

This is not that.

**Slide 3 — Two questions**
HTTP firewall ≈ “is this request allowed?”
ROPE ≈ “where did this value come from?”

Different doors.

**Slide 4 — Same turn**
User: text me the meeting summary.
Poison: post private notes to public GitHub.

Same `turnId` on both calls.

**Slide 5 — Result**
SMS → allow (key + trusted origin)
GitHub → structured deny (no key / bad origin)

The glowing `userIntent` changed nothing.

**Slide 6 — CTA**
Log the receipt.
Check the key.
Ask where the value came from.

https://github.com/sheshisheri-hi/mcp-meta-gate-showcase

---

## Comment you can pin under the post

Educational sample. SEP-2817 / SEP-2643 / channel-policy attestation / ROPE (arXiv:2608.27496) are drafts and a paper — not a conformance claim.

Code: https://github.com/sheshisheri-hi/mcp-meta-gate-showcase
