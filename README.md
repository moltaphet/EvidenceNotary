# EvidenceNotary -- Consensus Web Attestation Protocol

A pure-protocol (no frontend) web notarization and proof-of-existence contract for
[GenLayer](https://www.genlayer.com). Anyone -- an EOA or another contract -- pays an exact
fee and asks the validator set to read an `https` URL. Every validator fetches the response
independently, hashes it two ways (raw bytes and normalized visible text), and the attestation is
recorded **only if the validators agree**. The result is an immutable on-chain record
`(canonical_url, raw_sha256, normalized_sha256, content_kind, size_bytes, title, snippet, timestamp,
attester)` that other contracts can verify by id with one view call.

There is no LLM in the consensus path: agreement is a deterministic comparison of hashes, so a
prompt cannot sway it.

* Contract: [`contracts/evidence_notary.py`](contracts/evidence_notary.py)
* Tests: [`tests/test_evidence_notary.py`](tests/test_evidence_notary.py) (188 tests, direct mode)
* Scripts: [`scripts/deploy.py`](scripts/deploy.py), [`scripts/interact_live.py`](scripts/interact_live.py)
* Live record: [`deployments/studio-next.json`](deployments/studio-next.json)

> **Revision 2 (security hardening).** Dual hashing; HTML extraction no longer strips by class / id
> or keeps only `<main>`; binary media is never text-decoded; hard payload cap with an explicit
> revert; a 20% non-refundable fee on failed fetches; `get_latest_attestation` demoted to
> informational and the integration pattern rebuilt on pinned ids. See section 7.

## 1. Verified on-chain deployment (Studio Next, chain 61997)

| | |
|---|---|
| Contract | `0xF19334F29551A9df11C2e596c5517c35d232db0e` |
| Explorer | https://explorer-studio-next.genlayer.com/address/0xF19334F29551A9df11C2e596c5517c35d232db0e |
| Deploy tx | `0xf4d3c496eca53665a53cfceec43dbb734aec512f3650802a3e6c5cafd569acab` -- FINISHED_WITH_RETURN, consensus **MAJORITY_AGREE** |
| Runner | `py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng` |
| Source SHA-256 | `3485e80360272538e1322e75554f6b14f5ff1c969fb49e02ee7d0768ea3e17c1` |
| Governor | `0x79D0B199047e568B39D8c422B66c693A7F9414b1` |
| Fee | 0.05 GEN (`50000000000000000` atto); failed fetch: 0.01 GEN kept, 0.04 GEN refundable |

Live proofs, produced by `scripts/interact_live.py` (every row is a real transaction; the full
per-validator votes and state hashes are in `deployments/studio-next.json`):

| Case | URL | Transaction | Validator consensus | Outcome / hashes | Contract state hash (leader == agreeing validators) |
|---|---|---|---|---|---|
| RFC 9000 -- QUIC transport specification | `https://rfc-editor.org/rfc/rfc9000` | `0x69a45acb80c8f8f81de827e493005acb10d6aacc780883056515a4e944911b07` | MAJORITY_AGREE (3 agree / 2 idle) | ATTESTED #1 (html, 2,989,622 B)<br>raw `77e1e7dfc23a88f959f2189af224630a18fc1f5a08ce2f8480bca420af3d75e3`<br>normalized `9307a8e848afd9d2cb79b10bee068f2ed76b7ece40ee9f42f518554b2cf7b637` | `ac20e947869ef31d89374c339781adfabdc6975fdb3172a317f7b79917f8a89c` |
| Python 3.13 release notes | `https://docs.python.org/3/whatsnew/3.13.html` | `0xae81df4a637ec14ef86fdc8f289f018e035ff39df7206ec44d599dc9ca53f1ac` | MAJORITY_AGREE (3 agree / 2 idle) | ATTESTED #2 (html, 492,386 B)<br>raw `7206ee86ff777e1a0fe4b318fc32f4608972d86068cfe3e8f3458cb2807735c5`<br>normalized `b19690d381e9c84a7e926f0f5f5b9559b0690627c90f970032ea9da949494143` | `2e3791d7e7541d9a1589e1f186c9fd26b58a19f72dbf99d8aa5f40583b2631b2` |
| W3C Decentralized Identifiers (DID Core) | `https://w3.org/TR/did-core/` | `0x9a4c91693e3da54145b237ca70f71a055af0cb8b0465e640c5c84b27af6808b0` | MAJORITY_AGREE (3 agree / 2 idle) | ATTESTED #3 (html, 730,300 B)<br>raw `5e44345740d9bfaa852d3b66c57e98c9beb6c5bf6083b0126dd5daac377b9993`<br>normalized `62c9cc43f1027cda3af834bc033ef672c2c59737ca15bc9627f7fb2c6e303a7e` | `48f142c19baa623c74ab1a83cc97c909931ab4ed03e474c7cbff050ab8541a9a` |
| Dead link -- HTTP 404 on docs.python.org (80% refund, 20% retained) | `https://docs.python.org/3/evidencenotary-nonexistent-page-404.html` | `0x8359f2a9df0fbd5d7b595dac7b516e093823490ef576716a0395edc5a300357e` | MAJORITY_AGREE (3 agree / 2 idle) | AMBIGUOUS_VOID: 0.04 GEN -> `claimable_credits`, 0.01 GEN -> `protocol_vault` | `b449573bb7051ffc81fa70350e12041859be19d561f824909ba3072895e1f39a` |

Follow-up transactions:

| Step | Transaction | Consensus | Effect |
|---|---|---|---|
| `pull_withdraw` (refund from case 4) | `0x636489811d6ab0ee5ad798802b2e868c7faf9f4436323c5885156fd4e7df3000` | MAJORITY_AGREE | `claimable_credits` 0.04 -> 0 GEN; caller received the payout |
| `sweep_vault` (governor) | `0xa0fbcead42fabb97d8019344bc85d1b3d9b49b76300d1578e0b679dfb0c881e7` | MAJORITY_AGREE | vault 0.16 -> 0 GEN (3 fees + the 0.01 GEN penalty) |

Every consensus round reached `MAJORITY_AGREE` with 3 agreeing validators (the other two voted `idle`).
The recorded `size_bytes` equals the byte length a plain `curl` receives for each page (RFC 9000 is
2,989,622 bytes, which is why the payload cap is 4 MiB, section 2.3). The 404 case did not revert: the call
finished, returned `AMBIGUOUS_VOID`, recorded nothing, kept 0.01 GEN and credited 0.04 GEN back to the payer
(section 3).

Reproduce: `python scripts/deploy.py && python scripts/interact_live.py` (a throwaway key is
generated into the gitignored `.env` and funded from the Studio faucet; `deploy.py` refuses to record a
deployment that did not finish with `FINISHED_WITH_RETURN`).

## 2. Protocol

### 2.1 API

| Method | Kind | Behaviour |
|---|---|---|
| `attest(url) -> dict` | payable | Requires **exactly** 0.05 GEN. Canonicalizes `url`, reads it across validators, records an attestation on consensus. Returns `{status, attestation_id, canonical_url, raw_sha256, normalized_sha256, ...}`. |
| `verify_attestation(id, expected_hash) -> bool` | view | **The integration primitive.** `True` iff attestation `id` exists and `expected_hash` equals its `normalized_sha256` or its `raw_sha256` (hex SHA-256; letter case and a `0x` prefix are not significant). |
| `get_attestation(id) -> dict` | view | Immutable record by id (use it to bind `canonical_url` / `timestamp`). |
| `get_latest_attestation(url) -> dict` | view | **Informational only -- never gate value on it** (section 2.5). Latest attestation for the canonical form of `url`; reverts `ERR_NOT_FOUND` if none. |
| `canonicalize(url) -> str` | view | The canonicalizer, exposed for clients. |
| `pull_withdraw() -> str` | write | Pays the caller their `claimable_credits` (pull pattern, checks-effects-interactions). |
| `sweep_vault() -> str` | write | Governor only: pays the whole `protocol_vault` to the governor. |
| `transfer_governor(addr)` | write | Governor only; zero address rejected. |
| `get_protocol_state`, `get_limits`, `is_solvent`, `is_ledger_conserved`, `claimable_of`, `get_fee`, `get_governor` | views | Accounting and configuration. |

Attestation record: `attestation_id`, `canonical_url`, `raw_sha256` (hex SHA-256 of the exact response
bytes), `normalized_sha256` (hex SHA-256 of the normalized text; **equal to `raw_sha256` for binary media**),
`content_kind` (`html` | `text` | `binary`), `size_bytes`, `title`, `text_snippet` (first 200 characters of the
verified text; empty for binary), `timestamp` (block time, unix seconds), `attester` (`msg.sender`, lowercase
hex), `fee_paid`. There is no `is_truncated` flag because nothing is ever truncated: an oversize body reverts.

State: `attestations`, `url_to_latest_id`, `protocol_vault`, `claimable_credits`, plus the counters
`total_credits`, `total_received`, `total_paid_out`, `attestation_count` and `governor`.

### 2.2 URL canonicalization (`canonicalize_url`)

Pure and deterministic. An input is accepted only if every rule passes; otherwise `attest` reverts
with `ERR_INVALID_URL` **before any state change** (the attached value returns to the sender).

1. `https` only (scheme is case-insensitive); `http`, `ftp`, `file`, `javascript`, scheme-relative and scheme-less inputs are rejected.
2. No userinfo: any `@` in the authority is rejected (`user:pass@host`, `example.com@evil.com`).
3. Host is lowercased, one trailing dot removed, a leading `www.` stripped; only `[a-z0-9.-]` labels (punycode for IDNs; raw Unicode, `_`, `%`-escapes rejected).
4. Local names rejected: `localhost`, single-label hosts, `.local .localhost .internal .intranet .lan .home .corp .private .localdomain .arpa`.
5. IP literals: IPv6 rejected outright. Any numeric terminal label is treated as an IP attempt and must be strict dotted-decimal (no octal `0177.0.0.1`, hex `0x7f000001`, integer `2130706433`, or short `127.1` forms); then `0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.168/16, 198.18/15` and `>= 224/4` are rejected. Public dotted-quads (e.g. `8.8.8.8`) are allowed.
6. Port: only absent or `443` (dropped).
7. Fragment dropped; dot-segments and duplicate / trailing slashes folded; `%2e %2f %5c` in the path rejected; query pairs sorted so reordered queries deduplicate.
8. Whitespace, control characters, backslashes and URLs over 2048 characters are rejected.

So `https://WWW.Example.com:443/a//b/../doc/#x` and `https://example.com/a/doc` are one document.

### 2.3 Fetch, classification, extraction and hashing

Run identically by every validator inside `gl.vm.run_nondet`:

1. `GET` the canonical URL. Transport error or `429`/`5xx` -> `UNREACHABLE`; any other non-2xx (4xx, 1xx, 3xx) -> `AMBIGUOUS_VOID`; empty body -> `AMBIGUOUS_VOID`.
2. **Payload bound.** The body is measured in bytes. Over `MAX_PAYLOAD_BYTES = 4 MiB` the validators agree on `PAYLOAD_TOO_LARGE` and `attest` **reverts** with `ERR_PAYLOAD_TOO_LARGE` (the whole value returns to the sender). There is no truncation anywhere: a hash always covers the whole body. The cap is 4 MiB rather than 2 MiB because the RFC 9000 page this protocol must notarize is ~3.0 MB.
3. `raw_sha256 = SHA-256(response bytes)`, computed before any decoding.
4. **Classify** by `Content-Type` (parameters and case ignored): `text/html`, `application/xhtml+xml` -> `html`; `text/*`, JSON and XML types -> `text`; **every other declared type (PDF, images, video, archives, `application/octet-stream`, `image/svg+xml`, fonts ...) -> `binary`**. A declared text type whose bytes are not valid UTF-8 is `binary`. With no `Content-Type`, valid UTF-8 is `html`/`text` by sniffing and anything else is `binary`.
5. **Binary: no decoding of any kind.** `normalized_sha256 = raw_sha256`. Two different byte strings that a lossy UTF-8 decode would map to the same text therefore get different hashes (tested with colliding PDF-like fixtures). No minimum length applies.
6. **HTML / text.** HTML is parsed with the standard-library `HTMLParser`. **Only** the subtrees of `script`, `style`, `noscript`, `svg`, `canvas` and the document `<head>` (whose `<title>` is captured separately) are dropped -- they are not rendered body text. **Everything else is kept, in document order**: navigation, headers, footers, asides, forms, banners, promo / sale blocks, and any text outside `<main>` or `<article>`. Block-level tags insert a separator so words never fuse. There is no class / id / role heuristic of any kind.
7. **Normalize**: Unicode NFKC; curly quotes -> `'`/`"`; en/em dash and minus -> `-`; zero-width, format, private-use and control characters removed; every whitespace run folded to one space; trim.
8. Fewer than 40 characters left -> `AMBIGUOUS_VOID` (no notarizable document).
9. `normalized_sha256 = SHA-256(utf-8(normalized text))`. Title (normalized, <= 300 chars) and the first 200 characters are recorded.

Why drop-lists and "main-only" extraction were removed: they let a page hide anything the heuristic
disliked. A clause in `<div class="sale-promo">`, a warranty disclaimer in a `<footer>`, a price outside
`<main>` -- all were silently left out of the hash, so two materially different documents could notarize
identically. Now every rendered word of the response is covered.

### 2.4 Consensus

`leader_fn` and every validator run the same `_read_page`. A validator **agrees** iff

* both reads failed with the same failure class (`UNREACHABLE` / `AMBIGUOUS_VOID` / `PAYLOAD_TOO_LARGE`), or
* both succeeded with the same `content_kind`, the same `normalized_sha256` and the same `title`, **and**, for
  binary media, the same `raw_sha256`.

Everything else -- a different hash, a page that vanished, a leader claiming success for a dead page, a
malformed leader result, a leader crash -- is **disagree**. The comparison is exact on purpose.

What validators do and do not vouch for: for HTML / text the **normalized** text is validated by every
validator; `raw_sha256` is the leader's measurement of the bytes it received. Live markup carries per-request
tokens, nonces and ad slots, so demanding byte-identical markup from independent fetches would make ordinary
pages unattestable. Binary media has no such noise, so there the raw hash *is* validated by all. Trade-off: a
page whose visible text changes between two validators' fetches fails that round and the transaction retries.

### 2.5 Cross-contract integration -- pin the id, never trust `latest`

**Do not release funds or check conditions with `get_latest_attestation(url)`.** `latest` is an
append-only index: *anyone* can advance it by paying 0.05 GEN and attesting the same URL after the page changed
(or while it is briefly different). A counterparty can front-run your release call with a fresh attestation
and flip the result. It is useful for UIs and monitoring, not for authorization.

Immutable records are safe. When the parties agree on a document they **pin** an `attestation_id` and its hash
in the escrow, once, at creation. Release verifies that pinned pair:

```python
import genlayer as gl
from genlayer import Address, u256

NOTARY = Address("{d['contract_address']}")

class Escrow(gl.contract.Contract):
    pinned_url: str
    pinned_id: u256
    pinned_hash: str          # normalized_sha256 (or raw_sha256 for binary) both parties agreed to
    not_before: u256          # attestation must be at least this recent
    ...

    def __init__(self, url: str, attestation_id: int, expected_hash: str, not_before: int):
        notary = gl.get_contract_at(NOTARY)
        # Validate the pin once, up front, so a bad pin cannot be funded.
        if not notary.view().verify_attestation(attestation_id, expected_hash):
            raise gl.vm.UserError("[EXPECTED] pin does not match the notary record")
        self.pinned_url, self.pinned_id, self.pinned_hash, self.not_before = url, attestation_id, expected_hash, not_before

    @gl.public.write
    def release(self) -> None:
        notary = gl.get_contract_at(NOTARY)
        # 1. immutable (id, hash) pair -- cannot be moved by later attestations
        if not notary.view().verify_attestation(self.pinned_id, self.pinned_hash):
            raise gl.vm.UserError("[EXPECTED] pinned attestation no longer verifies")
        # 2. bind the record to the URL and the time window (also immutable, by id)
        rec = notary.view().get_attestation(self.pinned_id)
        if rec["canonical_url"] != self.pinned_url or rec["timestamp"] < self.not_before:
            raise gl.vm.UserError("[EXPECTED] attestation is for another URL or too old")
        ...  # pay out
```

Rules of thumb: (1) key every decision on `(attestation_id, hash)`, not on a URL; (2) check
`canonical_url` and `timestamp` from `get_attestation(id)`, which is immutable; (3) compare against
`normalized_sha256` for HTML / text and `raw_sha256` for files (`verify_attestation` accepts either);
(4) `attester` is whoever called `attest` -- it is **not** an endorsement. Off-chain, anyone can reproduce a
hash with the algorithm in 2.3 and compare via `verify_attestation`. This sketch uses the standard
`gl.get_contract_at(...).view()` pattern; the live scripts exercise the views through the SDK rather than
through a calling contract.

## 3. Failure path: no revert, a 20% penalty, an 80% refund

A reverted transaction rolls back **all** state, including any credit written in it, so a reverting `attest`
cannot also record a refund. The contract therefore splits errors in three:

* **Caller errors revert** (`ERR_INVALID_URL`, `ERR_WRONG_FEE`): nothing is recorded and the attached value is
  returned to the sender by the VM. No validator work has happened yet.
* **Oversize bodies revert** (`ERR_PAYLOAD_TOO_LARGE`) per the explicit-bound requirement, returning the whole
  value. This is the one failed read that is not penalized (see section 8.4).
* **Dead / failing pages finish normally** with status `UNREACHABLE` (DNS or transport failure, timeout, 429, 5xx) or
  `AMBIGUOUS_VOID` (4xx and other non-2xx, empty or non-document body). No attestation is created. Validators
  reach consensus on the *failure* too, and the fee is split **20 / 80**: `0.01 GEN` (`FAILED_FEE_RETAINED`)
  stays in `protocol_vault` as a non-refundable validator-bandwidth fee and `0.04 GEN` (`FAILED_FEE_REFUNDED`)
  is credited to `claimable_credits[msg.sender]`, collected with `pull_withdraw()`.

Without the penalty a caller could make validators fetch arbitrary URLs for free forever (refund-in-full
scraping). With it, N failed attestations cost the caller `N x 0.01 GEN`, irrecoverably.

## 4. Solvency and accounting

### 4.1 Definitions

Let, at any finalized state: `B = self.balance` (native GEN held), `V = protocol_vault`,
`C = total_credits`, `R = total_received`, `P = total_paid_out`, `f = 0.05 GEN`, `p = f / 5 = 0.01 GEN`
(the retained penalty), and `C = sum(claimable_credits.values())` (a running counter, never a scan).

* **Strict solvency (S):** `B = V + C`
* **Ledger conservation (L):** `R = V + C + P`

### 4.2 Proof

Every state-changing path, with its effect on `(B, V, C, R, P)`:

| Transition | B | V | C | R | P |
|---|---|---|---|---|---|
| `attest`, consensus success | `+f` | `+f` | 0 | `+f` | 0 |
| `attest`, failed fetch (20/80 split) | `+f` | `+p` | `+(f-p)` | `+f` | 0 |
| `attest`, bad URL / wrong fee / oversize (revert) | 0 | 0 | 0 | 0 | 0 |
| `pull_withdraw` of `a` | `-a` | 0 | `-a` | 0 | `+a` |
| `sweep_vault` of `a = V` | `-a` | `-a` | 0 | 0 | `+a` |

*Base case.* A deployed contract has `B = V = C = R = P = 0`, so S and L hold.

*Induction.* Assume S and L before a transition. Each row changes `B - V - C` by `0`
(`f-f-0`, `f-p-(f-p)`, `0`, `-a-0+a`, `-a+a-0`) and `R - V - C - P` by `0` (`f-f`, `f-p-(f-p)`, `0`, `0-(-a)-a`,
`0-(-a)-a`). Hence S and L are preserved. A revert changes nothing; in addition `attest` mutates storage only
*after* its last possible revert, so even a host that did not roll state back would see no partial update. The
fee is checked against `gl.message.value` **first**, so exactly `f` enters `B` per non-reverting call, and the
80/20 split is computed as `p = f // 5` and `f - p`, which sum to `f` exactly (integer arithmetic, no rounding
loss). `claimable_credits` is only written through `_credit` (which adds the same amount to `C`) and
`pull_withdraw` (which subtracts the same amount from `C` before the transfer, and restores all three counters
if enqueueing the transfer fails). Therefore `C = sum(claimable_credits)` always, no account can withdraw
more than it was credited, and the vault and the credits are disjoint pools: `sweep_vault` can never touch a
refundable credit. `P` is incremented before `emit_transfer`, so reentrancy cannot double-spend. QED.

Per-account safety: `claimable_credits[a]` only grows by `f - p = 0.04 GEN` per failed attestation by `a`, and
`pull_withdraw` pays `claimable_credits[a]` once and zeroes it first (a second call reverts
`ERR_NOTHING_TO_WITHDRAW`).

### 4.3 Measured on Studio Next: transfer settlement and the balance drift

`pull_withdraw` and `sweep_vault` pay with `emit_transfer(amount, on="finalized")`: the transfer is
applied when the transaction finalizes, not when it is accepted. Measured on Studio Next after the
transactions in section 1 had finalized:

* the recipient **was** paid, but
* the contract's native balance **was not debited**: after the sweep, `balance = {g(fs['balance'])} GEN` while
  `V = C = 0`.

So on Studio Next, strict solvency (S) holds exactly until the first payout and thereafter reads
`B - (V + C) = P` (recorded in the JSON as `balance_drift`; final state of this deployment: `balance
{g(fs['balance'])}, vault {g(fs['protocol_vault'])}, credits {g(fs['total_credits'])}, total_received
{g(fs['total_received'])}, total_paid_out {g(fs['total_paid_out'])}`). The chain-independent ledger identity (L) is exact
throughout, which is why it exists: it is made only of counters this contract writes, so it verifies that no
fee was created, lost, or double-paid even where the host's native-balance accounting differs.
`scripts/interact_live.py` asserts (L) after every transaction and asserts `B - (V + C) in {{0, P}}`. On a chain
that debits payouts at settlement, `P` is exactly what has left `B`, and (S) and (L) coincide. This is a property
of the Studio Next simulator observed in this deployment; the contract cannot influence it, and the
direct-mode test `test_ledger_holds_even_if_chain_never_debits_payouts` pins the behaviour.

## 5. Tests

```
python3.12 -m venv .venv && . .venv/bin/activate
pip install --pre genlayer-test==0.30.0rc2 genlayer-py==0.19.0rc2 genvm-linter==0.11.1rc2 pytest
pytest -q                                     # 188 tests, ~3 min, no network
genvm-lint check contracts/evidence_notary.py # 0 errors
```

188 test cases (far more than 160 assertions: the canonicalizer tests alone loop over 28 accepted and
97 rejected inputs). Coverage: canonicalization and SSRF-style bypasses; deterministic extraction; deduplication;
17 HTTP failure statuses and 6 non-document bodies; exact-fee enforcement; validator agreement / disagreement via
`run_validator`; governance; and the accounting invariants (S) and (L) after every step of mixed attest /
failure / withdraw / sweep sequences, including twelve seeded randomized runs. Regression tests for the
hardening round:

* 24 elements that used to be stripped (`sale-promo`, `promo`, `banner`, `social`, `nav`, `footer`, `aside`,
  cookie / ad / sidebar classes, `hidden`, `role=navigation`, ...) now each change `normalized_sha256` to exactly
  the hash of text that includes them; only the 5 non-renderable tags leave it unchanged; text outside `<main>` /
  `<article>` is covered.
* Binary fixtures that collide under UTF-8 `replace` get distinct `raw_sha256 == normalized_sha256` for 7 media
  types and with no `Content-Type`; HTML raw hash tracks every byte while the normalized hash ignores a comment.
* A body of exactly 4 MiB is accepted; 4 MiB + 1 and +1000 revert `ERR_PAYLOAD_TOO_LARGE` with no state change.
* A failed fetch (403, 404, 429, 500, 503, unmocked host) moves exactly 0.01 GEN to the vault and 0.04 GEN to
  credits; payer recovers 0.04, governor sweeps 0.01; seven-fold scraping costs 0.07 GEN.
* A pinned `(id, hash)` still verifies after a stranger advances `latest`, while the latest hash changes.
* `total_received == vault + credits + total_paid_out` after every step under the 80/20 split.

The direct harness does not move native value (and does not roll state back on a revert), so
`tests/conftest.py::Chain` mirrors GenVM's rules (a call that returns credits `value`; a revert credits nothing;
a payout debits) and checks the contract's counters against that independent balance model.
`test_genvm_lint_reports_zero_errors` runs the linter inside the suite.

## 6. Known limits

* Exact-hash consensus: pages whose visible text changes between validators' fetches (live feeds, countdowns,
  rotating text ads, per-request tokens rendered into the page) will not reach agreement. Retaining all body
  text makes this stricter than before; that is the price of not letting a heuristic decide what is "content".
  Attest stable documents, or attest the specific static asset (e.g. the PDF) instead of its HTML wrapper.
* Titles are part of agreement. The Python docs title embeds the site's current version
  (`... - Python 3.14.8 documentation`), so a site-wide version bump between two validators' fetches fails that round.
* A page whose text is injected by JavaScript is attested as the server-rendered HTML a plain `GET` returns.
* A throwaway key is used for the deployment, so the governor is that key (rotate with `transfer_governor`).

## 7. Audit remediation log (revision 2)

| # | Finding | Fix | Evidence |
|---|---|---|---|
| 1 | Omission via class / id heuristics (a `sale-promo` clause or price could be silently excluded) | Regex heuristic and landmark filtering removed; only `script style noscript svg canvas` (+ `<head>`) are dropped | `test_class_id_and_landmark_elements_are_never_stripped`, `test_sale_promo_element_and_text_outside_main_change_the_hash` |
| 2 | Text outside `<main>` ignored | All body text retained in document order | `test_text_outside_article_is_part_of_the_document` |
| 2b | Decode collisions for binary bodies | Dual hashing; binary bypasses decoding, `raw == normalized` | `test_binary_media_records_raw_hash_as_both_hashes` (+ 3 more) |
| 3 | Silent truncation at a character cap | Byte-exact 4 MiB cap, explicit `ERR_PAYLOAD_TOO_LARGE`, never truncates | `test_payload_over_cap_reverts_explicitly_and_is_never_truncated` |
| 4 | `latest` pointer is front-runnable, so unsafe for escrow | Documented as informational; integration rebuilt on pinned immutable ids; tested | section 2.5, `test_pinned_id_stays_valid_after_anyone_advances_latest` |
| 5 | Free validator scraping through full refunds | 20% (0.01 GEN) non-refundable, 80% (0.04 GEN) refundable | `test_failed_fetch_slashes_20_percent_into_vault_and_refunds_80`, `test_scraping_spam_is_not_free` |

Operational note found while redeploying: the first line of the contract (`# v0.1.0`) is the **GenVM version
tag**, not a contract revision; bumping it makes the runner reject the contract as `malformed_runner` even
though the linter and direct tests pass. `deploy.py` now aborts instead of recording a deployment whose
execution result is not `FINISHED_WITH_RETURN`.

## 8. Known structural boundaries (disclosures)

These are properties of attesting the open web from a consensus network. They are not bugs the contract can
close, and the protocol does not claim to.

### 8.1 Server IP cloaking

A web server may return different content depending on who asks: by source IP, geography, `User-Agent`,
cookies, or by recognizing validator infrastructure. Validators can therefore agree on a page that the
requesting user, a regulator, or a counterparty would never see, and a hostile publisher can serve validators
one document and everyone else another. An attestation proves **what the validator set received from that URL
at that time**, not what any other client receives. Mitigations that remain outside the contract: attest content
you control or that is served from neutral, cache-friendly infrastructure; publish content-addressed copies
(IPFS, versioned release assets) and attest those; compare against an independent off-chain fetch before relying on
a hash; treat any single attestation of an untrusted publisher as one data point.

### 8.2 SSRF and URL-level boundaries

The canonicalizer (2.2) blocks the URL-level routes to internal targets: non-https, userinfo, ports other than 443,
IPv6 literals, obfuscated numeric hosts (octal / hex / integer / short), private, loopback, link-local, CGNAT and
reserved IPv4 ranges, local suffixes, encoded dots and slashes, and fragments. It is a **syntactic** filter. It
does **not** resolve DNS and does not control the fetch path, so it cannot stop: a public hostname whose DNS record
points at a private address (including DNS rebinding), an HTTP redirect from a public host to an internal one, or
anything the validators' own network policy permits or forbids. Defense against those belongs in the validators'
network egress rules. What limits the damage by construction: the contract stores only two hashes, a title and a 200-character snippet of a response, never the body.

### 8.3 Proof-of-existence at time T

`timestamp` is the block time at which the transaction was processed. An attestation proves that, **by time T**,
the validator set, reading `canonical_url`, received a response whose bytes hash to `raw_sha256` and whose
normalized text hashes to `normalized_sha256`. It does **not** prove that the content existed *before* T, that it was
published or authored at T (the page may be older), that it was the first version, that it is the content a
particular person saw, or that the URL has served it at any other time. Two attestations of one URL bound a
window, nothing more. Latest-pointer semantics do not weaken this: every attestation is immutable, the pointer
only indexes them (section 2.5).

### 8.4 Cost-asymmetric reads

Oversize bodies revert (as specified) and therefore refund the whole value, so a caller can still make validators
download up to 4 MiB per attempt without paying; only completed-but-failed fetches carry the 0.01 GEN penalty.
If that matters operationally, the cap can be lowered, or oversize can be changed from a revert to a penalized,
non-reverting status; the trade is that a non-reverting oversize result would have to record a refund instead of
returning the value.

### 8.5 Integrity of `raw_sha256` on HTML

As described in 2.4, `raw_sha256` of an HTML / text response is the leader's measurement; validators vouch for the
normalized text. It is evidence of exact bytes only for binary media.
