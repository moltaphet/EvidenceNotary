# EvidenceNotary -- Consensus Web Attestation Protocol

A pure-protocol (no frontend) web notarization and proof-of-existence contract for
[GenLayer](https://www.genlayer.com). Anyone -- an EOA or another contract -- pays an exact
fee and asks the validator set to read an `https` page. Every validator fetches the page
independently, extracts the document text deterministically, hashes it with SHA-256, and the
attestation is recorded **only if the validators agree on the hash**. The result is an
on-chain `(canonical_url, content_hash, title, snippet, timestamp, attester)` record that
other contracts can verify with one view call.

There is no LLM in the consensus path: agreement is a deterministic comparison of content
hashes, so a prompt cannot sway it.

* Contract: [`contracts/evidence_notary.py`](contracts/evidence_notary.py)
* Tests: [`tests/test_evidence_notary.py`](tests/test_evidence_notary.py) (175 tests, direct mode)
* Scripts: [`scripts/deploy.py`](scripts/deploy.py), [`scripts/interact_live.py`](scripts/interact_live.py)
* Live record: [`deployments/studio-next.json`](deployments/studio-next.json)

## 1. Verified on-chain deployment (Studio Next, chain 61997)

| | |
|---|---|
| Contract | `0xfE5667cB007ed15678C3E85B43d1176EE18623e3` |
| Explorer | https://explorer-studio-next.genlayer.com/address/0xfE5667cB007ed15678C3E85B43d1176EE18623e3 |
| Deploy tx | `0x40a022b26de2aab4a0cca687e704e37aa5c2c373170e19316e9279512e633295` -- FINISHED_WITH_RETURN, consensus **MAJORITY_AGREE** |
| Runner | `py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng` |
| Source SHA-256 | `cd42f2588b9d7a63bdbed207c19a035eb49fe841a665929a152ace5972af87a3` |
| Governor | `0x79D0B199047e568B39D8c422B66c693A7F9414b1` |
| Fee | 0.05 GEN (`50000000000000000` atto) |

Live proofs, produced by `scripts/interact_live.py` (every row is a real transaction; the full
per-validator votes and state hashes are in `deployments/studio-next.json`):

| Case | URL | Transaction | Validator consensus | Outcome / content hash | Contract state hash (leader == agreeing validators) |
|---|---|---|---|---|---|
| RFC 9000 -- QUIC transport specification | `https://rfc-editor.org/rfc/rfc9000` | `0x58d3578ba75309443f91f5b4020bb859e0c58a740502103665bcd5a59d59a679` | MAJORITY_AGREE (3 agree / 2 idle) | ATTESTED #1, `sha256:9d82d6b01a17ffd3a01900602db6e0dd137c1f49b90343df30f58e1b5ada3fa4` | `53dc6639c8f2ed14ee9ea3263e075b62feaaff087e20131b9335d45e7892e0f6` |
| Python 3.13 release notes | `https://docs.python.org/3/whatsnew/3.13.html` | `0x5e043b3a77f086933eb2cae530be4880f618de196ae6246b862902140e1eec77` | MAJORITY_AGREE (3 agree / 2 idle) | ATTESTED #2, `sha256:78b64dae28463b310cb4828a376be43c068d40538590f7fbb0acf71e0a87efdc` | `baebf36878e2db25b17ababb5107ee19ae935a695d24c5af59d35795c2c724be` |
| W3C Decentralized Identifiers (DID Core) | `https://w3.org/TR/did-core/` | `0x7d9561dfd9e5027607084e13ba3123a787b6c9bf342f69af4f0eafc3c1402266` | MAJORITY_AGREE (3 agree / 2 idle) | ATTESTED #3, `sha256:2b0a6c2e4a9dd913627d33825e9dfa39c6c2def524875d7f29bdc1fbc11083eb` | `8353a3d60bc92400cb9623f0791e3d2eaace443b9eeb5df0945301d3111561c3` |
| Dead link -- HTTP 404 on docs.python.org (fee must be refunded) | `https://docs.python.org/3/evidencenotary-nonexistent-page-404.html` | `0x4a98bb7d75a18855ee9a25514fb97c9132f5025097745ee1e70ee84badcec0e0` | MAJORITY_AGREE (3 agree / 2 idle) | AMBIGUOUS_VOID -> 0.05 GEN to `claimable_credits` | `43e4c3a85a622337aa93997cd40dee52f6bba87f09d06df2e525269fb5db22b5` |

Follow-up transactions:

| Step | Transaction | Consensus | Effect |
|---|---|---|---|
| `pull_withdraw` (refund from case 4) | `0x06a856e1d906fbc564f235bbb20cb12a6da7235a98361066e4539f519dcb1e9b` | MAJORITY_AGREE | `claimable_credits` 0.05 -> 0 GEN; caller received the payout |
| `sweep_vault` (governor) | `0x8af95c3b2baeeb180036a9d2ab05e75897ad6279329b2e9a7d15480a4815d1b6` | MAJORITY_AGREE | vault 0.15 -> 0 GEN |

Every consensus round on the table reached `MAJORITY_AGREE` with 3 agreeing validators (the other
two validators voted `idle`). The three content hashes are reproducible:
two independent deployments of this contract produced the identical SHA-256 for each page.
The 404 case did not revert: the call finished, returned `AMBIGUOUS_VOID`, recorded nothing, and
credited the fee back to the payer (section 3).

Reproduce: `python scripts/deploy.py && python scripts/interact_live.py` (a throwaway key is
generated into the gitignored `.env` and funded from the Studio faucet).

## 2. Protocol

### 2.1 API

| Method | Kind | Behaviour |
|---|---|---|
| `attest(url) -> dict` | payable | Requires **exactly** 0.05 GEN. Canonicalizes `url`, reads it across validators, records an attestation on consensus. Returns `{status, attestation_id, canonical_url, ...}`. |
| `verify_attestation(id, expected_hash) -> bool` | view | `True` iff the attestation exists and its hash equals `expected_hash` (hex SHA-256; letter case and a `0x` prefix are not significant). |
| `get_latest_attestation(url) -> dict` | view | Latest attestation for the *canonical* form of `url`; reverts `ERR_NOT_FOUND` if none. |
| `get_attestation(id) -> dict` | view | Record by id. |
| `canonicalize(url) -> str` | view | The canonicalizer, exposed for clients. |
| `pull_withdraw() -> str` | write | Pays the caller their `claimable_credits` (pull pattern, checks-effects-interactions). |
| `sweep_vault() -> str` | write | Governor only: pays the whole `protocol_vault` to the governor. |
| `transfer_governor(addr)` | write | Governor only; zero address rejected. |
| `get_protocol_state`, `is_solvent`, `is_ledger_conserved`, `claimable_of`, `get_fee`, `get_governor` | views | Accounting and configuration. |

Attestation record: `attestation_id`, `canonical_url`, `content_hash` (hex SHA-256 of the normalized
text), `title`, `text_snippet` (first 200 characters of the verified text), `timestamp` (block time,
unix seconds), `attester` (`msg.sender`, lowercase hex), `fee_paid`.

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

### 2.3 Document extraction and normalization

Run identically by every validator inside `gl.vm.run_nondet`:

1. `GET` the canonical URL. Transport error or `429`/`5xx` -> `UNREACHABLE`; any other non-2xx (4xx, 1xx, 3xx) -> `AMBIGUOUS_VOID`.
2. Decode the body (UTF-8, replacement on error), cap at 4,000,000 characters.
3. If it is HTML, parse with the standard-library `HTMLParser` and **drop** whole subtrees for `script style noscript template svg canvas iframe object embed form button select input textarea nav header footer aside menu dialog head`, anything `hidden` / `aria-hidden`, `role` of navigation/banner/contentinfo/complementary/search, and any element whose `class`, `id`, `role` or `aria-label` matches cookie / consent / gdpr / banner / advert / ads / sponsor / promo / popup / modal / newsletter / subscribe / sidebar / breadcrumb / navbar / navigation / menu / social / share. Block-level tags insert a break so words never fuse.
4. If the page declares `<article>` or `<main>` with text, **only** that text is kept; otherwise all remaining body text.
5. **Normalize**: Unicode NFKC; curly quotes -> `'`/`"`; en/em dash and minus -> `-`; zero-width, format and private-use characters removed; control characters removed; every whitespace run folded to one space; trim. Non-HTML bodies skip steps 3-4.
6. Fewer than 40 characters left -> `AMBIGUOUS_VOID` (no notarizable document).
7. `content_hash = SHA-256(utf-8(normalized text))`. Title (`<title>`, normalized, <= 300 chars) and the first 200 characters are recorded.

Why it is robust: rotating ads, tracking scripts, cookie banners, whitespace, entities, typographic
punctuation and compatibility characters never reach the hash (each is a test).

### 2.4 Consensus

`leader_fn` and every validator run the same `_read_page`. A validator **agrees** iff both reads
succeeded and `content_hash` **and** `title` are identical, or both failed with the same failure class
(`UNREACHABLE` / `AMBIGUOUS_VOID`). Everything else -- a different hash, a page that vanished, a leader
claiming success for a dead page, a malformed leader result, a leader crash -- is **disagree**. The
check is exact on purpose: a notary that tolerates "close enough" documents notarizes nothing.
Trade-off: a page edited between two validators' fetches fails that round and the transaction retries.

### 2.5 Cross-contract integration

Any contract can verify a web proof with a synchronous view call (illustrative sketch of the standard
`gl.get_contract_at(...).view()` pattern; the live scripts exercise the views through the SDK, not through a calling contract):

```python
import genlayer as gl
from genlayer import Address

NOTARY = Address("0xfE5667cB007ed15678C3E85B43d1176EE18623e3")

class Escrow(gl.contract.Contract):
    ...
    @gl.public.write
    def release_if_published(self, url: str, expected_hash: str) -> None:
        notary = gl.get_contract_at(NOTARY)
        att = notary.view().get_latest_attestation(url)   # reverts if never attested
        if att["content_hash"] != expected_hash.lower():
            raise gl.vm.UserError("[EXPECTED] document differs from the agreed one")
        if att["timestamp"] < self.deadline_start:
            raise gl.vm.UserError("[EXPECTED] attestation predates the agreement")
        ...
        # or, by id:  notary.view().verify_attestation(attestation_id, expected_hash)
```

Integrators should pin the `attestation_id` they relied on (records are immutable; `get_latest_attestation`
moves as the page is re-attested) and check `timestamp`. `attester` is the caller of `attest`.
Off-chain, anyone can reproduce a hash with the algorithm in 2.3 and compare via `verify_attestation`.

## 3. Failure path and why `attest` does not revert on a dead page

The specification asks for a refund to `claimable_credits` when the URL is dead. A reverted
transaction rolls back **all** state, including any credit written in it, so a reverting `attest`
cannot also record a refund. The contract therefore splits errors in two:

* **Caller errors revert** (`ERR_INVALID_URL`, `ERR_WRONG_FEE`): nothing is recorded and the attached
  value is returned to the sender by the VM.
* **Dead / failing pages finish normally** with status `UNREACHABLE` (transport error, 429, 5xx) or
  `AMBIGUOUS_VOID` (other non-2xx, empty or non-document body). No attestation is created, the fee goes
  to `claimable_credits[caller]`, and the validators have reached consensus on the *failure* too. The
  payer collects with `pull_withdraw()`.

## 4. Solvency and accounting

### 4.1 Definitions

Let, at any finalized state: `B = self.balance` (native GEN held), `V = protocol_vault`,
`C = total_credits`, `R = total_received`, `P = total_paid_out`, `f = 0.05 GEN`, and
`C = sum(claimable_credits.values())` (a running counter, never a scan).

* **Strict solvency (S):** `B = V + C`
* **Ledger conservation (L):** `R = V + C + P`

### 4.2 Proof

Every state-changing path, with its effect on `(B, V, C, R, P)`:

| Transition | B | V | C | R | P |
|---|---|---|---|---|---|
| `attest`, consensus success | `+f` | `+f` | 0 | `+f` | 0 |
| `attest`, dead page (refund) | `+f` | 0 | `+f` | `+f` | 0 |
| `attest`, wrong fee / bad URL (revert) | 0 | 0 | 0 | 0 | 0 |
| `pull_withdraw` of `a` | `-a` | 0 | `-a` | 0 | `+a` |
| `sweep_vault` of `a = V` | `-a` | `-a` | 0 | 0 | `+a` |

*Base case.* A deployed contract has `B = V = C = R = P = 0`, so S and L hold.

*Induction.* Assume S and L before a transition. Each row changes `B - V - C` by `0`
(`f-f-0`, `f-0-f`, `0`, `-a-0+a`, `-a+a-0`) and `R - V - C - P` by `0` (`f-f`, `f-f`, `0`, `0-(-a)-a`,
`0-(-a)-a`). Hence S and L are preserved. A revert changes nothing. In `attest` the fee is checked
against `gl.message.value` **first**, so exactly `f` enters `B` per non-reverting call; `claimable_credits` is only written
through `_credit` (which adds the same amount to `C`) and `pull_withdraw` (which subtracts the same amount from `C`
before the transfer, and restores all three counters if enqueueing the transfer fails). Therefore
`C = sum(claimable_credits)` always, no account can withdraw more than it was credited, and the
vault and the credits are disjoint pools: `sweep_vault` can never touch a refund. `P` is incremented
before `emit_transfer`, so reentrancy cannot double-spend. QED.

Per-account safety: `claimable_credits[a]` only grows by `f` per refunded attestation by `a`, and
`pull_withdraw` pays `claimable_credits[a]` once and zeroes it first (a second call reverts
`ERR_NOTHING_TO_WITHDRAW`).

### 4.3 Measured on Studio Next: transfer settlement and the balance drift

`pull_withdraw` and `sweep_vault` pay with `emit_transfer(amount, on="finalized")`: the transfer is
applied when the transaction finalizes, not when it is accepted. Measured on Studio Next after the
transactions in section 1 had finalized (and re-read for 60 seconds after):

* the recipient **was** paid (caller balance rose by 0.05 GEN, less fees), but
* the contract's native balance **was not debited**: after the sweep, `balance = 0.2 GEN` while
  `V = C = 0`.

So on Studio Next, strict solvency (S) holds exactly until the first payout and thereafter reads
`B - (V + C) = P` (recorded in the JSON as `balance_drift`; final state: `balance 0.2, vault 0,
credits 0, total_paid_out 0.2`). The chain-independent ledger identity (L) is exact throughout, which is
why it exists: it is made only of counters this contract writes, so it verifies that no fee was created,
lost, or double-paid even where the host's native-balance accounting differs. `scripts/interact_live.py`
asserts (L) after every transaction and asserts `B - (V + C) in {0, P}`. On a chain that debits payouts at
settlement, `P` is exactly what has left `B`, and (S) and (L) coincide. This is a property of the Studio
Next simulator observed in this deployment; it is not something the contract can influence, and the
direct-mode test `test_ledger_holds_even_if_chain_never_debits_payouts` pins the behaviour.

## 5. Tests

```
python3.12 -m venv .venv && . .venv/bin/activate
pip install --pre genlayer-test==0.30.0rc2 genlayer-py==0.19.0rc2 genvm-linter==0.11.1rc2 pytest
pytest -q                                     # 175 tests, ~2.5 min, no network
genvm-lint check contracts/evidence_notary.py # 0 errors
```

175 test cases (well over 160 assertions: the canonicalizer tests alone loop over 28 accepted and
97 rejected inputs), covering canonicalization and SSRF-style bypasses, deterministic extraction (24 chrome
variants, whitespace / entity / NFKC / quote folding), deduplication, 17 HTTP failure statuses and 6 non-document
bodies with refunds, exact-fee enforcement, validator agreement / disagreement via `run_validator`, governance,
and the accounting invariants (S) and (L) after every step of mixed attest / refund / withdraw / sweep
sequences, including six seeded randomized runs. The direct harness does not move native value, so
`tests/conftest.py::Chain` mirrors GenVM's rules (a call that returns credits `value`; a revert credits nothing;
a payout debits) and checks the contract's counters against that independent balance model.
`test_genvm_lint_reports_zero_errors` runs the linter inside the suite.

## 6. Known limits

* Exact-hash consensus: pages that change between validators' fetches (live feeds, per-request tokens
  inside the article body) will not reach agreement. That is deliberate; attest stable documents.
* Extraction is structural (tags, classes), not semantic. A page whose body text is injected by JavaScript is
  attested as the server-rendered HTML a plain `GET` sees.
* Titles are part of agreement. The Python docs title embeds the site's current version
  (`... - Python 3.14.8 documentation`), so a site-wide version bump between two validators' fetches would fail that round.
* A fresh throwaway key is used for the deployment, so the governor is that key (rotate with `transfer_governor`).
