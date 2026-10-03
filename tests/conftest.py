"""Shared helpers for EvidenceNotary direct-mode tests (pure ASCII).

The direct harness executes contract code in memory and does not move native
GEN: attached value never reaches the contract balance and emit_transfer is a
no-op. `Chain` mirrors exactly what GenVM does on a real chain -- a call that
returns normally credits `value` to the contract, a call that reverts credits
nothing, and a successful payout debits the contract -- so the contract's own
bookkeeping can be checked against an independent balance model.
"""

import hashlib

import pytest

CONTRACT = "contracts/evidence_notary.py"
FEE = 5 * 10**16  # 0.05 GEN in atto-GEN
PENALTY = FEE // 5  # 0.01 GEN non-refundable bandwidth fee on a failed attestation
REFUND = FEE - PENALTY  # 0.04 GEN returned to claimable_credits
MAX_PAYLOAD = 4 * 1024 * 1024

LONG_TEXT = (
    "The notary records a content hash for every document it is shown. "
    "Validators read the page independently and must agree on the digest."
)


def html_page(body_text=LONG_TEXT, title="Sample Document", tracker=""):
    """A realistic page. Only <script>/<style>/<noscript>/<svg>/<canvas> are
    non-rendered; every other element's text is part of the document."""
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title>"
        "<style>body{font-family:serif}.ad{display:none}</style>"
        "<script>window.tracker = 'noise-" + tracker + "';</script></head><body>"
        "<header><div>Site Header Logo</div></header>"
        "<nav><ul><li>Home</li><li>Docs</li><li>Pricing</li></ul></nav>"
        "<div class='cookie-banner'>We use cookies. Accept all.</div>"
        "<div class='advert'>Buy now</div>"
        f"<article><h1>{title}</h1><p>{body_text}</p></article>"
        "<aside>Related links</aside>"
        "<footer>Copyright footer text</footer>"
        "<script>document.write('late script " + tracker + "')</script></body></html>"
    )


def page_text(body_text=LONG_TEXT, title="Sample Document"):
    """The normalized text html_page() must reduce to (document order)."""
    return (
        "Site Header Logo Home Docs Pricing We use cookies. Accept all. Buy now "
        f"{title} {body_text} Related links Copyright footer text"
    )


def typed(body, content_type, status=200):
    """A full-format web mock carrying a Content-Type header and raw bytes."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return {"response": {"status": status, "headers": {"Content-Type": content_type.encode()}, "body": body}}


def expected_hash(text):
    """Independent reference: SHA-256 over single-space-folded text."""
    return hashlib.sha256(" ".join(text.split()).encode("utf-8")).hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Chain:
    """Deploys the contract and mirrors native-value movement."""

    def __init__(self, vm, deploy, accounts):
        self.vm = vm
        self.alice, self.bob, self.carol = accounts
        vm.sender = self.alice  # deployer == governor
        self.c = deploy(CONTRACT)
        self.governor = self.alice
        self.addr = vm._contract_address
        vm.deal(self.addr, 0)
        self.mirror = 0

    # -- low level ---------------------------------------------------------
    def _sync(self):
        self.vm.deal(self.addr, self.mirror)

    def page(self, pattern, status=200, body=None):
        self.vm.mock_web(pattern, {"status": status, "body": body if body is not None else html_page()})

    def attest(self, who, url, value=FEE):
        self.vm.sender = who
        self.vm.value = value
        try:
            res = self.c.attest(url)
        finally:
            self.vm.value = 0
        self.mirror += value  # reached only when the call did not revert
        self._sync()
        return res

    def withdraw(self, who):
        self.vm.sender = who
        paid = int(self.c.pull_withdraw())
        self.mirror -= paid
        self._sync()
        return paid

    def sweep(self, who):
        self.vm.sender = who
        paid = int(self.c.sweep_vault())
        self.mirror -= paid
        self._sync()
        return paid

    # -- accounting --------------------------------------------------------
    def keys(self):
        return [self.key(a) for a in (self.alice, self.bob, self.carol)]

    def key(self, who):
        prev = self.vm.sender
        self.vm.sender = who
        k = self.c.whoami()
        self.vm.sender = prev
        return k

    def credits_sum(self):
        return sum(int(self.c.claimable_of(k)) for k in self.keys())

    def state(self):
        return self.c.get_protocol_state()

    def assert_invariants(self):
        s = self.state()
        vault, total = int(s["protocol_vault"]), int(s["total_credits"])
        assert self.mirror == vault + total, (self.mirror, vault, total)
        assert total == self.credits_sum()
        assert self.mirror >= 0
        # chain-independent ledger identity
        assert s["ledger_conserved"] is True
        assert int(s["total_received"]) == vault + total + int(s["total_paid_out"])
        assert self.c.is_ledger_conserved() is True


@pytest.fixture
def chain(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    return Chain(direct_vm, direct_deploy, (direct_alice, direct_bob, direct_charlie))
