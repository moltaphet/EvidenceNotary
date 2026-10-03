"""EvidenceNotary direct-mode test suite (pure ASCII).

Run:  pytest tests/ -q
Lint: genvm-lint check contracts/evidence_notary.py   (see test_genvm_lint)
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import CONTRACT, FEE, LONG_TEXT, expected_hash, html_page

ROOT = Path(__file__).resolve().parent.parent


# ============================================================================
# 1. URL canonicalization -- accepted forms
# ============================================================================
VALID_URLS = [
    ("https://example.com", "https://example.com/"),
    ("https://example.com/", "https://example.com/"),
    ("https://www.example.com/", "https://example.com/"),
    ("https://WWW.Example.COM/Path", "https://example.com/Path"),
    ("HTTPS://EXAMPLE.COM/a", "https://example.com/a"),
    ("https://example.com/a/", "https://example.com/a"),
    ("https://example.com/a//b///c/", "https://example.com/a/b/c"),
    ("https://example.com/a/./b", "https://example.com/a/b"),
    ("https://example.com/a/b/../c", "https://example.com/a/c"),
    ("https://example.com/../../a", "https://example.com/a"),
    ("https://example.com:443/a", "https://example.com/a"),
    ("https://example.com/a#section-2", "https://example.com/a"),
    ("https://example.com/a?b=2&a=1", "https://example.com/a?a=1&b=2"),
    ("https://example.com/a?a=1&&b=2&", "https://example.com/a?a=1&b=2"),
    ("https://example.com/a/?x=1#frag", "https://example.com/a?x=1"),
    ("  https://example.com/a  ", "https://example.com/a"),
    ("https://example.com.", "https://example.com/"),
    ("https://docs.python.org/3/whatsnew/3.13.html", "https://docs.python.org/3/whatsnew/3.13.html"),
    ("https://www.rfc-editor.org/rfc/rfc9000", "https://rfc-editor.org/rfc/rfc9000"),
    ("https://www.w3.org/TR/did-core/", "https://w3.org/TR/did-core"),
    ("https://sub.domain.example.co.uk/x", "https://sub.domain.example.co.uk/x"),
    ("https://xn--bcher-kva.example/", "https://xn--bcher-kva.example/"),
    ("https://8.8.8.8/dns", "https://8.8.8.8/dns"),
    ("https://1.1.1.1/", "https://1.1.1.1/"),
    ("https://172.15.0.1/", "https://172.15.0.1/"),
    ("https://172.32.0.1/", "https://172.32.0.1/"),
    ("https://100.63.0.1/", "https://100.63.0.1/"),
    ("https://a-b.example.com/", "https://a-b.example.com/"),
]


def test_canonicalize_accepts(chain):
    for raw, canon in VALID_URLS:
        assert chain.c.canonicalize(raw) == canon, raw


# ============================================================================
# 2. URL canonicalization -- rejected forms
# ============================================================================
INVALID_URLS = [
    # not https
    "http://example.com/",
    "HTTP://example.com/",
    "ftp://example.com/",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "data:text/html,hi",
    "//example.com/",
    "example.com/path",
    "rfc-editor.org/rfc/rfc9000",
    "https:/example.com",
    "https:example.com",
    "ws://example.com/",
    "",
    "   ",
    "https://",
    "https:///path",
    # userinfo
    "https://user:pass@example.com/",
    "https://user@example.com/",
    "https://@example.com/",
    "https://example.com@evil.com/",
    "https://example.com:443@evil.com/",
    "https://a:b@127.0.0.1/",
    "https://example.com/path@x",  # '@' in path is legal -> accepted (see below)
    # loopback / private / link-local / reserved IPv4
    "https://127.0.0.1/",
    "https://127.0.0.1:443/",
    "https://127.1.2.3/",
    "https://127.255.255.254/",
    "https://10.0.0.1/",
    "https://10.255.255.255/",
    "https://192.168.0.1/",
    "https://192.168.255.1/",
    "https://172.16.0.1/",
    "https://172.31.255.255/",
    "https://169.254.169.254/latest/meta-data",
    "https://0.0.0.0/",
    "https://100.64.0.1/",
    "https://100.127.255.255/",
    "https://192.0.0.8/",
    "https://198.18.0.1/",
    "https://224.0.0.1/",
    "https://255.255.255.255/",
    # numeric-IP obfuscation
    "https://2130706433/",  # decimal 127.0.0.1
    "https://0x7f000001/",  # hex
    "https://0x7f.0.0.1/",
    "https://0177.0.0.1/",  # octal
    "https://127.1/",  # short form
    "https://127.0.1/",
    "https://010.0.0.1/",
    "https://1.2.3/",
    "https://1.2.3.4.5/",
    "https://256.1.1.1/",
    "https://999.999.999.999/",
    "https://3232235521/",  # decimal 192.168.0.1
    # IPv6
    "https://[::1]/",
    "https://[::ffff:127.0.0.1]/",
    "https://[fe80::1]/",
    "https://[2001:db8::1]/",
    "https://::1/",
    # local names
    "https://localhost/",
    "https://LOCALHOST/",
    "https://localhost./",
    "https://foo.localhost/",
    "https://printer.local/",
    "https://db.internal/",
    "https://router.lan/",
    "https://intranet/",
    "https://singlelabel/",
    "https://www.localhost/",
    "https://host.localdomain/",
    "https://1.0.0.127.in-addr.arpa/",
    # ports
    "https://example.com:80/",
    "https://example.com:8443/",
    "https://example.com:0/",
    "https://example.com:abc/",
    "https://example.com:/",
    # character abuse
    "https://exa mple.com/",
    "https://example.com/a b",
    "https://example.com/\tpath",
    "https://example.com/\npath",
    "https://example.com\\@evil.com/",
    "https://example.com/a\\b",
    "https://exam\x00ple.com/",
    "https://exa_mple.com/",
    "https://-example.com/",
    "https://example-.com/",
    "https://ex%61mple.com/",
    "https://bücher.example/",
    "https://例え.jp/",
    "https://example..com/",
    "https://.example.com/",
    "https://example.com/%2e%2e/secret",
    "https://example.com/a%2fb",
    "https://example.com/a%5cb",
    "https://www./",
    "https://www.com/",
    "https://" + "a" * 64 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + "." + "e" * 63 + "/",
    "https://example.com/" + "a" * 2100,
]
# The '@' inside a *path* is not userinfo and is legal; keep it out of the reject list.
INVALID_URLS.remove("https://example.com/path@x")
# 63-char labels are legal individually; the oversized-host case is the 5x63+dots one.


def test_canonicalize_rejects(chain):
    for raw in INVALID_URLS:
        with chain.vm.expect_revert("ERR_INVALID_URL"):
            chain.c.canonicalize(raw)


def test_at_sign_in_path_is_not_userinfo(chain):
    assert chain.c.canonicalize("https://example.com/path@x") == "https://example.com/path@x"
    assert chain.c.canonicalize("https://example.com/?email=a@b.c") == "https://example.com/?email=a@b.c"


@pytest.mark.parametrize("raw", [
    "http://example.com/", "https://u:p@example.com/", "https://127.0.0.1/",
    "https://10.1.1.1/", "https://192.168.1.1/", "https://localhost/",
])
def test_attest_rejects_bad_url_and_changes_nothing(chain, raw):
    chain.page(r".*", 200)
    with chain.vm.expect_revert("ERR_INVALID_URL"):
        chain.attest(chain.alice, raw)
    s = chain.state()
    assert s["attestation_count"] == "0"
    assert s["protocol_vault"] == "0"
    assert s["total_credits"] == "0"
    chain.assert_invariants()


# ============================================================================
# 3. Successful attestation + deterministic extraction
# ============================================================================
def test_successful_attestation_record(chain):
    chain.page(r".*example\.com.*", 200, html_page(LONG_TEXT, "Sample Document"))
    chain.vm.warp("2026-03-01T12:00:00+00:00")
    r = chain.attest(chain.bob, "https://www.Example.com/doc/")
    assert r["status"] == "ATTESTED"
    assert r["attestation_id"] == 1
    assert r["canonical_url"] == "https://example.com/doc"
    assert r["refunded"] == "0"
    a = chain.c.get_attestation(1)
    assert a["attestation_id"] == 1
    assert a["canonical_url"] == "https://example.com/doc"
    assert a["title"] == "Sample Document"
    assert a["fee_paid"] == str(FEE)
    assert a["attester"] == chain.key(chain.bob)
    assert a["timestamp"] == 1772366400
    assert re.fullmatch(r"[0-9a-f]{64}", a["content_hash"])
    # heading "Sample Document" is inside <article> so it leads the text
    assert a["content_hash"] == expected_hash("Sample Document " + LONG_TEXT)
    assert a["text_snippet"] == ("Sample Document " + LONG_TEXT)[:200]
    assert len(a["text_snippet"]) <= 200
    chain.assert_invariants()


def test_snippet_is_first_200_chars(chain):
    long_body = " ".join(f"word{i}" for i in range(200))
    chain.page(r".*", 200, html_page(long_body, "T"))
    chain.attest(chain.alice, "https://example.com/long")
    a = chain.c.get_attestation(1)
    full = "T " + long_body
    assert len(a["text_snippet"]) == 200
    assert a["text_snippet"] == full[:200]
    assert a["content_hash"] == expected_hash(full)


def test_ids_are_sequential(chain):
    chain.page(r".*", 200)
    ids = [chain.attest(chain.alice, f"https://example.com/p{i}")["attestation_id"] for i in range(1, 6)]
    assert ids == [1, 2, 3, 4, 5]
    assert chain.state()["attestation_count"] == "5"


def test_failed_attest_does_not_consume_an_id(chain):
    chain.page(r".*bad.*", 404, "gone")
    chain.page(r".*good.*", 200)
    chain.attest(chain.alice, "https://bad.example.com/x")
    r = chain.attest(chain.alice, "https://good.example.com/x")
    assert r["attestation_id"] == 1


def test_chrome_is_stripped_from_hash(chain):
    chain.page(r".*a\.example\.com.*", 200, html_page(LONG_TEXT, "Doc", extra_chrome="AAA"))
    chain.page(r".*b\.example\.com.*", 200, html_page(LONG_TEXT, "Doc", extra_chrome="BBB"))
    r1 = chain.attest(chain.alice, "https://a.example.com/p")
    r2 = chain.attest(chain.alice, "https://b.example.com/p")
    # different ads / script payloads, identical document => identical hash
    assert r1["content_hash"] == r2["content_hash"]


@pytest.mark.parametrize("chrome", [
    "<script>evil()</script>",
    "<style>.x{color:red}</style>",
    "<noscript>enable js</noscript>",
    "<nav>Home | About | Contact</nav>",
    "<header>Brand header</header>",
    "<footer>All rights reserved</footer>",
    "<aside>Trending now</aside>",
    "<form><input name=q><button>Go</button></form>",
    "<div class='cookie-consent'>Accept cookies</div>",
    "<div id='cookie-banner'>Cookies!</div>",
    "<div class='ad-slot'>Sponsored</div>",
    "<div class='advert'>Buy</div>",
    "<div class='sidebar'>Sidebar</div>",
    "<div class='breadcrumb'>a &gt; b</div>",
    "<div class='newsletter-signup'>Subscribe</div>",
    "<div class='share-buttons'>Share</div>",
    "<div role='navigation'>nav role</div>",
    "<div role='banner'>banner role</div>",
    "<div aria-hidden='true'>hidden text</div>",
    "<div hidden>hidden attr</div>",
    "<svg><text>svg text</text></svg>",
    "<iframe>frame</iframe>",
    "<template><p>tmpl</p></template>",
    "<div class='popup modal'>Popup</div>",
])
def test_non_document_chrome_never_changes_hash(chain, chrome):
    base = (
        "<html><head><title>T</title></head><body><main><p>"
        + LONG_TEXT + "</p></main></body></html>"
    )
    noisy = (
        "<html><head><title>T</title></head><body>" + chrome
        + "<main><p>" + LONG_TEXT + "</p></main>" + chrome + "</body></html>"
    )
    chain.page(r".*clean\.example\.com.*", 200, base)
    chain.page(r".*noisy\.example\.com.*", 200, noisy)
    a = chain.attest(chain.alice, "https://clean.example.com/")
    b = chain.attest(chain.alice, "https://noisy.example.com/")
    assert a["status"] == b["status"] == "ATTESTED"
    assert a["content_hash"] == b["content_hash"]


def test_whitespace_entities_and_unicode_do_not_change_hash(chain):
    plain = "<html><body><article>" + LONG_TEXT + "</article></body></html>"
    messy_text = LONG_TEXT.replace(" ", "  \n\t ").replace("notary", "no&shy;tary".replace("&shy;", ""))
    messy = (
        "<html><body><article>\n\n  " + messy_text.replace("records", "re&#99;ords")
        + "​ </article></body></html>"
    )
    chain.page(r".*p1\.example\.com.*", 200, plain)
    chain.page(r".*p2\.example\.com.*", 200, messy)
    a = chain.attest(chain.alice, "https://p1.example.com/")
    b = chain.attest(chain.alice, "https://p2.example.com/")
    assert a["content_hash"] == b["content_hash"] == expected_hash(LONG_TEXT)


def test_typographic_quotes_and_dashes_fold(chain):
    straight = "<html><body><article>It's a \"quoted\" - dashed statement made of enough text to count.</article></body></html>"
    curly = "<html><body><article>It’s a “quoted” — dashed statement made of enough text to count.</article></body></html>"
    chain.page(r".*s\.example\.com.*", 200, straight)
    chain.page(r".*c\.example\.com.*", 200, curly)
    a = chain.attest(chain.alice, "https://s.example.com/")
    b = chain.attest(chain.alice, "https://c.example.com/")
    assert a["content_hash"] == b["content_hash"]


def test_nfkc_compatibility_forms_fold(chain):
    ascii_page = "<html><body><article>The file system stores 100 documents in the notary vault today.</article></body></html>"
    fancy = "<html><body><article>The ﬁle system stores １００ documents in the notary vault today.</article></body></html>"
    chain.page(r".*x\.example\.com.*", 200, ascii_page)
    chain.page(r".*y\.example\.com.*", 200, fancy)
    a = chain.attest(chain.alice, "https://x.example.com/")
    b = chain.attest(chain.alice, "https://y.example.com/")
    assert a["content_hash"] == b["content_hash"]


def test_text_change_changes_hash(chain):
    chain.page(r".*v1\.example\.com.*", 200, html_page(LONG_TEXT))
    chain.page(r".*v2\.example\.com.*", 200, html_page(LONG_TEXT.replace("agree", "disagree")))
    a = chain.attest(chain.alice, "https://v1.example.com/")
    b = chain.attest(chain.alice, "https://v2.example.com/")
    assert a["content_hash"] != b["content_hash"]


def test_article_landmark_preferred_over_page_body(chain):
    page = (
        "<html><body><div>Outside text that is long enough to be a document on its own right.</div>"
        "<article>" + LONG_TEXT + "</article></body></html>"
    )
    chain.page(r".*", 200, page)
    r = chain.attest(chain.alice, "https://example.com/")
    assert r["content_hash"] == expected_hash(LONG_TEXT)


def test_page_without_landmark_uses_body_text(chain):
    page = "<html><head><title>Plain</title></head><body><div><p>" + LONG_TEXT + "</p></div></body></html>"
    chain.page(r".*", 200, page)
    r = chain.attest(chain.alice, "https://example.com/")
    assert r["content_hash"] == expected_hash(LONG_TEXT)
    assert r["title"] == "Plain"


def test_title_is_not_part_of_body_hash_but_is_recorded(chain):
    chain.page(r".*t1\.example\.com.*", 200, "<html><head><title>One</title></head><body><p>" + LONG_TEXT + "</p></body></html>")
    r = chain.attest(chain.alice, "https://t1.example.com/")
    assert r["title"] == "One"
    assert r["content_hash"] == expected_hash(LONG_TEXT)


def test_plain_text_document(chain):
    chain.page(r".*", 200, "Request for Comments 9000\n\n   QUIC: A UDP-Based Multiplexed and Secure Transport\n")
    r = chain.attest(chain.alice, "https://example.com/rfc.txt")
    assert r["status"] == "ATTESTED"
    assert r["content_hash"] == expected_hash("Request for Comments 9000 QUIC: A UDP-Based Multiplexed and Secure Transport")
    assert r["title"] == ""


def test_malformed_html_is_tolerated(chain):
    page = "<html><body><article><p>" + LONG_TEXT + "<div><span>unclosed<p>more text</article></body>"
    chain.page(r".*", 200, page)
    r = chain.attest(chain.alice, "https://example.com/")
    assert r["status"] == "ATTESTED"
    assert re.fullmatch(r"[0-9a-f]{64}", r["content_hash"])


def test_extraction_is_deterministic_across_runs(chain):
    chain.page(r".*", 200)
    hashes = {chain.attest(chain.alice, "https://example.com/same")["content_hash"] for _ in range(4)}
    assert len(hashes) == 1


def test_oversized_body_is_bounded(chain):
    big = "<html><body><article>" + ("lorem ipsum dolor " * 20_000) + "</article></body></html>"
    chain.page(r".*", 200, big)
    r = chain.attest(chain.alice, "https://example.com/big")
    assert r["status"] == "ATTESTED"


def test_bytes_body_is_decoded(chain):
    chain.vm.mock_web(r".*", {"status": 200, "body": html_page().encode("utf-8")})
    r = chain.attest(chain.alice, "https://example.com/")
    assert r["status"] == "ATTESTED"


# ============================================================================
# 4. Deduplication / latest pointer
# ============================================================================
DUP_VARIANTS = [
    "https://example.com/doc",
    "https://example.com/doc/",
    "https://www.example.com/doc",
    "https://WWW.EXAMPLE.COM/doc/",
    "https://example.com:443/doc",
    "https://example.com/doc#top",
    "https://example.com//doc",
    "https://example.com/x/../doc",
    "  https://example.com/doc ",
]


@pytest.mark.parametrize("variant", DUP_VARIANTS)
def test_variants_resolve_to_one_canonical_record(chain, variant):
    chain.page(r".*", 200)
    r = chain.attest(chain.alice, variant)
    assert r["canonical_url"] == "https://example.com/doc"
    latest = chain.c.get_latest_attestation("https://example.com/doc")
    assert latest["attestation_id"] == r["attestation_id"]
    assert chain.c.get_latest_attestation(variant)["attestation_id"] == r["attestation_id"]


def test_latest_pointer_follows_newest_attestation(chain):
    chain.page(r".*", 200, html_page(LONG_TEXT))
    first = chain.attest(chain.alice, "https://example.com/doc")
    chain.vm.clear_mocks()
    chain.page(r".*", 200, html_page(LONG_TEXT + " Revised clause added in version two."))
    second = chain.attest(chain.bob, "https://www.example.com/doc/")
    assert first["attestation_id"] == 1 and second["attestation_id"] == 2
    latest = chain.c.get_latest_attestation("https://example.com/doc")
    assert latest["attestation_id"] == 2
    assert latest["content_hash"] == second["content_hash"] != first["content_hash"]
    # the superseded record stays immutable and verifiable
    assert chain.c.get_attestation(1)["content_hash"] == first["content_hash"]
    assert chain.c.verify_attestation(1, first["content_hash"]) is True
    assert chain.c.verify_attestation(2, first["content_hash"]) is False


def test_distinct_urls_have_independent_latest(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/a")
    chain.attest(chain.alice, "https://example.com/b")
    assert chain.c.get_latest_attestation("https://example.com/a")["attestation_id"] == 1
    assert chain.c.get_latest_attestation("https://example.com/b")["attestation_id"] == 2


def test_query_order_dedupes(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/s?a=1&b=2")
    r = chain.attest(chain.alice, "https://example.com/s?b=2&a=1")
    assert r["canonical_url"] == "https://example.com/s?a=1&b=2"
    assert chain.c.get_latest_attestation("https://example.com/s?b=2&a=1")["attestation_id"] == 2


def test_query_difference_is_a_different_document(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/s?a=1")
    chain.attest(chain.alice, "https://example.com/s?a=2")
    assert chain.c.get_latest_attestation("https://example.com/s?a=1")["attestation_id"] == 1
    assert chain.c.get_latest_attestation("https://example.com/s?a=2")["attestation_id"] == 2


def test_get_latest_unknown_url_reverts(chain):
    with chain.vm.expect_revert("ERR_NOT_FOUND"):
        chain.c.get_latest_attestation("https://example.com/never")


def test_get_latest_invalid_url_reverts(chain):
    with chain.vm.expect_revert("ERR_INVALID_URL"):
        chain.c.get_latest_attestation("http://example.com/")


def test_failed_attest_does_not_move_latest_pointer(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/doc")
    chain.vm.clear_mocks()
    chain.page(r".*", 404, "gone")
    chain.attest(chain.alice, "https://example.com/doc")
    assert chain.c.get_latest_attestation("https://example.com/doc")["attestation_id"] == 1


# ============================================================================
# 5. Dead / failing pages -> typed status + refund into claimable_credits
# ============================================================================
@pytest.mark.parametrize("status,expected", [
    (400, "AMBIGUOUS_VOID"), (401, "AMBIGUOUS_VOID"), (403, "AMBIGUOUS_VOID"),
    (404, "AMBIGUOUS_VOID"), (405, "AMBIGUOUS_VOID"), (410, "AMBIGUOUS_VOID"),
    (418, "AMBIGUOUS_VOID"), (451, "AMBIGUOUS_VOID"),
    (429, "UNREACHABLE"), (500, "UNREACHABLE"), (502, "UNREACHABLE"),
    (503, "UNREACHABLE"), (504, "UNREACHABLE"), (599, "UNREACHABLE"),
    (100, "AMBIGUOUS_VOID"), (301, "AMBIGUOUS_VOID"), (304, "AMBIGUOUS_VOID"),
])
def test_http_failures_refund_fee_to_claimable_credits(chain, status, expected):
    chain.page(r".*", status, "<html><body>error page</body></html>")
    r = chain.attest(chain.bob, "https://example.com/missing")
    assert r["status"] == expected
    assert r["attestation_id"] == 0
    assert r["refunded"] == str(FEE)
    s = chain.state()
    assert s["attestation_count"] == "0"
    assert s["protocol_vault"] == "0"  # fee never reaches the vault
    assert s["total_credits"] == str(FEE)
    assert chain.c.claimable_of(chain.key(chain.bob)) == FEE
    assert chain.c.claimable_of(chain.key(chain.alice)) == 0
    with chain.vm.expect_revert("ERR_NOT_FOUND"):
        chain.c.get_latest_attestation("https://example.com/missing")
    chain.assert_invariants()


def test_unmocked_host_is_unreachable_or_void_and_refunds(chain):
    # no mock registered: the harness fails the request like a dead host
    r = chain.attest(chain.alice, "https://nothing-listens-here.example.com/")
    assert r["status"] in ("UNREACHABLE", "AMBIGUOUS_VOID")
    assert r["refunded"] == str(FEE)
    assert chain.c.claimable_of(chain.key(chain.alice)) == FEE
    chain.assert_invariants()


@pytest.mark.parametrize("body", [
    "", "   \n\t ", "<html><body></body></html>",
    "<html><body><script>only script</script></body></html>",
    "<html><body><nav>only nav</nav></body></html>",
    "<html><body><p>too short</p></body></html>",
])
def test_empty_or_non_document_page_is_ambiguous_void(chain, body):
    chain.page(r".*", 200, body)
    r = chain.attest(chain.alice, "https://example.com/empty")
    assert r["status"] == "AMBIGUOUS_VOID"
    assert chain.c.claimable_of(chain.key(chain.alice)) == FEE
    assert chain.state()["protocol_vault"] == "0"
    chain.assert_invariants()


def test_none_body_is_ambiguous_void(chain):
    chain.vm.mock_web(r".*", {"status": 200, "body": None})
    r = chain.attest(chain.alice, "https://example.com/")
    assert r["status"] == "AMBIGUOUS_VOID"


def test_refunds_accumulate_per_account(chain):
    chain.page(r".*", 404, "gone")
    for _ in range(3):
        chain.attest(chain.alice, "https://example.com/x")
    chain.attest(chain.bob, "https://example.com/y")
    assert chain.c.claimable_of(chain.key(chain.alice)) == 3 * FEE
    assert chain.c.claimable_of(chain.key(chain.bob)) == FEE
    assert chain.state()["total_credits"] == str(4 * FEE)
    chain.assert_invariants()


def test_claimable_of_is_case_insensitive_and_unknown_is_zero(chain):
    chain.page(r".*", 404, "gone")
    chain.attest(chain.alice, "https://example.com/x")
    k = chain.key(chain.alice)
    assert chain.c.claimable_of(k) == FEE
    assert chain.c.claimable_of(k.upper().replace("0X", "0x")) == FEE
    assert chain.c.claimable_of("0x" + "ab" * 20) == 0


# ============================================================================
# 6. Exact fee enforcement
# ============================================================================
@pytest.mark.parametrize("value", [0, 1, FEE - 1, FEE + 1, 2 * FEE, FEE // 2, 10**18])
def test_wrong_fee_reverts_and_changes_nothing(chain, value):
    chain.page(r".*", 200)
    with chain.vm.expect_revert("ERR_WRONG_FEE"):
        chain.attest(chain.alice, "https://example.com/", value=value)
    s = chain.state()
    assert s["attestation_count"] == "0"
    assert s["protocol_vault"] == "0"
    assert s["total_credits"] == "0"
    chain.assert_invariants()


def test_fee_constant(chain):
    assert chain.c.get_fee() == FEE == 50_000_000_000_000_000


def test_fee_is_checked_before_any_web_access(chain):
    # no web mock at all: a wrong fee must revert on the fee check, not on I/O
    with chain.vm.expect_revert("ERR_WRONG_FEE"):
        chain.attest(chain.alice, "https://example.com/", value=FEE + 1)


# ============================================================================
# 7. Solvency invariant across attests, refunds, withdrawals, sweeps
# ============================================================================
def test_invariant_holds_at_genesis(chain):
    s = chain.state()
    assert s["balance"] == "0" and s["protocol_vault"] == "0" and s["total_credits"] == "0"
    chain.assert_invariants()


def test_invariant_after_each_attestation(chain):
    chain.page(r".*", 200)
    for i in range(6):
        who = (chain.alice, chain.bob, chain.carol)[i % 3]
        chain.attest(who, f"https://example.com/p{i}")
        chain.assert_invariants()
    assert chain.state()["protocol_vault"] == str(6 * FEE)
    assert chain.mirror == 6 * FEE


def test_invariant_with_mixed_success_and_refund(chain):
    chain.page(r".*ok\.example\.com.*", 200)
    chain.page(r".*dead\.example\.com.*", 404, "gone")
    chain.page(r".*flaky\.example\.com.*", 503, "busy")
    plan = [("ok", chain.alice), ("dead", chain.bob), ("ok", chain.carol),
            ("flaky", chain.alice), ("dead", chain.alice), ("ok", chain.bob)]
    for host, who in plan:
        chain.attest(who, f"https://{host}.example.com/x")
        chain.assert_invariants()
    s = chain.state()
    assert s["protocol_vault"] == str(3 * FEE)
    assert s["total_credits"] == str(3 * FEE)
    assert s["attestation_count"] == "3"
    assert chain.mirror == 6 * FEE


def test_withdraw_pays_exactly_credits_and_keeps_invariant(chain):
    chain.page(r".*", 404, "gone")
    chain.attest(chain.bob, "https://example.com/x")
    chain.attest(chain.bob, "https://example.com/y")
    paid = chain.withdraw(chain.bob)
    assert paid == 2 * FEE
    assert chain.c.claimable_of(chain.key(chain.bob)) == 0
    assert chain.state()["total_credits"] == "0"
    assert chain.mirror == 0
    chain.assert_invariants()


def test_withdraw_does_not_touch_vault(chain):
    chain.page(r".*ok.*", 200)
    chain.page(r".*dead.*", 404, "x")
    chain.attest(chain.alice, "https://ok.example.com/")
    chain.attest(chain.bob, "https://dead.example.com/")
    chain.withdraw(chain.bob)
    assert chain.state()["protocol_vault"] == str(FEE)
    assert chain.mirror == FEE
    chain.assert_invariants()


def test_double_withdraw_reverts(chain):
    chain.page(r".*", 404, "x")
    chain.attest(chain.bob, "https://example.com/")
    chain.withdraw(chain.bob)
    with chain.vm.expect_revert("ERR_NOTHING_TO_WITHDRAW"):
        chain.withdraw(chain.bob)
    chain.assert_invariants()


def test_withdraw_with_no_credits_reverts(chain):
    with chain.vm.expect_revert("ERR_NOTHING_TO_WITHDRAW"):
        chain.withdraw(chain.carol)


def test_withdraw_only_pays_the_caller(chain):
    chain.page(r".*", 404, "x")
    chain.attest(chain.alice, "https://example.com/")
    chain.attest(chain.bob, "https://example.com/")
    assert chain.withdraw(chain.alice) == FEE
    assert chain.c.claimable_of(chain.key(chain.bob)) == FEE
    chain.assert_invariants()
    assert chain.withdraw(chain.bob) == FEE
    chain.assert_invariants()


def test_sweep_moves_vault_to_governor(chain):
    chain.page(r".*", 200)
    for i in range(3):
        chain.attest(chain.bob, f"https://example.com/p{i}")
    paid = chain.sweep(chain.alice)
    assert paid == 3 * FEE
    assert chain.state()["protocol_vault"] == "0"
    assert chain.mirror == 0
    chain.assert_invariants()


def test_sweep_never_touches_refund_credits(chain):
    chain.page(r".*ok.*", 200)
    chain.page(r".*dead.*", 404, "x")
    chain.attest(chain.bob, "https://ok.example.com/")
    chain.attest(chain.carol, "https://dead.example.com/")
    chain.sweep(chain.alice)
    assert chain.c.claimable_of(chain.key(chain.carol)) == FEE
    assert chain.mirror == FEE  # only the refund remains
    chain.assert_invariants()
    chain.withdraw(chain.carol)
    assert chain.mirror == 0
    chain.assert_invariants()


def test_sweep_with_empty_vault_reverts(chain):
    with chain.vm.expect_revert("ERR_NOTHING_TO_WITHDRAW"):
        chain.sweep(chain.alice)


def test_sweep_twice_reverts_second_time(chain):
    chain.page(r".*", 200)
    chain.attest(chain.bob, "https://example.com/")
    chain.sweep(chain.alice)
    with chain.vm.expect_revert("ERR_NOTHING_TO_WITHDRAW"):
        chain.sweep(chain.alice)


@pytest.mark.parametrize("who", ["bob", "carol"])
def test_sweep_is_governor_only(chain, who):
    chain.page(r".*", 200)
    chain.attest(chain.bob, "https://example.com/")
    with chain.vm.expect_revert("ERR_UNAUTHORIZED"):
        chain.sweep(getattr(chain, who))
    assert chain.state()["protocol_vault"] == str(FEE)
    chain.assert_invariants()


def test_interleaved_attest_sweep_withdraw_sequence(chain):
    chain.page(r".*ok.*", 200)
    chain.page(r".*dead.*", 404, "x")
    steps = [
        lambda: chain.attest(chain.alice, "https://ok.example.com/1"),
        lambda: chain.attest(chain.bob, "https://dead.example.com/1"),
        lambda: chain.attest(chain.carol, "https://ok.example.com/2"),
        lambda: chain.sweep(chain.alice),
        lambda: chain.attest(chain.bob, "https://dead.example.com/2"),
        lambda: chain.withdraw(chain.bob),
        lambda: chain.attest(chain.alice, "https://ok.example.com/3"),
        lambda: chain.attest(chain.carol, "https://dead.example.com/3"),
        lambda: chain.withdraw(chain.carol),
        lambda: chain.sweep(chain.alice),
    ]
    for step in steps:
        step()
        chain.assert_invariants()
    assert chain.mirror == 0
    assert chain.state()["attestation_count"] == "3"


def test_reverted_calls_do_not_perturb_accounting(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/ok")
    before = chain.state()
    with chain.vm.expect_revert("ERR_INVALID_URL"):
        chain.attest(chain.alice, "http://example.com/")
    with chain.vm.expect_revert("ERR_WRONG_FEE"):
        chain.attest(chain.alice, "https://example.com/ok", value=FEE * 2)
    with chain.vm.expect_revert("ERR_NOTHING_TO_WITHDRAW"):
        chain.withdraw(chain.bob)
    after = chain.state()
    assert {k: v for k, v in before.items() if k != "balance"} == {k: v for k, v in after.items() if k != "balance"}
    chain.assert_invariants()


@pytest.mark.parametrize("seed", range(6))
def test_randomized_operation_sequences_keep_solvency(chain, seed):
    import random
    rng = random.Random(seed)
    chain.page(r".*ok.*", 200)
    chain.page(r".*dead.*", 404, "x")
    chain.page(r".*busy.*", 503, "x")
    accounts = [chain.alice, chain.bob, chain.carol]
    for _ in range(25):
        op = rng.choice(["ok", "ok", "dead", "busy", "withdraw", "sweep"])
        who = rng.choice(accounts)
        try:
            if op in ("ok", "dead", "busy"):
                chain.attest(who, f"https://{op}.example.com/{rng.randint(0, 3)}")
            elif op == "withdraw":
                chain.withdraw(who)
            else:
                chain.sweep(chain.alice)
        except Exception:
            pass  # legitimate reverts (nothing to withdraw / sweep)
        chain.assert_invariants()


def test_ledger_identity_counters(chain):
    chain.page(r".*ok.*", 200)
    chain.page(r".*dead.*", 404, "x")
    chain.attest(chain.alice, "https://ok.example.com/")
    chain.attest(chain.bob, "https://dead.example.com/")
    s = chain.state()
    assert s["total_received"] == str(2 * FEE) and s["total_paid_out"] == "0"
    chain.withdraw(chain.bob)
    s = chain.state()
    assert s["total_received"] == str(2 * FEE) and s["total_paid_out"] == str(FEE)
    chain.sweep(chain.alice)
    s = chain.state()
    assert s["total_paid_out"] == str(2 * FEE)
    assert s["protocol_vault"] == "0" and s["total_credits"] == "0"
    assert s["ledger_conserved"] is True


def test_ledger_holds_even_if_chain_never_debits_payouts(chain):
    """Studio Next credits payout recipients without debiting the contract's
    native balance. The strict balance identity then drifts upward by exactly
    the cumulative payouts, while the ledger identity stays exact."""
    chain.page(r".*dead.*", 404, "x")
    chain.attest(chain.bob, "https://dead.example.com/")
    chain.vm.sender = chain.bob
    assert int(chain.c.pull_withdraw()) == FEE  # mirror deliberately NOT debited
    s = chain.state()
    assert s["ledger_conserved"] is True
    assert s["solvent"] is False  # strict identity is off on such a chain ...
    drift = int(s["balance"]) - int(s["protocol_vault"]) - int(s["total_credits"])
    assert drift == int(s["total_paid_out"]) == FEE  # ... by exactly what was paid out


def test_solvency_view_reflects_mirror(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/")
    assert chain.c.is_solvent() is True
    assert chain.state()["solvent"] is True
    chain.vm.deal(chain.addr, chain.mirror + 1)  # an unexplained surplus is detected
    assert chain.c.is_solvent() is False
    chain.vm.deal(chain.addr, chain.mirror - 1)  # so is a deficit
    assert chain.c.is_solvent() is False


# ============================================================================
# 8. verify_attestation / get_attestation views
# ============================================================================
def test_verify_attestation_exact_match(chain):
    chain.page(r".*", 200)
    r = chain.attest(chain.alice, "https://example.com/")
    h = r["content_hash"]
    assert chain.c.verify_attestation(1, h) is True
    assert chain.c.verify_attestation(1, h.upper()) is True
    assert chain.c.verify_attestation(1, "0x" + h) is True
    assert chain.c.verify_attestation(1, "  " + h + "  ") is True


@pytest.mark.parametrize("bad", [
    "", "0x", "deadbeef", "0" * 64, "f" * 64, "g" * 64, "z" * 63,
])
def test_verify_attestation_mismatch(chain, bad):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/")
    assert chain.c.verify_attestation(1, bad) is False


def test_verify_attestation_off_by_one_char(chain):
    chain.page(r".*", 200)
    h = chain.attest(chain.alice, "https://example.com/")["content_hash"]
    flipped = ("0" if h[0] != "0" else "1") + h[1:]
    assert chain.c.verify_attestation(1, flipped) is False
    assert chain.c.verify_attestation(1, h[:-1]) is False
    assert chain.c.verify_attestation(1, h + "0") is False


@pytest.mark.parametrize("attestation_id", [0, 2, 99, 2**64])
def test_verify_attestation_unknown_id_is_false(chain, attestation_id):
    chain.page(r".*", 200)
    h = chain.attest(chain.alice, "https://example.com/")["content_hash"]
    assert chain.c.verify_attestation(attestation_id, h) is False


def test_get_attestation_unknown_reverts(chain):
    with chain.vm.expect_revert("ERR_NOT_FOUND"):
        chain.c.get_attestation(1)


def test_attestation_is_immutable_after_later_activity(chain):
    chain.page(r".*", 200)
    snap = chain.attest(chain.alice, "https://example.com/")
    chain.attest(chain.bob, "https://example.com/other")
    chain.sweep(chain.alice)
    a = chain.c.get_attestation(1)
    assert a["content_hash"] == snap["content_hash"]
    assert a["attester"] == chain.key(chain.alice)
    assert a["fee_paid"] == str(FEE)


def test_attester_recorded_per_caller(chain):
    chain.page(r".*", 200)
    chain.attest(chain.alice, "https://example.com/a")
    chain.attest(chain.bob, "https://example.com/b")
    chain.attest(chain.carol, "https://example.com/c")
    assert chain.c.get_attestation(1)["attester"] == chain.key(chain.alice)
    assert chain.c.get_attestation(2)["attester"] == chain.key(chain.bob)
    assert chain.c.get_attestation(3)["attester"] == chain.key(chain.carol)


def test_timestamp_tracks_block_clock(chain):
    chain.page(r".*", 200)
    chain.vm.warp("2026-01-01T00:00:00+00:00")
    chain.attest(chain.alice, "https://example.com/a")
    chain.vm.warp("2026-06-01T00:00:00+00:00")
    chain.attest(chain.alice, "https://example.com/b")
    t1, t2 = chain.c.get_attestation(1)["timestamp"], chain.c.get_attestation(2)["timestamp"]
    assert t1 == 1767225600
    assert t2 > t1


# ============================================================================
# 9. Governance
# ============================================================================
def test_deployer_is_governor(chain):
    assert chain.c.get_governor() == chain.key(chain.alice)


def test_transfer_governor_then_old_governor_loses_sweep(chain):
    chain.page(r".*", 200)
    chain.attest(chain.carol, "https://example.com/")
    chain.vm.sender = chain.alice
    chain.c.transfer_governor(chain.key(chain.bob))
    assert chain.c.get_governor() == chain.key(chain.bob)
    with chain.vm.expect_revert("ERR_UNAUTHORIZED"):
        chain.sweep(chain.alice)
    assert chain.sweep(chain.bob) == FEE
    chain.assert_invariants()


def test_transfer_governor_requires_governor(chain):
    chain.vm.sender = chain.bob
    with chain.vm.expect_revert("ERR_UNAUTHORIZED"):
        chain.c.transfer_governor(chain.key(chain.bob))
    assert chain.c.get_governor() == chain.key(chain.alice)


def test_transfer_governor_rejects_zero_address(chain):
    chain.vm.sender = chain.alice
    with chain.vm.expect_revert("ERR_UNAUTHORIZED"):
        chain.c.transfer_governor("0x" + "0" * 40)
    assert chain.c.get_governor() == chain.key(chain.alice)


# ============================================================================
# 10. Validator consensus (run_validator replays the captured validator_fn)
# ============================================================================
def _leader_attest(chain, url="https://example.com/doc"):
    chain.vm.clear_validators()
    return chain.attest(chain.alice, url)


def test_validator_agrees_on_identical_page(chain):
    chain.page(r".*", 200)
    _leader_attest(chain)
    assert chain.vm.run_validator() is True


def test_validator_agrees_despite_different_ads_and_scripts(chain):
    chain.page(r".*", 200, html_page(LONG_TEXT, "Doc", "leader-ad-1"))
    _leader_attest(chain)
    chain.vm.clear_mocks()
    chain.page(r".*", 200, html_page(LONG_TEXT, "Doc", "validator-ad-2"))
    assert chain.vm.run_validator() is True


def test_validator_disagrees_when_body_differs(chain):
    chain.page(r".*", 200, html_page(LONG_TEXT, "Doc"))
    _leader_attest(chain)
    chain.vm.clear_mocks()
    chain.page(r".*", 200, html_page(LONG_TEXT + " tampered", "Doc"))
    assert chain.vm.run_validator() is False


def test_validator_disagrees_when_title_differs(chain):
    chain.page(r".*", 200, html_page(LONG_TEXT, "Doc A"))
    _leader_attest(chain)
    chain.vm.clear_mocks()
    chain.page(r".*", 200, html_page(LONG_TEXT, "Doc B"))
    assert chain.vm.run_validator() is False


def test_validator_disagrees_if_page_vanished_for_validator(chain):
    chain.page(r".*", 200)
    _leader_attest(chain)
    chain.vm.clear_mocks()
    chain.page(r".*", 404, "gone")
    assert chain.vm.run_validator() is False


def test_validator_disagrees_if_leader_failed_but_page_exists(chain):
    chain.page(r".*", 404, "gone")
    _leader_attest(chain)
    chain.vm.clear_mocks()
    chain.page(r".*", 200)
    assert chain.vm.run_validator() is False


@pytest.mark.parametrize("leader_status,validator_status,agree", [
    (404, 404, True), (404, 410, True), (403, 404, True),
    (500, 503, True), (503, 429, True), (502, 502, True),
    (404, 500, False), (500, 404, False), (410, 502, False),
])
def test_validator_failure_class_agreement(chain, leader_status, validator_status, agree):
    chain.page(r".*", leader_status, "x")
    _leader_attest(chain)
    chain.vm.clear_mocks()
    chain.page(r".*", validator_status, "x")
    assert chain.vm.run_validator() is agree


def test_validator_rejects_forged_leader_hash(chain):
    chain.page(r".*", 200)
    _leader_attest(chain)
    forged = {"ok": True, "code": "ATTESTED", "hash": "0" * 64, "title": "Sample Document", "snippet": "x"}
    assert chain.vm.run_validator(leader_result=forged) is False


def test_validator_rejects_forged_success_for_dead_page(chain):
    chain.page(r".*", 404, "gone")
    _leader_attest(chain)
    forged = {"ok": True, "code": "ATTESTED", "hash": "a" * 64, "title": "t", "snippet": "s"}
    assert chain.vm.run_validator(leader_result=forged) is False


@pytest.mark.parametrize("garbage", [None, {}, {"hash": "x"}, [], "str", 7])
def test_validator_rejects_malformed_leader_result(chain, garbage):
    chain.page(r".*", 200)
    _leader_attest(chain)
    assert chain.vm.run_validator(leader_result=garbage) is False


def test_validator_disagrees_when_leader_errors(chain):
    chain.page(r".*", 200)
    _leader_attest(chain)
    assert chain.vm.run_validator(leader_error=Exception("leader crashed")) is False


# ============================================================================
# 11. Repository gates
# ============================================================================
def test_runner_pinned_not_floating():
    first = (ROOT / CONTRACT).read_text().splitlines()[:3]
    dep = [ln for ln in first if "Depends" in ln][0]
    assert re.search(r"py-genlayer:[0-9a-z]{40,}", dep)
    assert "latest" not in dep and ":test" not in dep


def test_no_float_or_randomness_in_contract_source():
    src = (ROOT / CONTRACT).read_text()
    assert "import random" not in src
    assert "float(" not in src
    assert "time.time" not in src


@pytest.mark.skipif(shutil.which("genvm-lint") is None and not (Path(sys.prefix) / "bin" / "genvm-lint").exists(),
                    reason="genvm-lint not installed")
def test_genvm_lint_reports_zero_errors():
    exe = shutil.which("genvm-lint") or str(Path(sys.prefix) / "bin" / "genvm-lint")
    proc = subprocess.run([exe, "check", CONTRACT], cwd=ROOT, capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "Lint passed" in out
    assert "Validation passed" in out
    assert "\u2718" not in out and "\u2717" not in out  # no failed-check marks
