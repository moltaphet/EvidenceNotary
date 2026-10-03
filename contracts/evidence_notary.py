# v0.1.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }

# EvidenceNotary -- Consensus Web Attestation Protocol (revision 2: dual hashing).
# NOTE: line 1 is the GenVM version tag, not this contract's revision; leave it.
#
# A decentralized web notarization / proof-of-existence protocol. Anyone (an EOA
# or another contract) pays an exact anti-spam fee and asks the validator set to
# read an https page. Every validator independently fetches the page, strips the
# non-document chrome (scripts, styles, navigation, cookie banners, ads), folds
# the remaining prose into a canonical form and hashes it with SHA-256. The
# attestation is recorded only if the validators agree on that hash.
#
# Two hashes are recorded per attestation. `raw_sha256` covers the exact bytes the
# validator received; `normalized_sha256` covers the canonical visible text of an
# HTML / text document. For binary media (PDF, images, archives ...) the body is
# never decoded and both hashes are the raw hash, so no byte-collision can hide
# behind a lossy text decode. Nothing is silently truncated: a body over
# MAX_PAYLOAD_BYTES is rejected as UNREACHABLE_OVERSIZE (penalized like any
# failed fetch, see below).
#
# Failure path: a dead / 4xx / 5xx page does NOT revert. A revert would roll the
# fee transfer back to the caller's wallet but leave no on-chain trace; the
# protocol instead returns a typed status (UNREACHABLE / AMBIGUOUS_VOID) and
# keeps a non-refundable 20% validator-bandwidth fee in `protocol_vault` and moves
# the remaining 80% into `claimable_credits`, a pull-pattern refund the payer
# collects with `pull_withdraw()`. Configuration errors (bad URL, wrong fee) do
# revert, which returns the attached value to the sender at the VM level.
#
# Solvency invariant (see README, section 4):
#       self.balance == protocol_vault + total_credits
# where total_credits == sum(claimable_credits.values()), maintained as a
# running counter so the identity is O(1) to check.
#
# Chain-independent companion (the ledger identity):
#       total_received == protocol_vault + total_credits + total_paid_out
# It involves only counters this contract writes, so it holds on every chain,
# including ones whose emit_transfer does not debit the contract's native
# balance at settlement (measured on Studio Next, see README 4.3). When the
# chain debits payouts, total_paid_out is exactly the amount already gone from
# self.balance and the two identities coincide.

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser

import genlayer as gl
from genlayer import Address, u256
from genlayer.storage import TreeMap

# genvm-lint matches the bare name `allow_storage` on storage dataclasses.
allow_storage = gl.storage.allow

# --- Protocol constants -------------------------------------------------------
ATTESTATION_FEE = 50_000_000_000_000_000  # 0.05 GEN, in atto-GEN
FAILED_FEE_RETAINED = ATTESTATION_FEE // 5  # 20% = 0.01 GEN stays in the vault
FAILED_FEE_REFUNDED = ATTESTATION_FEE - FAILED_FEE_RETAINED  # 80% = 0.04 GEN
SNIPPET_CHARS = 200
MAX_URL_CHARS = 2048
# Hard cap on the raw response body. 4 MiB, not 2 MiB: the RFC 9000 page this
# protocol is expected to notarize is ~3.0 MB of HTML. Over the cap -> penalized failure.
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MIN_TEXT_CHARS = 40  # below this an HTML/text page carries no notarizable document

# --- Error classification -----------------------------------------------------
ERR_URL = "[EXPECTED] ERR_INVALID_URL"
ERR_FEE = "[EXPECTED] ERR_WRONG_FEE"
ERR_NOT_FOUND = "[EXPECTED] ERR_NOT_FOUND"
ERR_UNAUTHORIZED = "[EXPECTED] ERR_UNAUTHORIZED"
ERR_NOTHING = "[EXPECTED] ERR_NOTHING_TO_WITHDRAW"
ERR_TRANSFER = "[EXPECTED] ERR_TRANSFER_FAILED"

# --- Attestation outcomes -----------------------------------------------------
STATUS_ATTESTED = "ATTESTED"
STATUS_UNREACHABLE = "UNREACHABLE"  # transport failure, timeout, HTTP 5xx / 429
STATUS_AMBIGUOUS_VOID = "AMBIGUOUS_VOID"  # HTTP 4xx, empty or non-document page
STATUS_OVERSIZE = "UNREACHABLE_OVERSIZE"  # raw body over MAX_PAYLOAD_BYTES: unprocessable, penalized

KIND_HTML = "html"
KIND_TEXT = "text"
KIND_BINARY = "binary"


# ------------------------------------------------------------------------------
# URL canonicalization (pure, deterministic, no network)
# ------------------------------------------------------------------------------
class UrlRejected(Exception):
    pass


_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_NUMERIC_LABEL_RE = re.compile(r"^(0[xX][0-9a-fA-F]*|[0-9]+)$")
_BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".intranet", ".lan", ".home",
    ".corp", ".private", ".localdomain", ".arpa",
)


def _is_forbidden_ipv4(octets: list) -> bool:
    a, b = octets[0], octets[1]
    if a == 0 or a == 10 or a == 127 or a >= 224:
        return True
    if a == 100 and 64 <= b <= 127:  # carrier-grade NAT
        return True
    if a == 169 and b == 254:  # link-local / cloud metadata
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 192 and b == 0:  # IETF protocol / documentation
        return True
    if a == 198 and b in (18, 19):  # benchmarking
        return True
    return False


def _check_host(host: str) -> str:
    if host == "" or len(host) > 253:
        raise UrlRejected("empty or oversized host")
    if host.endswith("."):
        host = host[:-1]
    if not _HOST_RE.match(host):
        raise UrlRejected("host must be lowercase ASCII letters, digits, hyphen, dot")
    if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise UrlRejected("local host name")
    labels = host.split(".")
    last = labels[-1]
    # Every purely numeric / hex-looking terminal label is an IP-literal attempt
    # (decimal 2130706433, hex 0x7f000001, octal 0177.0.0.1, short 127.1 ...).
    if _NUMERIC_LABEL_RE.match(last):
        if len(labels) != 4:
            raise UrlRejected("non-canonical numeric host")
        octets = []
        for lab in labels:
            if not lab.isdigit() or (len(lab) > 1 and lab[0] == "0") or len(lab) > 3:
                raise UrlRejected("non-canonical numeric host")
            n = int(lab)
            if n > 255:
                raise UrlRejected("non-canonical numeric host")
            octets.append(n)
        if _is_forbidden_ipv4(octets):
            raise UrlRejected("private or reserved address")
    elif "." not in host:
        raise UrlRejected("single-label host")
    return host


def _normalize_path(path: str) -> str:
    out = []
    for seg in path.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return "/" + "/".join(out)


def canonicalize_url(url) -> str:
    """Canonical form `https://host/path[?query]`, or raises UrlRejected.

    lowercase host; leading `www.` stripped; default port 443 dropped; fragment
    dropped; dot-segments and duplicate / trailing slashes folded; query pairs
    sorted so equivalent queries deduplicate. Rejects non-https, userinfo,
    non-default ports, IPv6 literals, numeric IPv4 tricks, private / loopback /
    link-local / reserved ranges, and local host names."""
    if not isinstance(url, str):
        raise UrlRejected("url must be a string")
    s = url.strip()
    if s == "" or len(s) > MAX_URL_CHARS:
        raise UrlRejected("empty or oversized url")
    for ch in s:
        if ord(ch) <= 0x20 or ord(ch) == 0x7F or ch == "\\":
            raise UrlRejected("whitespace, control or backslash character")
    if s[:8].lower() != "https://":
        raise UrlRejected("only https is accepted")
    rest = s[8:]
    # Strip the fragment first, then split authority from the rest.
    rest = rest.split("#", 1)[0]
    cut = len(rest)
    for sep in "/?":
        i = rest.find(sep)
        if i != -1 and i < cut:
            cut = i
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        raise UrlRejected("userinfo is not allowed")
    if authority.startswith("[") or "[" in authority or "]" in authority:
        raise UrlRejected("IPv6 literals are not allowed")
    host = authority
    if ":" in authority:
        host, port = authority.rsplit(":", 1)
        if port != "443":
            raise UrlRejected("only the default https port is accepted")
    host = _check_host(host.lower())
    if host.startswith("www."):
        host = host[4:]
        if host == "" or "." not in host:
            raise UrlRejected("single-label host")
        host = _check_host(host)
    path_part, _, query = tail.partition("?")
    if "%2e" in path_part.lower() or "%2f" in path_part.lower() or "%5c" in path_part.lower():
        raise UrlRejected("encoded dot or slash in path")
    path = _normalize_path(path_part)
    out = "https://" + host + path
    pairs = [p for p in query.split("&") if p != ""]
    if pairs:
        out += "?" + "&".join(sorted(pairs))
    return out


# ------------------------------------------------------------------------------
# Deterministic document extraction (pure, no network)
# ------------------------------------------------------------------------------
# Only strictly non-renderable tags are dropped. Navigation, footers, banners,
# asides and anything selected by class / id stay in the text: a notary must not
# decide which clauses, prices or warranties are "boilerplate".
_DROP_TAGS = frozenset(("script", "style", "noscript", "svg", "canvas"))
_VOID_TAGS = frozenset((
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
))
_BLOCK_TAGS = frozenset((
    "p", "div", "section", "article", "main", "li", "ul", "ol", "dl", "dt",
    "dd", "tr", "td", "th", "table", "pre", "blockquote", "h1", "h2", "h3",
    "h4", "h5", "h6", "br", "hr", "figure", "figcaption", "details",
    "summary", "nav", "header", "footer", "aside", "form", "label", "option",
))


class _DocExtractor(HTMLParser):
    """Collects every rendered text node of the document, in document order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.in_title = False
        self.in_head = False
        self.skip_depth = 0
        self.skip_stack = []
        self.chunks = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        elif tag == "head":
            self.in_head = True
        elif tag == "body":
            self.in_head = False
        if tag in _VOID_TAGS:
            if tag in _BLOCK_TAGS:
                self.chunks.append(" ")
            return
        if self.skip_depth > 0 or tag in _DROP_TAGS:
            self.skip_stack.append(tag)
            self.skip_depth += 1
            return
        if tag in _BLOCK_TAGS:
            self.chunks.append(" ")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "head":
            self.in_head = False
        if tag in _VOID_TAGS:
            return
        if self.skip_depth > 0:
            # unwind to the matching open tag if present (tolerates sloppy HTML)
            if tag in self.skip_stack:
                while self.skip_stack:
                    top = self.skip_stack.pop()
                    self.skip_depth -= 1
                    if top == tag:
                        break
            return
        if tag in _BLOCK_TAGS:
            self.chunks.append(" ")

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.skip_depth > 0 or self.in_head:
            return
        self.chunks.append(data)


def normalize_text(text: str) -> str:
    """Canonical text: NFKC, unified quotes / dashes / spaces, zero-width and
    control characters removed, runs of whitespace folded to one space."""
    t = unicodedata.normalize("NFKC", text)
    t = (
        t.replace("\u2018", "'").replace("\u2019", "'")
        .replace("\u201c", '"').replace("\u201d", '"')
        .replace("\u2013", "-").replace("\u2014", "-").replace("\u2212", "-")
    )
    out = []
    for ch in t:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Co", "Cs"):  # zero-width, format, private-use
            continue
        if ch.isspace() or cat in ("Zs", "Zl", "Zp") or ch in ("\t", "\n", "\r", "\x0b", "\x0c"):
            out.append(" ")
        elif cat == "Cc":
            continue
        else:
            out.append(ch)
    return " ".join("".join(out).split())


def extract_html(body: str) -> dict:
    """Returns {"title", "text"}: normalized title and all rendered body text."""
    p = _DocExtractor()
    try:
        p.feed(body)
        p.close()
    except Exception:
        pass  # the parser is tolerant; whatever was collected so far is used
    return {
        "title": normalize_text("".join(p.title_parts)),
        "text": normalize_text("".join(p.chunks)),
    }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash_of(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def _norm_hash(h) -> str:
    if not isinstance(h, str):
        return ""
    s = h.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


_HTML_TYPES = ("text/html", "application/xhtml+xml")
_TEXT_TYPES = ("application/json", "application/xml", "application/ld+json", "application/javascript")


def _content_type(headers) -> str:
    """Lowercased media type without parameters, "" if absent."""
    try:
        for k, v in headers.items():
            name = k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
            if name.lower() == "content-type":
                val = v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v)
                return val.split(";", 1)[0].strip().lower()
    except Exception:
        pass
    return ""


def classify_content(ctype: str, body: bytes) -> str:
    """KIND_HTML, KIND_TEXT or KIND_BINARY. Binary bodies are never text-decoded."""
    if ctype in _HTML_TYPES:
        return KIND_HTML
    if ctype.startswith("text/") or ctype in _TEXT_TYPES or (
        ctype.endswith("+json") or (ctype.endswith("+xml") and ctype != "image/svg+xml")
    ):
        # a declared text type whose bytes are not valid UTF-8 is not safely text
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            return KIND_BINARY
        return KIND_TEXT
    if ctype != "":
        return KIND_BINARY
    # No Content-Type: sniff. Valid UTF-8 is text (html if it looks like it).
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return KIND_BINARY
    if "\x00" in text[:1024]:
        return KIND_BINARY
    head = text[:20000].lower()
    if "<html" in head or "<!doctype html" in head or "<body" in head or "<title" in head:
        return KIND_HTML
    return KIND_TEXT


# ------------------------------------------------------------------------------
# Web read (runs inside the non-deterministic block on every validator)
# ------------------------------------------------------------------------------
def _read_page(canonical_url: str) -> dict:
    """Never raises. Returns a primitive-only dict so it is calldata-encodable:
    {"ok", "code", "kind", "raw", "norm", "title", "snippet", "size"}."""
    def fail(code):
        return {"ok": False, "code": code, "kind": "", "raw": "", "norm": "", "title": "", "snippet": "", "size": 0}

    try:
        res = gl.nondet.web.get(canonical_url)
    except Exception:
        return fail(STATUS_UNREACHABLE)
    status = getattr(res, "status", None)
    if status is None:
        status = getattr(res, "status_code", None)
    if not isinstance(status, int):
        return fail(STATUS_UNREACHABLE)
    if status == 429 or status >= 500:
        return fail(STATUS_UNREACHABLE)
    if status < 200 or status >= 300:
        return fail(STATUS_AMBIGUOUS_VOID)
    body = res.body
    if body is None:
        return fail(STATUS_AMBIGUOUS_VOID)
    if isinstance(body, str):
        body = body.encode("utf-8")
    elif isinstance(body, (bytes, bytearray)):
        body = bytes(body)
    else:
        return fail(STATUS_AMBIGUOUS_VOID)
    if len(body) > MAX_PAYLOAD_BYTES:
        return fail(STATUS_OVERSIZE)
    if len(body) == 0:
        return fail(STATUS_AMBIGUOUS_VOID)

    raw = sha256_hex(body)
    kind = classify_content(_content_type(getattr(res, "headers", None) or {}), body)
    if kind == KIND_BINARY:
        # No decoding of any kind: both hashes are the hash of the exact bytes.
        return {"ok": True, "code": STATUS_ATTESTED, "kind": kind, "raw": raw, "norm": raw,
                "title": "", "snippet": "", "size": len(body)}
    decoded = body.decode("utf-8", errors="replace")
    if kind == KIND_HTML:
        doc = extract_html(decoded)
    else:
        doc = {"title": "", "text": normalize_text(decoded)}
    text = doc["text"]
    if len(text) < MIN_TEXT_CHARS:
        return fail(STATUS_AMBIGUOUS_VOID)
    return {
        "ok": True,
        "code": STATUS_ATTESTED,
        "kind": kind,
        "raw": raw,
        "norm": content_hash_of(text),
        "title": doc["title"][:300],
        "snippet": text[:SNIPPET_CHARS],
        "size": len(body),
    }


def _read_equivalent(leader: dict, mine: dict) -> bool:
    """Validator agreement predicate.

    Successful reads must agree on content kind, the normalized hash, the
    title and the 200-character snippet; binary reads must additionally agree on the raw hash (it is their
    only hash). For HTML / text the raw hash is the leader's own measurement:
    live markup carries per-request tokens, so validators vouch for the
    normalized text, not for byte-identical markup. Failed reads must agree on
    the failure class."""
    if not isinstance(leader, dict) or "ok" not in leader:
        return False
    if leader["ok"] != mine["ok"]:
        return False
    if not mine["ok"]:
        return leader.get("code") == mine["code"]
    if leader.get("kind") != mine["kind"]:
        return False
    if leader.get("norm") != mine["norm"] or leader.get("title") != mine["title"]:
        return False
    # The snippet is derived from the normalized text, so every honest validator
    # computes the same one; a leader cannot attach an unvetted excerpt.
    if leader.get("snippet") != mine["snippet"]:
        return False
    if mine["kind"] == KIND_BINARY and leader.get("raw") != mine["raw"]:
        return False
    return True


def is_raw_hash_verified(kind: str) -> bool:
    """True only for binary media. There every validator compares `raw_sha256`
    (it is the sole hash), so it is a Byzantine-consensus proof. For HTML / text
    consensus is bounded to the normalized text (`normalized_sha256`, `title`,
    `text_snippet`); `raw_sha256` and `size_bytes` are the LEADER'S reported
    telemetry about markup that carries per-request noise, and are informational."""
    return kind == KIND_BINARY


@allow_storage
@dataclass
class Attestation:
    """On-chain record. Consensus-proven fields: canonical_url, normalized_sha256,
    text_snippet, title and content_kind (all html / text), plus raw_sha256 for
    binary. Leader-reported telemetry (html / text only): raw_sha256, size_bytes
    -- see `is_raw_hash_verified`. Chain-supplied: timestamp, attester, fee_paid.
    """

    attestation_id: u256
    canonical_url: str
    raw_sha256: str  # hex SHA-256 of exact bytes; validator-verified for binary only, informational for html/text
    normalized_sha256: str  # hex SHA-256 of the normalized text (== raw for binary)
    content_kind: str  # KIND_HTML | KIND_TEXT | KIND_BINARY
    size_bytes: u256  # length of the raw response body
    title: str
    text_snippet: str  # first 200 characters of the verified text
    timestamp: u256  # block timestamp, unix seconds
    attester: str  # msg.sender, 0x-hex
    fee_paid: u256


class EvidenceNotary(gl.contract.Contract):
    attestations: TreeMap[u256, Attestation]
    url_to_latest_id: TreeMap[str, u256]
    protocol_vault: u256
    claimable_credits: TreeMap[str, u256]
    total_credits: u256  # == sum(claimable_credits.values())
    attestation_count: u256
    governor: Address
    total_received: u256  # cumulative fees accepted (every attest call)
    total_paid_out: u256  # cumulative amount handed to emit_transfer

    def __init__(self):
        self.protocol_vault = 0
        self.total_credits = 0
        self.attestation_count = 0
        self.total_received = 0
        self.total_paid_out = 0
        self.governor = gl.message.sender_address

    # ------------------------------------------------------------------ views
    @gl.public.view
    def get_fee(self) -> u256:
        return ATTESTATION_FEE

    @gl.public.view
    def get_limits(self) -> dict:
        return {
            "fee": str(ATTESTATION_FEE),
            "failed_fee_retained": str(FAILED_FEE_RETAINED),
            "failed_fee_refunded": str(FAILED_FEE_REFUNDED),
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
        }

    @gl.public.view
    def get_governor(self) -> str:
        return self._key(self.governor)

    @gl.public.view
    def whoami(self) -> str:
        return self._key(gl.message.sender_address)

    @gl.public.view
    def canonicalize(self, url: str) -> str:
        """Canonical form of `url`; reverts with ERR_INVALID_URL if rejected."""
        try:
            return canonicalize_url(url)
        except UrlRejected as e:
            raise gl.vm.UserError(f"{ERR_URL} {e}")

    @gl.public.view
    def get_protocol_state(self) -> dict:
        return {
            "balance": str(self.balance),
            "protocol_vault": str(self.protocol_vault),
            "total_credits": str(self.total_credits),
            "attestation_count": str(self.attestation_count),
            "total_received": str(self.total_received),
            "total_paid_out": str(self.total_paid_out),
            "solvent": self.balance == self.protocol_vault + self.total_credits,
            "ledger_conserved": self._ledger_conserved(),
        }

    @gl.public.view
    def is_solvent(self) -> bool:
        return self.balance == self.protocol_vault + self.total_credits

    @gl.public.view
    def is_ledger_conserved(self) -> bool:
        return self._ledger_conserved()

    @gl.public.view
    def claimable_of(self, account_hex: str) -> u256:
        key = account_hex.lower()
        if key in self.claimable_credits:
            return self.claimable_credits[key]
        return 0

    @gl.public.view
    def get_attestation(self, attestation_id: u256) -> dict:
        if attestation_id not in self.attestations:
            raise gl.vm.UserError(f"{ERR_NOT_FOUND} attestation {attestation_id}")
        return self._as_dict(self.attestations[attestation_id])

    @gl.public.view
    def verify_attestation(self, attestation_id: u256, expected_hash: str) -> bool:
        """True iff the attestation exists and `expected_hash` equals the hash that
        VALIDATORS agreed on for its content kind (hex SHA-256; a `0x` prefix and
        letter case are not significant):

        * KIND_BINARY: `raw_sha256` (all validators compared it).
        * KIND_HTML / KIND_TEXT: `normalized_sha256`, the consensus-verified text
          hash. `raw_sha256` of an HTML page is the leader's own measurement of
          markup that carries per-request noise; it is informational metadata and
          is deliberately NOT accepted here, so an unvetted leader value can
          never be treated as canon.

        This is the integration primitive: pin an `attestation_id`, then verify."""
        if attestation_id not in self.attestations:
            return False
        want = _norm_hash(expected_hash)
        if len(want) != 64:
            return False
        a = self.attestations[attestation_id]
        if a.content_kind == KIND_BINARY:
            return want == a.raw_sha256
        return want == a.normalized_sha256

    @gl.public.view
    def get_latest_attestation(self, url: str) -> dict:
        """Latest attestation of `url` (canonicalized first).

        INFORMATIONAL ONLY. `latest` is an append-only index that ANYONE can
        advance by paying the fee and attesting the same URL, so it must never
        gate escrow release or any condition check. Pin an attestation_id and
        use verify_attestation instead."""
        try:
            canon = canonicalize_url(url)
        except UrlRejected as e:
            raise gl.vm.UserError(f"{ERR_URL} {e}")
        if canon not in self.url_to_latest_id:
            raise gl.vm.UserError(f"{ERR_NOT_FOUND} no attestation for {canon}")
        return self._as_dict(self.attestations[self.url_to_latest_id[canon]])

    # ----------------------------------------------------------------- writes
    @gl.public.write.payable
    def attest(self, url: str) -> dict:
        """Notarize `url`. Requires exactly ATTESTATION_FEE attached.

        Returns {"status", "attestation_id", ...}. status is ATTESTED on
        consensus. Otherwise (UNREACHABLE / AMBIGUOUS_VOID) nothing is recorded,
        20% of the fee (FAILED_FEE_RETAINED) stays in the vault as non-refundable
        validator bandwidth and 80% moves to the caller's claimable credits. A body
        over MAX_PAYLOAD_BYTES is an unprocessable payload and takes the same path
        with status UNREACHABLE_OVERSIZE: it never reverts, so downloading
        oversized bodies is never free."""
        if gl.message.value != ATTESTATION_FEE:
            raise gl.vm.UserError(f"{ERR_FEE} expected {ATTESTATION_FEE}")
        try:
            canon = canonicalize_url(url)
        except UrlRejected as e:
            raise gl.vm.UserError(f"{ERR_URL} {e}")

        def leader_fn():
            return _read_page(canon)

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            mine = _read_page(canon)
            if not isinstance(leaders_res, gl.vm.Return):
                return False  # leader crashed; the validator's own read decides nothing
            return _read_equivalent(leaders_res.calldata, mine)

        result = gl.vm.run_nondet(leader_fn, validator_fn)

        # No revert is possible past this point, so state is mutated only here.
        self.total_received += ATTESTATION_FEE
        sender = self._key(gl.message.sender_address)
        if not result["ok"]:
            self.protocol_vault += FAILED_FEE_RETAINED
            self._credit(sender, FAILED_FEE_REFUNDED)
            return {
                "status": result["code"],
                "attestation_id": 0,
                "canonical_url": canon,
                "retained": str(FAILED_FEE_RETAINED),
                "refunded": str(FAILED_FEE_REFUNDED),
            }

        att_id = self.attestation_count + 1
        self.attestation_count = att_id
        self.attestations[att_id] = Attestation(
            attestation_id=att_id,
            canonical_url=canon,
            raw_sha256=result["raw"],
            normalized_sha256=result["norm"],
            content_kind=result["kind"],
            size_bytes=result["size"],
            title=result["title"],
            text_snippet=result["snippet"],
            timestamp=self._now(),
            attester=sender,
            fee_paid=ATTESTATION_FEE,
        )
        self.url_to_latest_id[canon] = att_id
        self.protocol_vault += ATTESTATION_FEE
        return {
            "status": STATUS_ATTESTED,
            "attestation_id": int(att_id),
            "canonical_url": canon,
            "raw_sha256": result["raw"],
            "is_raw_hash_verified": is_raw_hash_verified(result["kind"]),
            "normalized_sha256": result["norm"],
            "content_kind": result["kind"],
            "title": result["title"],
            "retained": str(ATTESTATION_FEE),
            "refunded": "0",
        }

    @gl.public.write
    def pull_withdraw(self) -> str:
        """Pay out the caller's refunded credits (checks-effects-interactions)."""
        key = self._key(gl.message.sender_address)
        if key not in self.claimable_credits or self.claimable_credits[key] == 0:
            raise gl.vm.UserError(f"{ERR_NOTHING}")
        amount = self.claimable_credits[key]
        self.claimable_credits[key] = 0
        self.total_credits -= amount
        self.total_paid_out += amount
        try:
            gl.chain.Account(gl.message.sender_address).emit_transfer(amount, on="finalized")
        except Exception:
            self.claimable_credits[key] = amount
            self.total_credits += amount
            self.total_paid_out -= amount
            raise gl.vm.UserError(f"{ERR_TRANSFER}")
        return str(amount)

    @gl.public.write
    def sweep_vault(self) -> str:
        """Governor-only: transfer the whole protocol vault to the governor."""
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")
        amount = self.protocol_vault
        if amount == 0:
            raise gl.vm.UserError(f"{ERR_NOTHING}")
        self.protocol_vault = 0
        self.total_paid_out += amount
        try:
            gl.chain.Account(self.governor).emit_transfer(amount, on="finalized")
        except Exception:
            self.protocol_vault = amount
            self.total_paid_out -= amount
            raise gl.vm.UserError(f"{ERR_TRANSFER}")
        return str(amount)

    @gl.public.write
    def transfer_governor(self, new_governor_hex: str) -> None:
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")
        if new_governor_hex.lower() == "0x0000000000000000000000000000000000000000":
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor cannot be the zero address")
        self.governor = Address(new_governor_hex)

    # --------------------------------------------------------------- internals
    def _ledger_conserved(self) -> bool:
        return self.total_received == self.protocol_vault + self.total_credits + self.total_paid_out

    def _key(self, addr: Address) -> str:
        return addr.as_hex.lower()

    def _credit(self, key: str, amount: int) -> None:
        if key in self.claimable_credits:
            self.claimable_credits[key] = self.claimable_credits[key] + amount
        else:
            self.claimable_credits[key] = amount
        self.total_credits += amount

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _as_dict(self, a: Attestation) -> dict:
        """Record as a dict. `is_raw_hash_verified` is True only for binary media;
        for html / text, `raw_sha256` and `size_bytes` are leader-reported
        telemetry, while `normalized_sha256` and `text_snippet` are validator-
        consensus proofs."""
        return {
            "attestation_id": int(a.attestation_id),
            "canonical_url": a.canonical_url,
            "raw_sha256": a.raw_sha256,
            "is_raw_hash_verified": is_raw_hash_verified(a.content_kind),
            "normalized_sha256": a.normalized_sha256,
            "content_kind": a.content_kind,
            "size_bytes": int(a.size_bytes),
            "title": a.title,
            "text_snippet": a.text_snippet,
            "timestamp": int(a.timestamp),
            "attester": a.attester,
            "fee_paid": str(a.fee_paid),
        }
