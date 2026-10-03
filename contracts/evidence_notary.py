# v0.1.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }

# EvidenceNotary -- Consensus Web Attestation Protocol.
#
# A decentralized web notarization / proof-of-existence protocol. Anyone (an EOA
# or another contract) pays an exact anti-spam fee and asks the validator set to
# read an https page. Every validator independently fetches the page, strips the
# non-document chrome (scripts, styles, navigation, cookie banners, ads), folds
# the remaining prose into a canonical form and hashes it with SHA-256. The
# attestation is recorded only if the validators agree on that hash.
#
# Failure path: a dead / 4xx / 5xx page does NOT revert. A revert would roll the
# fee transfer back to the caller's wallet but leave no on-chain trace; the
# protocol instead returns a typed status (UNREACHABLE / AMBIGUOUS_VOID) and
# moves the fee into `claimable_credits`, a pull-pattern refund the payer
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
SNIPPET_CHARS = 200
MAX_URL_CHARS = 2048
MAX_BODY_CHARS = 4_000_000  # bound on the raw document a validator will process
MIN_TEXT_CHARS = 40  # below this the page carries no notarizable document

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
_DROP_TAGS = frozenset((
    "script", "style", "noscript", "template", "svg", "canvas", "iframe",
    "object", "embed", "form", "button", "select", "input", "textarea",
    "nav", "header", "footer", "aside", "menu", "dialog", "head",
))
_VOID_TAGS = frozenset((
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
))
_CHROME_ATTR_RE = re.compile(
    r"(cookie|consent|gdpr|banner|advert|(^|[-_ ])ads?([-_ ]|$)|adsbygoogle|"
    r"sponsor|promo|popup|modal|newsletter|subscribe|sidebar|breadcrumb|"
    r"navbar|navigation|menu|skip-link|social|share)",
    re.IGNORECASE,
)
_BLOCK_TAGS = frozenset((
    "p", "div", "section", "article", "main", "li", "ul", "ol", "dl", "dt",
    "dd", "tr", "table", "pre", "blockquote", "h1", "h2", "h3", "h4", "h5",
    "h6", "br", "hr", "figure", "figcaption", "details", "summary",
))


class _DocExtractor(HTMLParser):
    """Collects the visible prose of the document body, skipping chrome.

    Two passes are made by the caller: if the page declares <article> or
    <main>, only text inside those landmarks is kept; otherwise all
    non-chrome body text is kept."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.in_title = False
        self.skip_depth = 0
        self.skip_stack = []
        self.landmark_depth = 0
        self.all_chunks = []
        self.landmark_chunks = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        if tag in _VOID_TAGS:
            if tag in _BLOCK_TAGS:
                self._brk()
            return
        chrome = tag in _DROP_TAGS
        if not chrome and tag not in ("html", "body", "article", "main"):
            for k, v in attrs:
                if k in ("class", "id", "role", "aria-label") and v:
                    if _CHROME_ATTR_RE.search(v) or v.lower() in ("navigation", "banner", "contentinfo", "complementary", "search"):
                        chrome = True
                        break
                if k == "hidden" or (k == "aria-hidden" and v == "true"):
                    chrome = True
                    break
        if self.skip_depth > 0 or chrome:
            self.skip_stack.append(tag)
            self.skip_depth += 1
            return
        if tag in ("article", "main"):
            self.landmark_depth += 1
        if tag in _BLOCK_TAGS:
            self._brk()

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
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
        if tag in ("article", "main") and self.landmark_depth > 0:
            self.landmark_depth -= 1
        if tag in _BLOCK_TAGS:
            self._brk()

    def _brk(self):
        self.all_chunks.append(" ")
        if self.landmark_depth > 0:
            self.landmark_chunks.append(" ")

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.skip_depth > 0:
            return
        self.all_chunks.append(data)
        if self.landmark_depth > 0:
            self.landmark_chunks.append(data)


def normalize_text(text: str) -> str:
    """Canonical text: NFKC, unified quotes / dashes / spaces, zero-width and
    control characters removed, runs of whitespace folded to one space."""
    t = unicodedata.normalize("NFKC", text)
    t = (
        t.replace("‘", "'").replace("’", "'")
        .replace("“", '"').replace("”", '"')
        .replace("–", "-").replace("—", "-").replace("−", "-")
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


def extract_document(body: str) -> dict:
    """Returns {"title", "text"}: the normalized title and article text."""
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS]
    head = body[:2048].lstrip().lower()
    looks_html = "<html" in head or "<!doctype html" in head or "<body" in body[:20000].lower() or "<title" in body[:20000].lower()
    if not looks_html:
        return {"title": "", "text": normalize_text(body)}
    p = _DocExtractor()
    try:
        p.feed(body)
        p.close()
    except Exception:
        pass  # the parser is tolerant; whatever was collected so far is used
    chunks = p.landmark_chunks if normalize_text("".join(p.landmark_chunks)) != "" else p.all_chunks
    return {
        "title": normalize_text("".join(p.title_parts)),
        "text": normalize_text("".join(chunks)),
    }


def content_hash_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _norm_hash(h) -> str:
    if not isinstance(h, str):
        return ""
    s = h.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


# ------------------------------------------------------------------------------
# Web read (runs inside the non-deterministic block on every validator)
# ------------------------------------------------------------------------------
def _read_page(canonical_url: str) -> dict:
    """Never raises. Returns a primitive-only dict so it is calldata-encodable:
    {"ok": bool, "code": str, "hash": str, "title": str, "snippet": str}."""
    def fail(code):
        return {"ok": False, "code": code, "hash": "", "title": "", "snippet": ""}

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
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", errors="replace")
    elif not isinstance(body, str):
        return fail(STATUS_AMBIGUOUS_VOID)
    doc = extract_document(body)
    text = doc["text"]
    if len(text) < MIN_TEXT_CHARS:
        return fail(STATUS_AMBIGUOUS_VOID)
    return {
        "ok": True,
        "code": STATUS_ATTESTED,
        "hash": content_hash_of(text),
        "title": doc["title"][:300],
        "snippet": text[:SNIPPET_CHARS],
    }


def _read_equivalent(leader: dict, mine: dict) -> bool:
    """Validator agreement predicate. Successful reads must agree on the content
    hash and title exactly; failed reads must agree on the failure class."""
    if not isinstance(leader, dict) or "ok" not in leader:
        return False
    if leader["ok"] != mine["ok"]:
        return False
    if mine["ok"]:
        return leader.get("hash") == mine["hash"] and leader.get("title") == mine["title"]
    return leader.get("code") == mine["code"]


@allow_storage
@dataclass
class Attestation:
    attestation_id: u256
    canonical_url: str
    content_hash: str  # hex SHA-256 of the normalized document text
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
        """True iff attestation exists and its content hash equals `expected_hash`
        (hex SHA-256; a `0x` prefix and letter case are not significant)."""
        if attestation_id not in self.attestations:
            return False
        want = _norm_hash(expected_hash)
        if len(want) != 64:
            return False
        return self.attestations[attestation_id].content_hash == want

    @gl.public.view
    def get_latest_attestation(self, url: str) -> dict:
        """Latest attestation of `url` (canonicalized first). For other contracts."""
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
        consensus, otherwise UNREACHABLE / AMBIGUOUS_VOID with the fee moved to
        the caller's claimable credits (nothing is recorded, nothing is lost)."""
        if gl.message.value != ATTESTATION_FEE:
            raise gl.vm.UserError(f"{ERR_FEE} expected {ATTESTATION_FEE}")
        try:
            canon = canonicalize_url(url)
        except UrlRejected as e:
            raise gl.vm.UserError(f"{ERR_URL} {e}")
        self.total_received += ATTESTATION_FEE

        def leader_fn():
            return _read_page(canon)

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            mine = _read_page(canon)
            if not isinstance(leaders_res, gl.vm.Return):
                return False  # leader crashed; the validator's own read decides nothing
            return _read_equivalent(leaders_res.calldata, mine)

        result = gl.vm.run_nondet(leader_fn, validator_fn)

        sender = self._key(gl.message.sender_address)
        if not result["ok"]:
            self._credit(sender, ATTESTATION_FEE)
            return {
                "status": result["code"],
                "attestation_id": 0,
                "canonical_url": canon,
                "refunded": str(ATTESTATION_FEE),
            }

        att_id = self.attestation_count + 1
        self.attestation_count = att_id
        self.attestations[att_id] = Attestation(
            attestation_id=att_id,
            canonical_url=canon,
            content_hash=result["hash"],
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
            "content_hash": result["hash"],
            "title": result["title"],
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
        return {
            "attestation_id": int(a.attestation_id),
            "canonical_url": a.canonical_url,
            "content_hash": a.content_hash,
            "title": a.title,
            "text_snippet": a.text_snippet,
            "timestamp": int(a.timestamp),
            "attester": a.attester,
            "fee_paid": str(a.fee_paid),
        }
