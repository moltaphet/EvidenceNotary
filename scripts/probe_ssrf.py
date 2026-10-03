"""Live SSRF probe: attest a public hostname that resolves to loopback.

    python scripts/probe_ssrf.py [url]        # default https://localtest.me/

`localtest.me` is a public name whose DNS A record is 127.0.0.1, so it passes the
contract's syntactic URL filter. This script shows what the validators' execution
environment actually does with it, and stores the exact result under
`ssrf_probe` in deployments/studio-next.json.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import _chain as ch  # noqa: E402
from interact_live import consensus_summary, decode_return  # noqa: E402

URL = sys.argv[1] if len(sys.argv) > 1 else "https://localtest.me/"


def main() -> None:
    client, account, balance = ch.make_client()
    dep = ch.load_deployment()
    addr = dep["contract_address"]
    me = account.address.lower()
    view = lambda name, *a: client.read_contract(address=addr, function_name=name, args=list(a))  # noqa: E731

    canon = view("canonicalize", URL)
    before = view("get_protocol_state")
    credits_before = int(view("claimable_of", me))
    print(f"contract {addr}\nprobe    {URL}  (canonical {canon})\nfilter   passes the URL canonicalizer")

    tx_hash = client.write_contract(address=addr, function_name="attest", args=[URL], value=ch.FEE,
                                    fees=ch.fee_preset(client))
    tx_hash = tx_hash if isinstance(tx_hash, str) else tx_hash.hex()
    client.wait_for_transaction_receipt(tx_hash, wait_until="decided", retries=300, interval=3000)
    tx = client.get_transaction(tx_hash)
    after = view("get_protocol_state")
    credits_after = int(view("claimable_of", me))
    returned = decode_return(tx)
    cons = consensus_summary(tx)

    print(f"tx       {tx_hash}")
    print(f"consensus {cons['result']}  votes {cons['tally']}  exec {cons['execution']}")
    print(f"returned {returned}")
    print(f"vault    {before['protocol_vault']} -> {after['protocol_vault']}")
    print(f"credits  {credits_before} -> {credits_after}   attestations {before['attestation_count']} -> {after['attestation_count']}")

    dep["ssrf_probe"] = {
        "url": URL,
        "canonical_url": canon,
        "passes_url_filter": True,
        "tx_hash": tx_hash,
        "consensus": cons,
        "returned": returned,
        "attestation_recorded": after["attestation_count"] != before["attestation_count"],
        "vault_before": before["protocol_vault"], "vault_after": after["protocol_vault"],
        "claimable_before": str(credits_before), "claimable_after": str(credits_after),
        "probed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    ch.save_deployment(dep)
    print("recorded ssrf_probe in deployments/studio-next.json")


if __name__ == "__main__":
    main()
