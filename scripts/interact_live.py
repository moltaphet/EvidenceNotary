"""Notarize four live sources on Studio Next and record the proofs.

    python scripts/interact_live.py

Cases: RFC 9000, Python 3.13 release notes, W3C DID Core, and a dead docs.python.org
URL that must end in a fee refund. Each case records the transaction hash, the
validator consensus result and per-validator votes, the on-chain attestation,
and the contract's accounting before and after. The refund is then withdrawn
and the vault swept, with the solvency identity read back from the contract
after every step. Everything is written to deployments/studio-next.json.
"""

import base64
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import _chain as ch  # noqa: E402
from genlayer_py.abi import calldata  # noqa: E402

CASES = [
    ("RFC 9000 -- QUIC transport specification", "https://rfc-editor.org/rfc/rfc9000", True),
    ("Python 3.13 release notes", "https://docs.python.org/3/whatsnew/3.13.html", True),
    ("W3C Decentralized Identifiers (DID Core)", "https://w3.org/TR/did-core/", True),
    ("Dead link -- HTTP 404 on docs.python.org (fee must be refunded)",
     "https://docs.python.org/3/evidencenotary-nonexistent-page-404.html", False),
]


def decode_return(tx):
    """Best-effort decode of the leader's returned calldata (None if absent)."""
    try:
        receipt = tx["consensus_data"]["leader_receipt"]
        receipt = receipt[0] if isinstance(receipt, list) else receipt
        res = receipt["result"]
        raw = base64.b64decode(res["raw"] if isinstance(res, dict) else res)
        return calldata.decode(raw[1:]) if raw and raw[0] == 0 else None
    except Exception:
        return None


def consensus_summary(tx):
    votes = {k: v for k, v in (tx["consensus_data"].get("votes") or {}).items()}
    tally = {}
    for v in votes.values():
        tally[v] = tally.get(v, 0) + 1
    leader = tx["consensus_data"].get("leader_receipt") or [{}]
    leader = leader[0] if isinstance(leader, list) else leader
    state_hashes = {"leader": leader.get("contract_state_hash")}
    for i, v in enumerate(tx["consensus_data"].get("validators") or []):
        if v.get("contract_state_hash"):
            state_hashes[f"validator_{i}_{v.get('mode', '')}_{v.get('vote', '')}"] = v["contract_state_hash"]
    return {
        "result": tx.get("result_name"),
        "state_hashes": state_hashes,
        "execution": tx.get("txExecutionResultName"),
        "votes": votes,
        "tally": tally,
        "tx_execution_hash": tx.get("tx_execution_hash"),
    }


def main() -> None:
    client, account, balance = ch.make_client()
    dep = ch.load_deployment()
    addr = dep["contract_address"]
    me = account.address.lower()
    print(f"contract {addr}\ncaller   {account.address}  {balance / 10**18:.4f} GEN")

    def view(name, *args):
        return client.read_contract(address=addr, function_name=name, args=list(args))

    def state():
        s = view("get_protocol_state")
        return {k: (str(v) if not isinstance(v, bool) else v) for k, v in s.items()}

    def write(name, *args, value=0, finalize=False):
        tx_hash = client.write_contract(
            address=addr, function_name=name, args=list(args), value=value, fees=ch.fee_preset(client)
        )
        tx_hash = tx_hash if isinstance(tx_hash, str) else tx_hash.hex()
        client.wait_for_transaction_receipt(tx_hash, wait_until="decided", retries=300, interval=3000)
        if finalize:
            # Payouts use emit_transfer(on="finalized"): the contract balance falls
            # only once the transaction finalizes, so the solvency identity is
            # checked over finalized state (see README, section 4.3).
            client.wait_for_transaction_receipt(tx_hash, wait_until="finalized", retries=300, interval=3000)
        return tx_hash, client.get_transaction(tx_hash)

    def check_solvent(s):
        """Ledger identity must hold exactly; strict balance identity must hold
        up to the payouts the chain has not debited (README 4.3)."""
        assert s["ledger_conserved"] is True, f"LEDGER BROKEN: {s}"
        assert int(s["total_received"]) == int(s["protocol_vault"]) + int(s["total_credits"]) + int(s["total_paid_out"]), s
        drift = int(s["balance"]) - int(s["protocol_vault"]) - int(s["total_credits"])
        assert drift in (0, int(s["total_paid_out"])), f"BALANCE DRIFT {drift} unexplained by payouts: {s}"
        s["balance_drift"] = str(drift)

    proofs = []
    check_solvent(state())
    for label, url, expect_ok in CASES:
        before = state()
        credits_before = int(view("claimable_of", me))
        print(f"\n== {label}\n   {url}")
        tx_hash, tx = write("attest", url, value=ch.FEE)
        after = state()
        check_solvent(after)
        cons = consensus_summary(tx)
        returned = decode_return(tx)
        entry = {
            "case": label,
            "url": url,
            "tx_hash": tx_hash,
            "consensus": cons,
            "returned": returned,
            "state_before": before,
            "state_after": after,
            "block_time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        print(f"   tx {tx_hash}\n   consensus {cons['result']}  votes {cons['tally']}  exec {cons['execution']}")
        if expect_ok:
            att = view("get_latest_attestation", url)
            assert view("verify_attestation", att["attestation_id"], att["content_hash"]) is True
            entry["outcome"] = "ATTESTED"
            entry["attestation"] = att
            print(f"   ATTESTED id={att['attestation_id']} sha256={att['content_hash']}\n   title: {att['title']}")
            assert int(after["attestation_count"]) == int(before["attestation_count"]) + 1
            assert int(after["protocol_vault"]) == int(before["protocol_vault"]) + ch.FEE
        else:
            credits_after = int(view("claimable_of", me))
            entry["outcome"] = (returned or {}).get("status", "REFUNDED") if isinstance(returned, dict) else "REFUNDED"
            entry["refund"] = {"claimable_before": str(credits_before), "claimable_after": str(credits_after)}
            print(f"   refunded -> claimable {credits_before} -> {credits_after}  returned={returned}")
            assert credits_after == credits_before + ch.FEE
            assert after["attestation_count"] == before["attestation_count"]
            assert after["protocol_vault"] == before["protocol_vault"]
        proofs.append(entry)

    # Pull the refund back out, then sweep the vault; solvency re-checked each time.
    print("\n== pull_withdraw (refund)")
    bal0 = client.get_balance(account.address)
    before = state()
    tx_hash, tx = write("pull_withdraw", finalize=True)
    after = state()
    check_solvent(after)
    withdraw = {
        "tx_hash": tx_hash, "consensus": consensus_summary(tx), "returned": decode_return(tx),
        "state_before": before, "state_after": after,
        "claimable_after": str(view("claimable_of", me)),
        "caller_balance_before": str(bal0),
        "caller_balance_after": str(client.get_balance(account.address)),
    }
    assert int(after["total_credits"]) == 0
    print(f"   tx {tx_hash} consensus {withdraw['consensus']['result']} credits -> {after['total_credits']}")

    print("\n== sweep_vault (governor)")
    before = state()
    tx_hash, tx = write("sweep_vault", finalize=True)
    after = state()
    check_solvent(after)
    sweep = {
        "tx_hash": tx_hash, "consensus": consensus_summary(tx), "returned": decode_return(tx),
        "state_before": before, "state_after": after,
    }
    print(f"   tx {tx_hash} consensus {sweep['consensus']['result']} vault -> {after['protocol_vault']}")

    dep["live_proofs"] = proofs
    dep["pull_withdraw"] = withdraw
    dep["sweep_vault"] = sweep
    dep["final_state"] = state()
    dep["interacted_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ch.save_deployment(dep)
    print("\nrecorded deployments/studio-next.json")


if __name__ == "__main__":
    main()
