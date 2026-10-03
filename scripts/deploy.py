"""Deploy contracts/evidence_notary.py to GenLayer Studio Next (chain 61997).

    python scripts/deploy.py

Writes deployments/studio-next.json (address, deploy tx, source hash, runner).
"""

import json
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import _chain as ch  # noqa: E402


def main() -> None:
    client, account, balance = ch.make_client()
    print(f"network   studio-next (chain {ch.CHAIN_ID})  {ch.RPC_URL}")
    print(f"deployer  {account.address}  balance {balance / 10**18:.4f} GEN")

    code = ch.CONTRACT_FILE.read_bytes()
    tx = client.deploy_contract(code=code, args=[], fees=ch.fee_preset(client))
    tx_hash = tx if isinstance(tx, str) else tx.hex()
    print(f"deploy tx {tx_hash}")
    receipt = client.wait_for_transaction_receipt(tx_hash, wait_until="decided", retries=200, interval=3000)
    status = receipt.get("txExecutionResultName") or receipt.get("result_name") or receipt.get("status")
    consensus = receipt.get("result_name")
    data = receipt.get("data") or {}
    address = data.get("contract_address") or (receipt.get("tx_data_decoded") or {}).get("contract_address") \
        or (receipt.get("txDataDecoded") or {}).get("contractAddress")
    if status != "FINISHED_WITH_RETURN" or consensus not in ("MAJORITY_AGREE", "AGREE"):
        lr = (receipt.get("consensus_data") or {}).get("leader_receipt") or [{}]
        raise SystemExit(f"deploy FAILED on-chain (status {status}, consensus {consensus}): "
                         f"{(lr[0] if isinstance(lr, list) else lr).get('result')}")
    if not address:
        print(json.dumps(receipt, indent=2, default=str)[:3000])
        raise SystemExit(f"deploy did not yield a contract address (status {status})")
    print(f"status    {status}  consensus {consensus}\naddress   {address}")

    ch.save_deployment({
        "network": "studio-next",
        "chain_id": ch.CHAIN_ID,
        "rpc_url": ch.RPC_URL,
        "contract_address": address,
        "explorer_url": f"{ch.EXPLORER}/address/{address}",
        "source": "contracts/evidence_notary.py",
        "runner": ch.runner_hash(),
        "source_sha256": ch.source_sha256(),
        "deployer_and_governor": account.address,
        "deploy_tx": tx_hash,
        "deploy_status": str(status),
        "deploy_consensus": str(consensus),
        "deployed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "attestation_fee_atto": ch.FEE,
        "live_proofs": [],
    })
    print("recorded deployments/studio-next.json")


if __name__ == "__main__":
    main()
