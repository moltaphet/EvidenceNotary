"""Shared Studio Next plumbing for deploy.py and interact_live.py.

The signing key lives in `.env` (gitignored). It is generated on first use and
funded from the Studio faucet, so no personal wallet is ever touched.
"""

import hashlib
import json
import os
from pathlib import Path

from genlayer_py import create_account, create_client
from genlayer_py.chains import studio_devnet

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
DEPLOYMENT_FILE = ROOT / "deployments" / "studio-next.json"
CONTRACT_FILE = ROOT / "contracts" / "evidence_notary.py"

RPC_URL = "https://studio-next.genlayer.com/api"  # Studio Next, chain id 61997
CHAIN_ID = 61997
EXPLORER = "https://explorer-studio-next.genlayer.com"
FEE = 5 * 10**16  # 0.05 GEN
MIN_BALANCE = 5 * 10**17
FEE_ESTIMATE_OPTIONS = {
    "leaderTimeunitsAllocation": 100,
    "validatorTimeunitsAllocation": 200,
    "rotations": [1],
}


def load_private_key() -> str:
    key = os.environ.get("EVIDENCE_NOTARY_KEY")
    if key:
        return key
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("EVIDENCE_NOTARY_KEY="):
                return line.split("=", 1)[1].strip()
    acct = create_account()
    ENV_FILE.write_text(f"EVIDENCE_NOTARY_KEY={acct.key.hex()}\n")
    ENV_FILE.chmod(0o600)
    print(f"generated deployer key for {acct.address} -> .env")
    return acct.key.hex()


def make_client():
    account = create_account(load_private_key())
    client = create_client(chain=studio_devnet, endpoint=RPC_URL, account=account)
    if client.chain.id != CHAIN_ID:
        raise SystemExit(f"expected chain {CHAIN_ID}, endpoint reports {client.chain.id}")
    balance = client.get_balance(account.address)
    if balance < MIN_BALANCE:
        client.fund_account(address=account.address, amount=10**18)
        balance = client.get_balance(account.address)
    return client, account, balance


def fee_preset(client):
    est = client.estimate_transaction_fees(FEE_ESTIMATE_OPTIONS)
    return {"distribution": est["distribution"], "feeValue": est["feeValue"]}


def source_sha256() -> str:
    return hashlib.sha256(CONTRACT_FILE.read_bytes()).hexdigest()


def runner_hash() -> str:
    first = CONTRACT_FILE.read_text().splitlines()[1]
    return first.split("py-genlayer:")[1].split('"')[0]


def load_deployment() -> dict:
    return json.loads(DEPLOYMENT_FILE.read_text())


def save_deployment(data: dict) -> None:
    DEPLOYMENT_FILE.parent.mkdir(exist_ok=True)
    DEPLOYMENT_FILE.write_text(json.dumps(data, indent=2, sort_keys=False, default=str) + "\n")
