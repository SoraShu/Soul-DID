import os
import json
import time
from datetime import datetime
from pathlib import Path

from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table

import config

console = Console()


def get_web3():
    """Get Web3 instance"""
    w3 = Web3(Web3.HTTPProvider(config.RPC_URL))
    if not w3.is_connected():
        console.print("[red]Error: Cannot connect to RPC[/red]")
        raise ConnectionError("Failed to connect to RPC")
    return w3


def get_contracts(w3):
    """Get contract instances"""
    did_contract = w3.eth.contract(
        address=Web3.to_checksum_address(config.DID_CONTRACT),
        abi=config.SOULBOUND_DID_ABI,
    )
    issuer_registry = w3.eth.contract(
        address=Web3.to_checksum_address(config.ISSUER_REGISTRY),
        abi=config.ISSUER_REGISTRY_ABI,
    )
    age_verifier = w3.eth.contract(
        address=Web3.to_checksum_address(config.AGE_VERIFIER),
        abi=config.AGE_VERIFIER_ABI,
    )
    verifier_registry = w3.eth.contract(
        address=Web3.to_checksum_address(config.VERIFIER_REGISTRY),
        abi=config.VERIFIER_REGISTRY_ABI,
    )
    return did_contract, issuer_registry, age_verifier, verifier_registry


def load_account(private_key: str):
    """Load account from private key"""
    if not private_key.startswith("0x"):
        private_key = "0x" + private_key
    return Account.from_key(private_key)


def sign_message(message_hash: bytes, private_key: str) -> bytes:
    """
    Sign a message hash with Ethereum signed message prefix.

    Args:
        message_hash: The hash to sign (bytes32)
        private_key: The private key to sign with

    Returns:
        The signature bytes
    """
    account = load_account(private_key)

    # 确保 message_hash 是 bytes 类型
    if isinstance(message_hash, str):
        if message_hash.startswith("0x"):
            message_hash = bytes.fromhex(message_hash[2:])
        else:
            message_hash = bytes.fromhex(message_hash)

    # Create eth_sign compatible message (adds "\x19Ethereum Signed Message:\n32" prefix)
    message = encode_defunct(primitive=message_hash)
    signed = account.sign_message(message)
    return signed.signature


def generate_challenge() -> tuple[bytes, str]:
    """Generate a challenge (timestamp-based)"""
    timestamp = int(time.time())
    challenge_str = f"DID-Challenge-{timestamp}"
    challenge_hash = Web3.keccak(text=challenge_str)
    return challenge_hash, challenge_str


def format_timestamp(timestamp: int) -> str:
    """Format Unix timestamp to readable string"""
    if timestamp == 0:
        return "Never"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def print_did_info(did_info: tuple, token_id: int):
    """Print DID info in a table"""
    public_key, created_at, did_document, owner = did_info

    table = Table(title=f"DID Info (Token ID: {token_id})")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Owner", owner)
    table.add_row("Public Key", f"0x{public_key.hex()}" if public_key else "N/A")
    table.add_row("Created At", format_timestamp(created_at))
    table.add_row("DID Document", did_document if did_document else "N/A")

    console.print(table)


def print_verification_info(record: tuple):
    """Print verification record in a table"""
    token_id, issuer, verified_at, expires_at, is_valid = record

    table = Table(title="Verification Record")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("DID Token ID", str(token_id))
    table.add_row("Issuer", issuer)
    table.add_row("Verified At", format_timestamp(verified_at))
    table.add_row("Expires At", format_timestamp(expires_at))
    table.add_row("Is Valid", "✓ Yes" if is_valid else "✗ No")

    console.print(table)


def send_transaction(w3, contract_func, account, gas_limit=500000):
    """Build, sign and send transaction"""
    tx = contract_func.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": gas_limit,
            "gasPrice": w3.eth.gas_price,
            "chainId": config.CHAIN_ID,
        }
    )

    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

    console.print(f"[yellow]Transaction sent:  {tx_hash.hex()}[/yellow]")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    if receipt["status"] == 1:
        console.print("[green]Transaction successful![/green]")
    else:
        console.print("[red]Transaction failed![/red]")

    return receipt


# ============ DID Key Management ============


class DIDKeyManager:
    """Manage DID key pairs (separate from wallet keys)"""

    def __init__(self, keys_dir: str = None):
        if keys_dir is None:
            keys_dir = os.path.join(os.path.dirname(__file__), ".did_keys")
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate a new ECDSA key pair for DID"""
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()

        # Serialize keys
        private_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        return private_bytes, public_bytes

    def save_key_pair(self, address: str, private_key: bytes, public_key: bytes):
        """Save key pair to file"""
        key_file = self.keys_dir / f"{address.lower()}.json"
        key_data = {
            "address": address,
            "did_private_key": f"0x{private_key.hex()}",
            "did_public_key": f"0x{public_key.hex()}",
        }
        with open(key_file, "w") as f:
            json.dump(key_data, f, indent=2)
        console.print(f"[green]DID keys saved to:  {key_file}[/green]")

    def load_key_pair(self, address: str) -> tuple[bytes, bytes] | None:
        """Load key pair from file"""
        key_file = self.keys_dir / f"{address.lower()}.json"
        if not key_file.exists():
            return None

        with open(key_file, "r") as f:
            key_data = json.load(f)

        private_key = bytes.fromhex(key_data["did_private_key"][2:])
        public_key = bytes.fromhex(key_data["did_public_key"][2:])
        return private_key, public_key

    def has_key_pair(self, address: str) -> bool:
        """Check if key pair exists for address"""
        key_file = self.keys_dir / f"{address.lower()}.json"
        return key_file.exists()

    def list_keys(self) -> list[dict]:
        """List all saved key pairs"""
        keys = []
        for key_file in self.keys_dir.glob("*.json"):
            with open(key_file, "r") as f:
                key_data = json.load(f)
                keys.append(
                    {
                        "address": key_data["address"],
                        "public_key": key_data["did_public_key"][:20] + "...",
                    }
                )
        return keys
