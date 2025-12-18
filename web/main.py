#!/usr/bin/env python3
"""
DID Viewer Web Application
"""

import os
import sys
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from web3 import Web3
from dotenv import load_dotenv

load_dotenv(os.getenv("DOT_ENV_PATH", ".env"))

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "client"))

try:
    import config
except ImportError:
    raise ImportError("Cannot import config module from client directory")

SOULBOUND_DID_ABI = [
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
        "name": "getDIDInfo",
        "outputs": [
            {"internalType": "bytes", "name": "publicKey", "type": "bytes"},
            {"internalType": "uint256", "name": "createdAt", "type": "uint256"},
            {"internalType": "string", "name": "didDocument", "type": "string"},
            {"internalType": "address", "name": "owner", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "addr", "type": "address"}],
        "name": "getDIDByAddress",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes", "name": "publicKey", "type": "bytes"}],
        "name": "getDIDByPublicKey",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
        "name": "ownerOf",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]

VERIFIER_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "didTokenId", "type": "uint256"}
        ],
        "name": "getDIDVerifications",
        "outputs": [
            {"internalType": "string[]", "name": "types", "type": "string[]"},
            {"internalType": "bool[]", "name": "hasVerification", "type": "bool[]"},
            {
                "components": [
                    {
                        "internalType": "uint256",
                        "name": "didTokenId",
                        "type": "uint256",
                    },
                    {"internalType": "address", "name": "issuer", "type": "address"},
                    {
                        "internalType": "uint256",
                        "name": "verifiedAt",
                        "type": "uint256",
                    },
                    {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
                    {"internalType": "bool", "name": "isValid", "type": "bool"},
                ],
                "internalType": "struct IVCVerifier.VerificationRecord[]",
                "name": "records",
                "type": "tuple[]",
            },
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getAllVCTypes",
        "outputs": [{"internalType": "string[]", "name": "", "type": "string[]"}],
        "stateMutability": "view",
        "type": "function",
    },
]

ISSUER_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "issuerAddress", "type": "address"}
        ],
        "name": "getIssuerInfo",
        "outputs": [
            {"internalType": "string", "name": "name", "type": "string"},
            {"internalType": "string", "name": "description", "type": "string"},
            {"internalType": "bool", "name": "isActive", "type": "bool"},
            {"internalType": "uint256", "name": "registeredAt", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "issuerAddress", "type": "address"}
        ],
        "name": "isValidIssuer",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

# create FastAPI app
app = FastAPI(title="DID Viewer", description="View Decentralized Identity Information")

# set templates and static files
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")

os.makedirs(templates_dir, exist_ok=True)
os.makedirs(static_dir, exist_ok=True)

templates = Jinja2Templates(directory=templates_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Web3 connection
w3: Optional[Web3] = None
did_contract = None
verifier_registry = None
issuer_registry = None


def get_web3():
    """Get Web3 connection"""
    global w3, did_contract, verifier_registry, issuer_registry

    if w3 is None or not w3.is_connected():
        w3 = Web3(Web3.HTTPProvider(config.RPC_URL))

        did_contract = w3.eth.contract(
            address=Web3.to_checksum_address(config.DID_CONTRACT), abi=SOULBOUND_DID_ABI
        )
        verifier_registry = w3.eth.contract(
            address=Web3.to_checksum_address(config.VERIFIER_REGISTRY),
            abi=VERIFIER_REGISTRY_ABI,
        )
        issuer_registry = w3.eth.contract(
            address=Web3.to_checksum_address(config.ISSUER_REGISTRY),
            abi=ISSUER_REGISTRY_ABI,
        )

    return w3, did_contract, verifier_registry, issuer_registry


def format_timestamp(timestamp: int) -> str:
    """Format timestamp"""
    if timestamp == 0:
        return "Never"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def is_expired(expires_at: int) -> bool:
    """Check if expired"""
    if expires_at == 0:
        return False
    return datetime.now().timestamp() > expires_at


# Pydantic models
class DIDInfo(BaseModel):
    token_id: int
    owner: str
    public_key: str
    created_at: str
    created_at_timestamp: int
    did_document: str


class VerificationInfo(BaseModel):
    vc_type: str
    is_verified: bool
    issuer: Optional[str] = None
    issuer_name: Optional[str] = None
    verified_at: Optional[str] = None
    expires_at: Optional[str] = None
    is_valid: bool = False
    is_expired: bool = False


class DIDQueryResult(BaseModel):
    success: bool
    error: Optional[str] = None
    did_info: Optional[DIDInfo] = None
    verifications: list[VerificationInfo] = []


class SystemStats(BaseModel):
    connected: bool
    rpc_url: str
    chain_id: int
    block_number: int
    total_dids: int
    vc_types: list[str]
    contracts: dict


# API routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/stats", response_model=SystemStats)
async def get_stats():
    """Get system statistics"""
    try:
        w3, did_contract, verifier_registry, _ = get_web3()

        total_dids = did_contract.functions.totalSupply().call()
        vc_types = verifier_registry.functions.getAllVCTypes().call()

        return SystemStats(
            connected=w3.is_connected(),
            rpc_url=config.RPC_URL,
            chain_id=config.CHAIN_ID,
            block_number=w3.eth.block_number,
            total_dids=total_dids,
            vc_types=vc_types,
            contracts={
                "did": config.DID_CONTRACT,
                "issuer_registry": config.ISSUER_REGISTRY,
                "verifier_registry": config.VERIFIER_REGISTRY,
                "age_verifier": config.AGE_VERIFIER,
            },
        )
    except Exception as _:
        return SystemStats(
            connected=False,
            rpc_url=config.RPC_URL,
            chain_id=config.CHAIN_ID,
            block_number=0,
            total_dids=0,
            vc_types=[],
            contracts={},
        )


@app.get("/api/did/{query}", response_model=DIDQueryResult)
async def query_did(query: str):
    """
    Query DID information

    query could be:
    - Token ID (digits only)
    - wallet address (begin with 0x, length 42)
    - public key (begin with 0x, length != 42)
    """
    try:
        w3, did_contract, verifier_registry, issuer_registry = get_web3()

        token_id = None

        # Determine query type
        if query.isdigit():
            # Token ID
            token_id = int(query)
        elif query.startswith("0x") and len(query) == 42:
            # Wallet address
            try:
                address = Web3.to_checksum_address(query)
                token_id = did_contract.functions.getDIDByAddress(address).call()
            except Exception as e:
                return DIDQueryResult(success=False, error=f"Invalid address: {str(e)}")
        elif query.startswith("0x"):
            # Public key
            try:
                public_key_bytes = bytes.fromhex(query[2:])
                token_id = did_contract.functions.getDIDByPublicKey(
                    public_key_bytes
                ).call()
            except Exception as e:
                return DIDQueryResult(
                    success=False, error=f"Invalid public key: {str(e)}"
                )
        else:
            return DIDQueryResult(
                success=False,
                error="Invalid query format.  Use Token ID, wallet address, or public key.",
            )

        if token_id is None or token_id == 0:
            return DIDQueryResult(success=False, error="DID not found")

        # Get DID information
        try:
            did_info = did_contract.functions.getDIDInfo(token_id).call()
            public_key, created_at, did_document, owner = did_info
        except Exception as e:
            return DIDQueryResult(
                success=False, error=f"Failed to get DID info: {str(e)}"
            )

        # Get verification information
        verifications = []
        try:
            result = verifier_registry.functions.getDIDVerifications(token_id).call()
            vc_types, has_verifications, records = result

            for i, vc_type in enumerate(vc_types):
                verification = VerificationInfo(
                    vc_type=vc_type,
                    is_verified=has_verifications[i],
                    is_valid=False,
                    is_expired=False,
                )

                if has_verifications[i] and i < len(records):
                    record = records[i]
                    verification.issuer = record[1]
                    verification.verified_at = format_timestamp(record[2])
                    verification.expires_at = format_timestamp(record[3])
                    verification.is_valid = record[4]
                    verification.is_expired = is_expired(record[3])

                    # get issuer name
                    try:
                        issuer_info = issuer_registry.functions.getIssuerInfo(
                            record[1]
                        ).call()
                        verification.issuer_name = issuer_info[0]
                    except Exception:
                        verification.issuer_name = "Unknown"

                verifications.append(verification)
        except Exception as e:
            print(f"Error getting verifications: {e}")

        return DIDQueryResult(
            success=True,
            did_info=DIDInfo(
                token_id=token_id,
                owner=owner,
                public_key=f"0x{public_key.hex()}",
                created_at=format_timestamp(created_at),
                created_at_timestamp=created_at,
                did_document=did_document if did_document else "",
            ),
            verifications=verifications,
        )

    except Exception as e:
        return DIDQueryResult(success=False, error=str(e))


@app.get("/api/issuer/{address}")
async def get_issuer_info(address: str):
    """Get issuer information"""
    try:
        _, _, _, issuer_registry = get_web3()

        address = Web3.to_checksum_address(address)

        is_valid = issuer_registry.functions.isValidIssuer(address).call()
        info = issuer_registry.functions.getIssuerInfo(address).call()

        return {
            "success": True,
            "address": address,
            "name": info[0],
            "description": info[1],
            "is_active": info[2],
            "registered_at": format_timestamp(info[3]),
            "is_valid": is_valid,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
