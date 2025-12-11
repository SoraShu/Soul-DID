import os
import json
from dotenv import load_dotenv

load_dotenv(os.getenv("DOT_ENV_PATH", ".env"))

# Network configuration
RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
CHAIN_ID = int(os.getenv("CHAIN_ID", "31337"))

# Contract addresses (update after deployment)
DID_CONTRACT = os.getenv("DID_CONTRACT", "0x5FbDB2315678afecb367f032d93F642f64180aa3")
ISSUER_REGISTRY = os.getenv(
    "ISSUER_REGISTRY", "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
)
VERIFIER_REGISTRY = os.getenv(
    "VERIFIER_REGISTRY", "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
)
AGE_VERIFIER = os.getenv("AGE_VERIFIER", "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")

# ABIs
SOULBOUND_DID_ABI = json.loads("""
[
    {
        "inputs": [{"internalType": "bytes", "name": "publicKey", "type": "bytes"}, {"internalType": "string", "name": "didDocument", "type": "string"}],
        "name": "mintDID",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability":  "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}, {"internalType": "bytes32", "name": "challenge", "type": "bytes32"}, {"internalType": "bytes", "name": "signature", "type": "bytes"}],
        "name": "verifyChallenge",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
        "name": "getDIDInfo",
        "outputs":  [{"internalType": "bytes", "name": "publicKey", "type": "bytes"}, {"internalType": "uint256", "name": "createdAt", "type": "uint256"}, {"internalType": "string", "name": "didDocument", "type": "string"}, {"internalType": "address", "name": "owner", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "addr", "type": "address"}],
        "name": "getDIDByAddress",
        "outputs": [{"internalType": "uint256", "name": "", "type":  "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name":  "tokenId", "type": "uint256"}],
        "name": "ownerOf",
        "outputs":  [{"internalType": "address", "name": "", "type":  "address"}],
        "stateMutability": "view",
        "type": "function"
    }
]
""")

ISSUER_REGISTRY_ABI = json.loads("""
[
    {
        "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}, {"internalType": "string", "name": "name", "type": "string"}, {"internalType": "string", "name": "description", "type": "string"}],
        "name": "registerIssuer",
        "outputs": [],
        "stateMutability":  "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}, {"internalType": "bool", "name": "isActive", "type": "bool"}],
        "name": "setIssuerStatus",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs":  [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
        "name": "isValidIssuer",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
        "name":  "getIssuerInfo",
        "outputs": [{"internalType": "string", "name": "name", "type":  "string"}, {"internalType": "string", "name": "description", "type": "string"}, {"internalType": "bool", "name": "isActive", "type": "bool"}, {"internalType": "uint256", "name": "registeredAt", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getIssuerCount",
        "outputs": [{"internalType":  "uint256", "name": "", "type": "uint256"}],
        "stateMutability":  "view",
        "type":  "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "getIssuerAt",
        "outputs": [{"internalType":  "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    }
]
""")

AGE_VERIFIER_ABI = json.loads("""
[
    {
        "inputs":  [{"internalType": "uint256", "name": "didTokenId", "type": "uint256"}, {"internalType": "address", "name": "issuer", "type": "address"}, {"internalType": "uint256", "name": "expiresAt", "type": "uint256"}, {"internalType": "bytes", "name": "signature", "type": "bytes"}, {"internalType": "bytes", "name": "vcData", "type": "bytes"}],
        "name": "verifyAndRecord",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "didTokenId", "type": "uint256"}],
        "name": "hasValidVerification",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name":  "didTokenId", "type":  "uint256"}],
        "name": "getVerification",
        "outputs": [{"components": [{"internalType": "uint256", "name": "didTokenId", "type": "uint256"}, {"internalType":  "address", "name": "issuer", "type": "address"}, {"internalType": "uint256", "name": "verifiedAt", "type": "uint256"}, {"internalType":  "uint256", "name": "expiresAt", "type": "uint256"}, {"internalType":  "bool", "name": "isValid", "type": "bool"}], "internalType": "struct IVCVerifier.VerificationRecord", "name": "", "type": "tuple"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getVCType",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "pure",
        "type": "function"
    }
]
""")

VERIFIER_REGISTRY_ABI = json.loads("""
[
    {
        "inputs": [{"internalType": "address", "name": "walletAddress", "type": "address"}],
        "name": "getVerificationsByAddress",
        "outputs": [{"internalType":  "uint256", "name": "didTokenId", "type": "uint256"}, {"internalType": "string[]", "name": "types", "type": "string[]"}, {"internalType": "bool[]", "name": "hasVerification", "type": "bool[]"}, {"components": [{"internalType": "uint256", "name": "didTokenId", "type": "uint256"}, {"internalType":  "address", "name": "issuer", "type": "address"}, {"internalType": "uint256", "name": "verifiedAt", "type": "uint256"}, {"internalType": "uint256", "name": "expiresAt", "type": "uint256"}, {"internalType": "bool", "name": "isValid", "type": "bool"}], "internalType": "struct IVCVerifier. VerificationRecord[]", "name": "records", "type": "tuple[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getAllVCTypes",
        "outputs":  [{"internalType": "string[]", "name": "", "type": "string[]"}],
        "stateMutability": "view",
        "type": "function"
    }
]
""")
