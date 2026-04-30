"""
config.py — All environment variables. NO hardcoded secrets.
Create a .env file in ai-modules/fir_warden/ with the values below.
"""

import os
from dotenv import load_dotenv

# Load environment from root
from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).parents[2] / ".env")

def _require(key: str) -> str:
    val = os.getenv(key)
    if not val:
        raise RuntimeError(f"Missing required env var: {key}. Add it to ai-modules/fir_warden/.env")
    return val

# ── Credentials (REQUIRED — must be in .env) ──────────────────────────────────
CONTRACT_ADDRESS = _require("CONTRACT_ADDRESS")
PRIVATE_KEY      = _require("PRIVATE_KEY")
SUPABASE_URL     = _require("SUPABASE_URL")
SUPABASE_KEY     = _require("SUPABASE_KEY")

# ── Optional with safe defaults ───────────────────────────────────────────────
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")         # empty = localhost-only fallback
RPC_URL      = os.getenv("RPC_URL", "https://rpc-amoy.polygon.technology/")

# ── Security Rules ────────────────────────────────────────────────────────────
AUTHORIZED_IPS = {"127.0.0.1", "::1", "testclient"}

# ── DDoS Detection ────────────────────────────────────────────────────────────
DDOS_THRESHOLD = 20
DDOS_WINDOW    = 10

# ── Blockchain ────────────────────────────────────────────────────────────────
CHAIN_ID = 80002  # Polygon Amoy

# ── Contract ABI (EvidenceRegistry.sol — matches deployed contract) ───────────
CONTRACT_ABI = [
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": False,
        "internalType": "address",
        "name": "wallet",
        "type": "address"
      }
    ],
    "name": "AuthorizedAdded",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": False,
        "internalType": "address",
        "name": "wallet",
        "type": "address"
      }
    ],
    "name": "AuthorizedRevoked",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "docId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "docHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "string",
        "name": "docType",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "string",
        "name": "fileName",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "uploadedBy",
        "type": "address"
      }
    ],
    "name": "DocumentAnchored",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "docId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "originalHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "submittedHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "detectedBy",
        "type": "address"
      }
    ],
    "name": "DocumentTampered",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "docId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "checkHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "bool",
        "name": "intact",
        "type": "bool"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "checkedBy",
        "type": "address"
      }
    ],
    "name": "DocumentVerified",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "firId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "firHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "uint256",
        "name": "version",
        "type": "uint256"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "officer",
        "type": "address"
      }
    ],
    "name": "FIRAnchored",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "firId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "oldHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "newHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "uint256",
        "name": "newVersion",
        "type": "uint256"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "updatedBy",
        "type": "address"
      }
    ],
    "name": "FIRUpdated",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "customerId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "submittedHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "originalHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "flaggedBy",
        "type": "address"
      }
    ],
    "name": "KYCFlagged",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "customerId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "kycHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "string",
        "name": "kycType",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "registeredBy",
        "type": "address"
      }
    ],
    "name": "KYCRegistered",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "customerId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "verifiedHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "bool",
        "name": "matched",
        "type": "bool"
      },
      {
        "indexed": False,
        "internalType": "address",
        "name": "verifiedBy",
        "type": "address"
      }
    ],
    "name": "KYCVerified",
    "type": "event"
  },
  {
    "anonymous": False,
    "inputs": [
      {
        "indexed": True,
        "internalType": "string",
        "name": "firId",
        "type": "string"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "originalHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "bytes32",
        "name": "newHash",
        "type": "bytes32"
      },
      {
        "indexed": False,
        "internalType": "uint256",
        "name": "version",
        "type": "uint256"
      }
    ],
    "name": "TamperDetected",
    "type": "event"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "docId",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "hash",
        "type": "bytes32"
      },
      {
        "internalType": "string",
        "name": "docType",
        "type": "string"
      },
      {
        "internalType": "string",
        "name": "fileName",
        "type": "string"
      }
    ],
    "name": "anchorDocument",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "firId",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "firHash",
        "type": "bytes32"
      }
    ],
    "name": "anchorFIR",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "wallet",
        "type": "address"
      }
    ],
    "name": "authorizeWallet",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "cid",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "hash",
        "type": "bytes32"
      },
      {
        "internalType": "string",
        "name": "kycType",
        "type": "string"
      }
    ],
    "name": "registerKYC",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "wallet",
        "type": "address"
      }
    ],
    "name": "revokeWallet",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "firId",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "firHash",
        "type": "bytes32"
      },
      {
        "internalType": "string",
        "name": "",
        "type": "string"
      }
    ],
    "name": "updateFIR",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "docId",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "hash",
        "type": "bytes32"
      }
    ],
    "name": "verifyDocument",
    "outputs": [
      {
        "internalType": "bool",
        "name": "intact",
        "type": "bool"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "cid",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "hash",
        "type": "bytes32"
      }
    ],
    "name": "verifyKYC",
    "outputs": [
      {
        "internalType": "bool",
        "name": "matched",
        "type": "bool"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "inputs": [],
    "name": "admin",
    "outputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "name": "authorized",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "docId",
        "type": "string"
      },
      {
        "internalType": "bytes32",
        "name": "hash",
        "type": "bytes32"
      }
    ],
    "name": "checkDocumentHash",
    "outputs": [
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "cid",
        "type": "string"
      }
    ],
    "name": "getKYCStatus",
    "outputs": [
      {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
      },
      {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
      },
      {
        "internalType": "string",
        "name": "",
        "type": "string"
      },
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      },
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      },
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      },
      {
        "internalType": "bool",
        "name": "",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "getPlatformStats",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "firCount",
        "type": "uint256"
      },
      {
        "internalType": "uint256",
        "name": "kycCount",
        "type": "uint256"
      },
      {
        "internalType": "uint256",
        "name": "docCount",
        "type": "uint256"
      },
      {
        "internalType": "uint256",
        "name": "tamperCount",
        "type": "uint256"
      },
      {
        "internalType": "uint256",
        "name": "blockNumber",
        "type": "uint256"
      },
      {
        "internalType": "address",
        "name": "adminAddress",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalDocuments",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalFIRs",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalKYCs",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalTamperEvents",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "string",
        "name": "firId",
        "type": "string"
      },
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      },
      {
        "internalType": "bytes32",
        "name": "firHash",
        "type": "bytes32"
      }
    ],
    "name": "verifyFIR",
    "outputs": [
      {
        "internalType": "bool",
        "name": "valid",
        "type": "bool"
      },
      {
        "internalType": "bool",
        "name": "tampered",
        "type": "bool"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  }
]