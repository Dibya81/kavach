"""
blockchain.py
Polygon Amoy smart contract integration.
Handles Web3 init, anchoring FIR hashes, and chain status checks.
Falls back to a deterministic mock when the chain is unreachable.
"""

import time

from .config   import CONTRACT_ADDRESS, PRIVATE_KEY, RPC_URL, CHAIN_ID, CONTRACT_ABI
from .database import db_lock, get_supabase
from .utils    import sha256, now_iso

# ── Module-level state (set by init_web3) ────────────────────────────────────
w3             = None
contract       = None
wallet_address = None
chain_connected = False


def init_web3():
    """Connect to Polygon Amoy RPC and load the deployed contract. Called at startup."""
    global w3, contract, wallet_address, chain_connected
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 30}))
        if w3.is_connected():
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                abi=CONTRACT_ABI
            )
            wallet_address = w3.eth.account.from_key(PRIVATE_KEY).address
            chain_connected = True
            # logger.info(f"Blockchain connected - Amoy - Wallet: {wallet_address}")

            # ── Authorization Check (EvidenceRegistry: authorized mapping + authorizeWallet) ──
            try:
                is_authorized = contract.functions.authorized(wallet_address).call()
                if not is_authorized:
                    # Try to self-authorize (only succeeds if this wallet IS the admin)
                    admin = contract.functions.admin().call()
                    if admin.lower() == wallet_address.lower():
                        nonce = w3.eth.get_transaction_count(wallet_address)
                        tx = contract.functions.authorizeWallet(wallet_address).build_transaction({
                            "from": wallet_address, "nonce": nonce,
                            "gas": 100000, "gasPrice": w3.eth.gas_price, "chainId": CHAIN_ID,
                        })
                        signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
                        w3.eth.send_raw_transaction(signed.raw_transaction)
            except Exception:
                pass
        else:
            # logger.warn("Blockchain RPC unreachable - running in mock mode")
            pass
    except Exception as e:
        # logger.warn(f"Web3 init failed: {e} - running in mock mode")
        pass


def anchor_to_blockchain(fir_id: str, version: int, fir_hash: str) -> dict:
    """
    Send a FIR hash to the on-chain EvidenceRegistry contract.
    Falls back to a mock record if chain is unreachable.
    """
    if chain_connected and w3 and contract:
        try:
            from web3 import Web3
            hash_bytes = bytes.fromhex(fir_hash)
            nonce      = w3.eth.get_transaction_count(wallet_address)
            gas_price  = w3.eth.gas_price

            gas_estimate = contract.functions.anchorFIR(fir_id, hash_bytes).estimate_gas({
                "from": wallet_address,
            })
            tx = contract.functions.anchorFIR(fir_id, hash_bytes).build_transaction({
                "from":     wallet_address,
                "nonce":    nonce,
                "gas":      int(gas_estimate * 1.2),  # 20% buffer
                "gasPrice": gas_price,
                "chainId":  CHAIN_ID,
            })
            signed  = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

            result = {
                "fir_id":      fir_id,
                "version":     version,
                "fir_hash":    fir_hash,
                "tx_hash":     tx_hash.hex(),
                "block_num":   receipt.blockNumber,
                "network":     "Polygon Amoy Testnet",
                "status":      "CONFIRMED" if receipt.status == 1 else "FAILED",
                "anchored_at": now_iso(),
            }
            _persist_record(result)
            return result

        except Exception as e:
            # logger.warn(f"Chain tx failed: {e}")
            pass
            # fall through to mock

    # ── Mock fallback ─────────────────────────────────────────────────────────
    result = {
        "fir_id":      fir_id,
        "version":     version,
        "fir_hash":    fir_hash,
        "tx_hash":     "0x" + sha256(fir_hash + str(time.time()))[:64],
        "block_num":   0,
        "network":     "Polygon Amoy (mock - chain unreachable)",
        "status":      "MOCK",
        "anchored_at": now_iso(),
    }
    _persist_record(result)
    return result


def verify_on_chain(fir_id: str, fir_hash: str, on_chain_hash: str) -> bool:
    """
    Call verifyFIR on the contract. Falls back to local hash comparison.
    """
    if chain_connected and contract:
        try:
            from web3 import Web3
            valid, _ = contract.functions.verifyFIR(
                fir_id, 1, bytes.fromhex(fir_hash)
            ).call()
            return valid
        except Exception:
            pass
    # Local fallback
    return on_chain_hash == fir_hash if on_chain_hash else False


def get_chain_status() -> dict:
    """Return current blockchain connection status and wallet info."""
    status = {
        "connected":    chain_connected,
        "rpc":          RPC_URL,
        "contract":     CONTRACT_ADDRESS,
        "wallet":       wallet_address,
        "network":      "Polygon Amoy Testnet",
        "chain_id":     CHAIN_ID,
    }
    if chain_connected and w3:
        try:
            status["block"]         = w3.eth.block_number
            status["balance_matic"] = round(
                float(w3.from_wei(w3.eth.get_balance(wallet_address), "ether")), 6
            )
            # Pull real on-chain stats from EvidenceRegistry.getPlatformStats()
            fir_c, kyc_c, doc_c, tamper_c, block_n, admin_a = contract.functions.getPlatformStats().call()
            status["chain_fir_count"]     = fir_c
            status["chain_tamper_events"] = tamper_c
            status["chain_block_number"]  = block_n
        except Exception:
            pass
    return status


def _persist_record(record: dict):
    """Save a blockchain anchor record to the blockchain_records table."""
    try:
        from .database import get_supabase
        get_supabase().table("blockchain_records").insert({
            "record_type":  "fir",
            "reference_id": record["fir_id"],
            "tx_hash":      record["tx_hash"],
            "block_number": record["block_num"],
            "data_hash":    record["fir_hash"],
            "network":      record["network"],
            "status":       "confirmed" if record["status"] == "CONFIRMED" else "pending",
        }).execute()
    except Exception as e:
        # logger.warn(f"Failed to persist blockchain record: {e}")
        pass
