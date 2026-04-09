CURVE = "ed25519"
SLIP44_ID = 283
PATTERNS = (
    "m/44'/coin_type'/account'/change'/address_index'",
)
FALCON_SLIP21_PATH = [b"Algorand", b"FALCON-DET1024", b"keygen-v1"]

# Signature scheme tags echoed in AlgorandSignTx.signature_type and
# AlgorandTxSignature.signature_type. Default is Ed25519 to keep wire
# compatibility with hosts that don't know about post-quantum signing.
SIG_ED25519 = 0
SIG_FALCON_DET1024 = 1
