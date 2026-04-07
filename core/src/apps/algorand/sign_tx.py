from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain

from . import CURVE, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import AlgorandSignTx, AlgorandTxSignature
    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, slip44_id=SLIP44_ID, curve=CURVE)
async def sign_tx(
    msg: AlgorandSignTx,
    keychain: Keychain,
) -> AlgorandTxSignature:
    from trezor.crypto.curve import ed25519
    from trezor.crypto.hashlib import sha512_256
    from trezor.messages import AlgorandTxAck, AlgorandTxRequest, AlgorandTxSignature
    from trezor.ui.layouts import show_continue_in_app
    from trezor.wire import DataError, context

    from trezor import TR

    from apps.common import seed

    from .layout import confirm_group_overview, confirm_transaction
    from .transaction import Transaction

    address_n = msg.address_n
    group_size = msg.group_size  # defaults to 1
    group_index = msg.group_index  # defaults to 0

    node = keychain.derive(address_n)
    signer_public_key = seed.remove_ed25519_prefix(node.public_key())

    if group_size < 1 or group_size > 16:
        raise DataError("Invalid group size")
    if group_index != 0:
        raise DataError("First transaction must have group_index = 0")

    # Collect all transactions in the group
    transactions: list[Transaction] = []
    raw_txs: list[bytes] = []

    # Parse the first transaction (from AlgorandSignTx)
    tx_bytes = msg.serialized_tx
    try:
        transaction = Transaction(tx_bytes)
    except Exception:
        raise DataError("Invalid transaction")
    transactions.append(transaction)
    raw_txs.append(tx_bytes)

    # If this is a group, request remaining transactions via TxRequest/TxAck
    for i in range(1, group_size):
        ack: AlgorandTxAck = await context.call(
            AlgorandTxRequest(group_index=i),
            AlgorandTxAck,
        )
        tx_bytes = ack.serialized_tx
        try:
            transaction = Transaction(tx_bytes)
        except Exception:
            raise DataError(f"Invalid transaction at index {i}")
        transactions.append(transaction)
        raw_txs.append(tx_bytes)

    # For groups: verify all transactions share the same group ID
    if group_size > 1:
        # Compute the expected group ID per Algorand spec:
        # 1. Hash each tx WITHOUT the grp field
        # 2. Wrap hashes in TxGroup and hash with "TG" prefix
        from .msgpack import msgpack_encode

        tx_hashes: list[bytes] = []
        for tx in transactions:
            tx_dict = dict(tx.raw)
            tx_dict.pop("grp", None)
            tx_bytes = msgpack_encode(tx_dict)
            tx_hashes.append(sha512_256(b"TX" + tx_bytes).digest())

        txgroup = msgpack_encode({"txlist": tx_hashes})
        expected_group_id = sha512_256(b"TG" + txgroup).digest()

        for i, tx in enumerate(transactions):
            if tx.group_id is None:
                raise DataError(f"Transaction {i} missing group ID")
            if tx.group_id != expected_group_id:
                raise DataError(f"Transaction {i} has wrong group ID")

        # Show group overview before individual transactions
        await confirm_group_overview(transactions)

    # Verify at least one transaction has sender == signer
    signer_tx_indices = [
        i
        for i, tx in enumerate(transactions)
        if tx.sender == signer_public_key
    ]
    if not signer_tx_indices:
        raise DataError("No transaction in the group matches the signer")

    # Show UI confirmation for each transaction
    for i, tx in enumerate(transactions):
        await confirm_transaction(
            tx,
            group_index=i if group_size > 1 else None,
            group_size=group_size if group_size > 1 else None,
        )

    # Sign transactions where sender matches the derived key
    if group_size == 1:
        # Single transaction: sender must match
        if transactions[0].sender != signer_public_key:
            raise DataError("Transaction sender does not match account")
        signature = ed25519.sign(node.private_key(), b"TX" + raw_txs[0])
        show_continue_in_app(TR.send__transaction_signed)
        return AlgorandTxSignature(signature=signature)
    else:
        # Group: sign each transaction where we are the sender
        group_signatures: list[bytes] = []
        for i, (tx, raw_tx) in enumerate(zip(transactions, raw_txs)):
            if tx.sender == signer_public_key:
                sig = ed25519.sign(node.private_key(), b"TX" + raw_tx)
                group_signatures.append(sig)
            else:
                group_signatures.append(b"")  # empty = not our transaction

        show_continue_in_app(TR.send__transaction_signed)
        return AlgorandTxSignature(
            signature=group_signatures[signer_tx_indices[0]],
            group_signatures=group_signatures,
        )
