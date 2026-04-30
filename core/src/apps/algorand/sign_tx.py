from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain

from . import (
    CURVE,
    FALCON_SLIP21_PATH,
    PATTERNS,
    SIG_ED25519,
    SIG_FALCON_DET1024,
    SLIP44_ID,
)

if TYPE_CHECKING:
    from trezor.messages import AlgorandSignTx, AlgorandTxSignature
    from apps.common.keychain import Keychain


@with_slip44_keychain(
    *PATTERNS,
    slip44_id=SLIP44_ID,
    curve=CURVE,
    slip21_namespaces=[FALCON_SLIP21_PATH],
)
async def sign_tx(
    msg: AlgorandSignTx,
    keychain: Keychain,
) -> AlgorandTxSignature:
    from trezor.crypto.curve import ed25519
    from trezor.crypto.hashlib import sha512_256
    from trezor.messages import AlgorandTxAck, AlgorandTxRequest, AlgorandTxSignature
    from trezor.ui.layouts import show_continue_in_app
    from trezor.ui.layouts.progress import progress
    from trezor.wire import DataError, context

    from trezor import TR

    from apps.common import seed

    from .layout import confirm_group_overview, confirm_transaction
    from .transaction import Transaction

    address_n = msg.address_n
    group_size = msg.group_size  # defaults to 1
    group_index = msg.group_index  # defaults to 0
    sig_type = msg.signature_type if msg.signature_type is not None else SIG_ED25519

    if sig_type not in (SIG_ED25519, SIG_FALCON_DET1024):
        raise DataError("Unsupported signature_type")

    node = keychain.derive(address_n)
    signer_public_key = seed.remove_ed25519_prefix(node.public_key())

    falcon_privkey = None
    falcon_spinner = None
    signer_address_bytes = (
        signer_public_key if sig_type == SIG_ED25519 else None
    )

    if group_size < 1 or group_size > 16:
        raise DataError("Invalid group size")
    if group_index != 0:
        raise DataError("First transaction must have group_index = 0")

    # Collect all transactions in the group
    transactions: list[Transaction] = []

    # Parse the first transaction (from AlgorandSignTx)
    tx_bytes = msg.serialized_tx
    try:
        transaction = Transaction(tx_bytes)
    except Exception:
        raise DataError("Invalid transaction")
    transactions.append(transaction)

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

        # Validate that the group has a feasible validity window
        max_fv = max(tx.first_valid for tx in transactions)
        min_lv = min(tx.last_valid for tx in transactions)
        if max_fv > min_lv:
            raise DataError("Group has no valid submission window")

        # Show group overview before individual transactions
        review_all = sig_type == SIG_FALCON_DET1024 or await confirm_group_overview(
            transactions, signer_address_bytes
        )

    try:
        signer_tx_indices: list[int] | None = None
        if sig_type == SIG_ED25519:
            signer_tx_indices = [
                i
                for i, tx in enumerate(transactions)
                if tx.sender == signer_address_bytes
            ]
            if not signer_tx_indices:
                raise DataError("No transaction in the group matches the signer")

        # Show UI confirmation for each transaction.
        # For Ed25519 groups: by default only show transactions we're signing.
        # If the user presses "Review all" (from the context menu), restart
        # the loop and show every transaction in the group.
        # For FALCON groups we defer key generation until after review, so we
        # cannot identify signer-owned transactions yet and review all entries.
        if group_size > 1:
            if sig_type == SIG_FALCON_DET1024:
                visible = list(enumerate(transactions))
                for review_idx, (i, tx) in enumerate(visible):
                    await confirm_transaction(
                        tx,
                        group_index=i,
                        group_size=group_size,
                        signature_type=sig_type,
                        signer_address=None,
                        review_index=review_idx,
                        review_count=len(visible),
                    )
            else:
                while True:
                    restart = False
                    visible = [
                        (i, tx) for i, tx in enumerate(transactions)
                        if review_all or tx.sender == signer_address_bytes
                    ]
                    for review_idx, (i, tx) in enumerate(visible):
                        info_pressed = await confirm_transaction(
                            tx,
                            group_index=i,
                            group_size=group_size,
                            signature_type=sig_type,
                            signer_address=signer_address_bytes,
                            show_review_all=not review_all,
                            review_index=review_idx,
                            review_count=len(visible),
                        )
                        if info_pressed:
                            review_all = True
                            restart = True
                            break
                    if not restart:
                        break
        else:
            await confirm_transaction(
                transactions[0],
                signature_type=sig_type,
            )

        if sig_type == SIG_FALCON_DET1024:
            from .falcon_keys import derive_falcon_keypair
            from .logicsig import derive_falcon_logicsig_address

            falcon_spinner = progress(
                title=TR.progress__signing_transaction,
                indeterminate=True,
            )
            falcon_spinner.start()

            falcon_privkey, falcon_pubkey = derive_falcon_keypair(keychain, address_n)
            signer_address_bytes, _falcon_counter = derive_falcon_logicsig_address(
                falcon_pubkey
            )
            signer_tx_indices = [
                i
                for i, tx in enumerate(transactions)
                if tx.sender == signer_address_bytes
            ]
            if not signer_tx_indices:
                raise DataError("No transaction in the group matches the signer")

        # Sign transactions where sender matches the derived key
        if group_size == 1:
            # Single transaction: sender must match
            if transactions[0].sender != signer_address_bytes:
                raise DataError("Transaction sender does not match account")
            if sig_type == SIG_FALCON_DET1024:
                from .falcon_keys import falcon_sign

                # FALCON LogicSig accounts verify over the 32-byte TxID,
                # not the raw serialized transaction bytes (the on-chain
                # `txn TxID` opcode pushes the hash, not the body).
                txid = sha512_256(b"TX" + transactions[0].serialized_tx).digest()
                signature = falcon_sign(falcon_privkey, txid)
            else:
                signature = ed25519.sign(
                    node.private_key(), b"TX" + transactions[0].serialized_tx
                )
            if falcon_spinner is not None:
                falcon_spinner.stop()
            show_continue_in_app(TR.send__transaction_signed)
            return AlgorandTxSignature(
                signature=signature,
                signature_type=sig_type,
            )
        else:
            # Group: sign each transaction where we are the sender
            group_signatures: list[bytes] = []
            for tx in transactions:
                if tx.sender != signer_address_bytes:
                    group_signatures.append(b"")  # empty = not our transaction
                    continue
                if sig_type == SIG_FALCON_DET1024:
                    from .falcon_keys import falcon_sign

                    txid = sha512_256(b"TX" + tx.serialized_tx).digest()
                    sig = falcon_sign(falcon_privkey, txid)
                else:
                    sig = ed25519.sign(node.private_key(), b"TX" + tx.serialized_tx)
                group_signatures.append(sig)

            if falcon_spinner is not None:
                falcon_spinner.stop()
            show_continue_in_app(TR.send__transaction_signed)
            return AlgorandTxSignature(
                signature=group_signatures[signer_tx_indices[0]],
                group_signatures=group_signatures,
                signature_type=sig_type,
            )
    finally:
        if falcon_spinner is not None:
            falcon_spinner.stop()
        if falcon_privkey is not None:
            from .falcon_keys import zeroize_privkey

            zeroize_privkey(falcon_privkey)
