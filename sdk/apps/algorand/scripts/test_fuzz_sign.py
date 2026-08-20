# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "py-algorand-sdk>=2.7",
#     "pynacl>=1.5",
# ]
# ///
"""
Fuzz-test Algorand transaction signing through the Trezor extapp.

Generates randomised valid unsigned transactions of every type the app
supports, optionally bound into atomic groups, sends them to the device,
and checks that the returned Ed25519 signatures verify against the
sender's public key.

Usage
-----
    # Test all types, randomised, 10 iterations each
    uv run scripts/test_fuzz_sign.py --count 10

    # Only payment and keyreg, group size 2-4
    uv run scripts/test_fuzz_sign.py --kinds pay,keyreg --group-min 2 --group-max 4

    # Singletons only (no groups)
    uv run scripts/test_fuzz_sign.py --group-max 1

    # Applications at varying on-completion values
    uv run scripts/test_fuzz_sign.py --kinds appl --count 20 --seed 42

    # Stress: maximal-size transactions (large app creates, big groups)
    uv run scripts/test_fuzz_sign.py --stress --count 2 --seed 42

    # Negative: malformed/oversized/tampered payloads the device must reject
    uv run scripts/test_fuzz_sign.py --negative --count 3 --seed 42
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import random
import sys
from pathlib import Path

# --- Ensure local monorepo trezorlib is found before the PyPI version ---
# (py-algorand-sdk pulls in the public `trezor` which lacks trezorapp).
_trezor_path = Path(__file__).parent.parent.parent.parent.parent / "python" / "src"
if _trezor_path.exists():
    sys.path.insert(0, str(_trezor_path))

from algosdk import encoding, transaction
from trezorlib import messages, protobuf
from trezorlib.debuglink import TrezorTestContext
from trezorlib.exceptions import TrezorFailure
from trezorlib.transport import get_transport

sys.path.insert(0, str(Path(__file__).parent))
from algorand_messages import (
    AlgorandSignTransactions,
    AlgorandTxAck,
    AlgorandTxRequest,
    AlgorandTransactionSignatures,
)
from app_loader import add_app_args, load_app

# ── helpers ─────────────────────────────────────────────────────────

def rand_pk() -> bytes:
    """A random 32-byte public key (not derived from any seed)."""
    return os.urandom(32)


def rand_addr() -> str:
    """Random valid Algorand address string."""
    return encoding.encode_address(rand_pk())


def rand_genesis_hash() -> bytes:
    return os.urandom(32)


def rand_genesis_id() -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))


MAX_U64 = 2**64 - 1

# Real public-network genesis hashes, so the device's network-name lookup
# (Mainnet/Testnet/Betanet) gets exercised, not only the "Unknown" path.
KNOWN_GENESIS = {
    "mainnet-v1.0": base64.b64decode("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="),
    "testnet-v1.0": base64.b64decode("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="),
    "betanet-v1.0": base64.b64decode("mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0="),
}


def choose_network(rng: random.Random) -> "tuple[bytes, str | None]":
    """Pick a shared (genesis_hash, genesis_id) for a transaction/group.

    ~40% of the time a real public network (exercises the name lookup); else a
    random hash (the "Unknown" path), sometimes with a random genesis id.
    """
    if rng.random() < 0.4:
        gid = rng.choice(list(KNOWN_GENESIS))
        return KNOWN_GENESIS[gid], gid
    return rand_genesis_hash(), (rand_genesis_id() if rng.random() < 0.3 else None)


def decorate(txn: transaction.Transaction, rng: random.Random) -> None:
    """Randomly attach the common transaction-header fields so every type
    exercises them, and hit fee boundaries. genesis_hash/genesis_id are shared
    per group and set by the caller.
    """
    # Fee: exercise zero, typical, large, and the u64 ceiling.
    txn.fee = rng.choice([0, 1000, rng.randint(1_000, 10_000_000), MAX_U64])
    if rng.random() < 0.4:  # note (up to MAX_NOTE_LEN = 1024)
        txn.note = os.urandom(rng.choice([1, rng.randint(1, 1024), 1024]))
    if rng.random() < 0.2:  # lease
        txn.lease = os.urandom(32)
    if rng.random() < 0.2:  # rekey — a header field valid on any type
        txn.rekey_to = rand_addr()


#: ed25519 signing-domain prefix Algorand prepends before signing a txn.
TX_DOMAIN = b"TX"


def canonical_txn_bytes(txn: transaction.Transaction, *, grp: bytes | None = None) -> bytes:
    """Canonical msgpack of the bare transaction map — exactly what the device
    parses. Encoding is delegated to the reference implementation (algosdk);
    the only tweak is setting the atomic-group field for a group member."""
    txn.group = grp
    return base64.b64decode(encoding.msgpack_encode(txn))


def suggested_params(gh: bytes, fv: int | None = None, lv: int | None = None) -> transaction.SuggestedParams:
    """Minimal suggested-params stub (device ignores consensus fee minimums)."""
    return transaction.SuggestedParams(
        fee=0,
        first=fv or random.randint(1, 100),
        last=lv or random.randint(fv + 1, fv + 900) if fv else random.randint(101, 1000),
        gh=base64.b64encode(gh).decode(),  # algosdk expects base64, not hex
        gen=None,
        flat_fee=True,
        consensus_version="https://github.com/nullun/tiny-algo",
        min_fee=0,
    )


def make_pay(rng: random.Random) -> tuple[transaction.PaymentTxn, bytes]:
    snd = rand_addr()
    rcv = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh)
    amt = rng.randint(0, 10_000_000_000)  # up to 10k ALGO
    close = rand_addr() if rng.random() < 0.3 else None
    note = os.urandom(rng.randint(0, 128))
    txn = transaction.PaymentTxn(
        sender=snd,
        sp=sp,
        receiver=rcv,
        amt=amt,
        close_remainder_to=close,
        note=note,
    )
    return txn, gh


def make_keyreg(rng: random.Random) -> tuple[transaction.Transaction, bytes]:
    snd = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh)
    mode = rng.choice(["online", "offline", "nonpart"])
    # Dedicated keyreg classes so algosdk emits canonical bytes directly:
    # offline omits the vote keys, nonpart sets the flag, online carries them.
    if mode == "online":
        txn = transaction.KeyregOnlineTxn(
            sender=snd, sp=sp,
            votekey=base64.b64encode(rng.randbytes(32)).decode(),
            selkey=base64.b64encode(rng.randbytes(32)).decode(),
            sprfkey=base64.b64encode(rng.randbytes(64)).decode(),
            votefst=rng.randint(1, 1000),
            votelst=rng.randint(2000, 5000),
            votekd=rng.randint(1, 1000),
        )
    elif mode == "nonpart":
        txn = transaction.KeyregNonparticipatingTxn(sender=snd, sp=sp)
    else:  # offline
        txn = transaction.KeyregOfflineTxn(sender=snd, sp=sp)
    return txn, gh


def make_axfer(rng: random.Random) -> tuple[transaction.AssetTransferTxn, bytes]:
    snd = rand_addr()
    rcv = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh)
    xaid = rng.randint(1, 2**63 - 1)
    aamt = rng.randint(1, 1_000_000)
    asnd = rand_addr() if rng.random() < 0.3 else None
    aclose = None if asnd else (rand_addr() if rng.random() < 0.3 else None)
    txn = transaction.AssetTransferTxn(
        sender=snd, sp=sp,
        receiver=rcv,
        amt=aamt,
        index=xaid,
        close_assets_to=aclose,
        revocation_target=asnd,
    )
    return txn, gh


def make_afrz(rng: random.Random) -> tuple[transaction.AssetFreezeTxn, bytes]:
    snd = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh)
    faid = rng.randint(1, 2**63 - 1)
    fadd = rand_addr()
    frozen = rng.choice([True, False])
    txn = transaction.AssetFreezeTxn(
        sender=snd, sp=sp,
        index=faid,
        target=fadd,
        new_freeze_state=frozen,
    )
    return txn, gh


def make_acfg(rng: random.Random) -> tuple[transaction.AssetConfigTxn, bytes]:
    snd = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh)
    mode = rng.choice(["create", "reconfig", "destroy"])
    if mode == "create":
        # Roles are individually optional; omitting one renders as "Empty"
        # (and permanently disables it), so leave some out at random.
        role = lambda: rand_addr() if rng.random() < 0.7 else None
        txn = transaction.AssetConfigTxn(
            sender=snd, sp=sp,
            index=0,
            total=rng.choice([1, rng.randint(1, 10_000_000_000), MAX_U64]),
            decimals=rng.randint(0, 19),
            default_frozen=rng.choice([True, False]),
            unit_name="".join(rng.choices("ABCDEFGH", k=rng.randint(1, 8))),
            asset_name="".join(rng.choices("abcdefghijklmnopqrstuvwxyz ", k=rng.randint(1, 24))),
            url="https://example.com/asset",
            manager=role(),
            reserve=role(),
            freeze=role(),
            clawback=role(),
            metadata_hash=(os.urandom(32) if rng.random() < 0.5 else None),
            strict_empty_address_check=False,
        )
    elif mode == "reconfig":
        txn = transaction.AssetConfigTxn(
            sender=snd, sp=sp,
            index=rng.randint(1, 2**63 - 1),
            manager=rand_addr(),
            reserve=rand_addr(),
            strict_empty_address_check=False,
        )
    else:  # destroy
        txn = transaction.AssetConfigTxn(
            sender=snd, sp=sp,
            index=rng.randint(1, 2**63 - 1),
            strict_empty_address_check=False,
        )
    return txn, gh


_ON_COMPLETIONS = [0, 1, 2, 3, 4, 5]  # NoOp … DeleteApp


def make_appl(rng: random.Random) -> tuple[transaction.ApplicationCallTxn, bytes]:
    snd = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh)
    oc = rng.choice(_ON_COMPLETIONS)
    apid = 0 if oc in (0, 4, 5) and rng.random() < 0.4 else rng.randint(1, 1000)

    approval = b"#pragma version 10\nint 1" if apid == 0 else None
    clear = b"#pragma version 10\nint 1" if apid == 0 else None

    # Box references (opt-in): reference the called app itself (index 0).
    boxes = (
        [transaction.BoxReference(app_index=0, name=os.urandom(rng.randint(1, 8)))
         for _ in range(rng.randint(1, 2))]
        if rng.random() < 0.3 else None
    )

    txn = transaction.ApplicationCallTxn(
        sender=snd, sp=sp,
        index=apid if apid else 0,
        on_complete=oc,
        approval_program=approval or b"",
        clear_program=clear or b"",
        global_schema=transaction.StateSchema(
            num_uints=rng.randint(0, 4),
            num_byte_slices=rng.randint(0, 4),
        ) if apid == 0 else None,
        local_schema=transaction.StateSchema(
            num_uints=rng.randint(0, 4),
            num_byte_slices=rng.randint(0, 4),
        ) if apid == 0 else None,
        app_args=[rng.randbytes(rng.randint(1, 20)) for _ in range(rng.randint(0, 3))],
        accounts=[rand_addr() for _ in range(rng.randint(0, 2))],
        foreign_apps=[rng.randint(1, 500) for _ in range(rng.randint(0, 2))],
        foreign_assets=[rng.randint(1, 500) for _ in range(rng.randint(0, 2))],
        extra_pages=rng.randint(0, 3) if apid == 0 else 0,
        boxes=boxes,
        # reject_version is only valid on a call; the device rejects it on create.
        reject_version=rng.randint(1, 5) if (apid != 0 and rng.random() < 0.2) else 0,
    )
    return txn, gh


# Map kind name → generator.
GENERATORS = {
    "pay":    make_pay,
    "keyreg": make_keyreg,
    "axfer":  make_axfer,
    "afrz":   make_afrz,
    "acfg":   make_acfg,
    "appl":   make_appl,
}


# ── stress-test generators (maximal-size transactions) ────────────

def make_stress_pay(rng: random.Random) -> tuple[transaction.PaymentTxn, bytes]:
    """Payment with a max-size note (1024 bytes via algosdk; tiny-algo
    permits 4096 for forward compatibility)."""
    snd = rand_addr()
    rcv = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh, fv=1, lv=1000)
    note = os.urandom(1024)  # algosdk caps at 1024; tiny-algo at 4096
    txn = transaction.PaymentTxn(
        sender=snd, sp=sp,
        receiver=rcv, amt=1_000_000,
        note=note,
    )
    return txn, gh


def make_stress_appl(rng: random.Random) -> tuple[transaction.ApplicationCallTxn, bytes]:
    """Application create at the protocol program-size ceiling (~10 KiB).

    With 3 extra pages the approval + clear programs may total 4×2048 = 8192
    bytes; combined with the max total arg length (2048) and the reference
    lists, this is about the largest a single application transaction can be.
    """
    snd = rand_addr()
    gh = rand_genesis_hash()
    sp = suggested_params(gh, fv=1, lv=1000)
    txn = transaction.ApplicationCallTxn(
        sender=snd, sp=sp,
        index=0,
        on_complete=0,  # NoOp create
        approval_program=os.urandom(4096),
        clear_program=os.urandom(4096),  # 4096 + 4096 = 4×2048 (extra_pages=3)
        extra_pages=3,
        global_schema=transaction.StateSchema(num_uints=8, num_byte_slices=8),
        local_schema=transaction.StateSchema(num_uints=8, num_byte_slices=8),
        app_args=[os.urandom(512) for _ in range(4)],  # 4×512 = 2048 max total
        accounts=[rand_addr() for _ in range(4)],
        foreign_apps=[rng.randint(1, 100) for _ in range(2)],
        foreign_assets=[rng.randint(1, 100) for _ in range(2)],
    )
    return txn, gh


STRESS_GENERATORS = {
    "pay":  make_stress_pay,
    "appl": make_stress_appl,
}


# ── negative / rejection generators ──────────────────────────────────
#
# Each returns ``(payload, total_size)`` for a SignTransactions request the
# device must REJECT (return a Failure) — never accept and never crash. The
# `total_size` override forges the chunked-upload length field; it is None for
# ordinary single-message sends.

#: Device limits (src/main.rs): `MAX_TXN_GROUP_SIZE` and `MAX_TXN_GROUP_BYTES`.
DEVICE_MAX_GROUP_SIZE = 16
DEVICE_MAX_GROUP_BYTES = 96 * 1024


def _valid_pay(rng: random.Random, gh: bytes | None = None, gen: str | None = None) -> transaction.PaymentTxn:
    """A single well-formed payment, optionally pinned to a shared network."""
    txn, _ = make_pay(rng)
    if gh is not None:
        txn.genesis_hash = base64.b64encode(gh).decode()
        txn.genesis_id = gen
    return txn


def neg_too_many_members(rng: random.Random) -> tuple[bytes, int | None]:
    """MAX+1 concatenated members. The device rejects on the member-count cap
    before any group check, so no group ID is needed (algosdk itself refuses to
    compute one for >16 members)."""
    gh, gen = choose_network(rng)
    txns = [_valid_pay(rng, gh, gen) for _ in range(DEVICE_MAX_GROUP_SIZE + 1)]
    return b"".join(canonical_txn_bytes(t, grp=None) for t in txns), None


def neg_forged_group_id(rng: random.Random) -> tuple[bytes, int | None]:
    """Two valid members carrying a group ID that is not their real one. The
    device must recompute the group ID over the members and reject the forgery
    (otherwise a member could be spliced into an unrelated group)."""
    gh, gen = choose_network(rng)
    txns = [_valid_pay(rng, gh, gen) for _ in range(2)]
    real = transaction.calculate_group_id(txns)
    forged = os.urandom(32)
    while forged == real:
        forged = os.urandom(32)
    return b"".join(canonical_txn_bytes(t, grp=forged) for t in txns), None


def neg_truncated(rng: random.Random) -> tuple[bytes, int | None]:
    """A valid transaction cut off mid-msgpack."""
    blob = canonical_txn_bytes(_valid_pay(rng), grp=None)
    return blob[: rng.randint(1, max(1, len(blob) - 1))], None


def neg_trailing_garbage(rng: random.Random) -> tuple[bytes, int | None]:
    """A valid transaction with extra bytes appended — parsed as the start of a
    second member, which is not valid msgpack."""
    blob = canonical_txn_bytes(_valid_pay(rng), grp=None)
    return blob + os.urandom(rng.randint(1, 64)), None


def neg_garbage(rng: random.Random) -> tuple[bytes, int | None]:
    """Random bytes — not a msgpack map at all."""
    return os.urandom(rng.randint(1, 256)), None


def neg_empty(rng: random.Random) -> tuple[bytes, int | None]:
    """Empty payload — no transaction to sign."""
    return b"", None


def neg_oversized_total(rng: random.Random) -> tuple[bytes, int | None]:
    """A small chunk declaring a total_size beyond the group-bytes cap; the
    device must reject the buffer request up front rather than allocate it."""
    blob = canonical_txn_bytes(_valid_pay(rng), grp=None)
    return blob, DEVICE_MAX_GROUP_BYTES + rng.randint(1, 64 * 1024)


#: name → generator. Every case here must be rejected by a correct device.
NEGATIVE_CASES = [
    ("too_many_members",  neg_too_many_members),
    ("forged_group_id",   neg_forged_group_id),
    ("truncated_msgpack", neg_truncated),
    ("trailing_garbage",  neg_trailing_garbage),
    ("garbage_bytes",     neg_garbage),
    ("empty_payload",     neg_empty),
    ("oversized_total",   neg_oversized_total),
]


# ── verify signature (ed25519) ──────────────────────────────────────

def verify_sig(txn_bytes: bytes, sig: bytes, pk: bytes) -> bool:
    """Verify an ed25519 signature over ``TX`` || txn_bytes."""
    from nacl.signing import VerifyKey
    msg = TX_DOMAIN + txn_bytes
    try:
        VerifyKey(pk).verify(msg, sig)
        return True
    except Exception:
        return False


# ── test runner ─────────────────────────────────────────────────────

BIP44_ALGORAND = 44 | 0x80000000, 283 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000

CHUNK_SIZE = 7000  # leave room for protobuf envelope overhead


def confirm_flow(client):
    """Input flow: page to the end of each review screen, then confirm.

    Uses the framework's semantic confirm (press_yes / DebugButton.YES), which
    completes both tap-through and hold-to-confirm screens with no manual hold
    and independent of animation state.
    """
    debug = client.debug
    while True:
        yield
        layout = debug.read_layout()
        for _ in range(max(0, layout.page_count() - 1)):
            debug.click(debug.screen_buttons.ok())
            layout = debug.read_layout()
        debug.press_yes()


def send_and_sign(session, instance_id: int, txns: list[bytes]) -> list[bytes]:
    """Send a batch of txns to the device and return signatures.

    Auto-confirms every review screen via the debug input flow, so the fuzzer
    runs unattended. Large payloads are split via the chunked-upload protocol:
    SignTransactions carries the first chunk plus total_size, then the device
    pulls the rest with TxRequest, each answered by a TxAck; it replies
    TransactionSignatures once the advertised total has arrived.
    """
    payload = b"".join(txns)
    total = len(payload)

    with session.test_ctx as client:
        client.set_input_flow(confirm_flow(client))

        if total <= CHUNK_SIZE:
            return _send_single(session, instance_id, payload)

        # Chunked upload.
        chunk0 = payload[:CHUNK_SIZE]
        request = AlgorandSignTransactions(
            address_n=list(BIP44_ALGORAND),
            transactions=chunk0,
            total_size=total,
        )
        buf = io.BytesIO()
        protobuf.dump_message(buf, request)
        envelope = messages.TrezorAppMessage(
            instance_id=instance_id,
            message_id=2,  # SignTransactions
            data=buf.getvalue(),
        )
        resp = session.call(envelope, expect=messages.TrezorAppResponse)

        offset = CHUNK_SIZE
        while resp.message_id == 4:  # TxRequest
            tx_request = protobuf.load_message(io.BytesIO(resp.data), AlgorandTxRequest)
            size = min(tx_request.data_length, CHUNK_SIZE)
            next_chunk = payload[offset: offset + size]
            offset += len(next_chunk)
            ack = AlgorandTxAck(data=next_chunk)
            buf = io.BytesIO()
            protobuf.dump_message(buf, ack)
            envelope = messages.TrezorAppMessage(
                instance_id=instance_id,
                message_id=5,  # TxAck
                data=buf.getvalue(),
            )
            resp = session.call(envelope, expect=messages.TrezorAppResponse)

        response = protobuf.load_message(io.BytesIO(resp.data), AlgorandTransactionSignatures)
        return [r.signature for r in response.signatures]


def _send_single(session, instance_id: int, payload: bytes) -> list[bytes]:
    request = AlgorandSignTransactions(
        address_n=list(BIP44_ALGORAND),
        transactions=payload,
    )
    buf = io.BytesIO()
    protobuf.dump_message(buf, request)
    envelope = messages.TrezorAppMessage(
        instance_id=instance_id,
        message_id=2,
        data=buf.getvalue(),
    )
    resp = session.call(envelope, expect=messages.TrezorAppResponse)
    response = protobuf.load_message(io.BytesIO(resp.data), AlgorandTransactionSignatures)
    return [r.signature for r in response.signatures]


def _send_raw(session, instance_id: int, payload: bytes, total_size: int | None = None) -> list[bytes]:
    """Send one SignTransactions message (no chunking, no input flow) and return
    any signatures. Negative payloads are rejected at parse/validation before
    any confirmation UI, so no auto-confirm is needed; a payload that instead
    reaches signing returns signatures here and is flagged as under-rejection."""
    # total_size=None leaves the optional field unset (a plain single send).
    request = AlgorandSignTransactions(
        address_n=list(BIP44_ALGORAND),
        transactions=payload,
        total_size=total_size,
    )
    buf = io.BytesIO()
    protobuf.dump_message(buf, request)
    envelope = messages.TrezorAppMessage(
        instance_id=instance_id, message_id=2, data=buf.getvalue()
    )
    resp = session.call(envelope, expect=messages.TrezorAppResponse)
    response = protobuf.load_message(io.BytesIO(resp.data), AlgorandTransactionSignatures)
    return [r.signature for r in response.signatures]


def _first_line(s: str) -> str:
    lines = [ln for ln in s.strip().splitlines() if ln.strip()]
    return lines[0][:80] if lines else "<no message>"


def reload_app(ctx, args) -> "tuple[object, int]":
    """Recover after a suspected app crash: fresh session + reload the app."""
    session = ctx.get_session()
    return session, load_app(session, args)


def run_negative_suite(session, instance_id: int, ctx, args) -> int:
    """Run the rejection suite. Returns an exit code (0 = all rejected cleanly).

    Each case must be REJECTED (device returns a Failure). Accepting a bad
    payload (returning signatures) or crashing the app both fail the suite; a
    crash additionally triggers an app reload so the run can continue.
    """
    print("Negative mode: malformed / oversized / tampered payloads "
          "(the device must reject every one)\n")
    total = rejected = 0
    accepted: list[str] = []
    crashed: list[str] = []

    for name, gen in NEGATIVE_CASES:
        for i in range(args.count):
            total += 1
            rng = random.Random(f"{args.seed}-neg-{name}-{i}" if args.seed is not None else None)
            payload, total_size = gen(rng)
            tag = f"{name}[{i}]"
            try:
                sigs = _send_raw(session, instance_id, payload, total_size)
                accepted.append(tag)
                print(f"  FAIL  [{total:3d}] {name}: ACCEPTED ({len(sigs)} sigs) "
                      f"— device signed a payload it should have rejected")
            except TrezorFailure as e:
                rejected += 1
                print(f"  OK    [{total:3d}] {name}: rejected — {_first_line(str(e))}")
            except Exception as e:
                crashed.append(tag)
                print(f"  CRASH [{total:3d}] {name}: {type(e).__name__}: {e}")
                if args.seed is not None:
                    print(f"        (seed={args.seed}, case={name}, iter={i})")
                # The app task likely died; reload a fresh instance to continue.
                try:
                    session, instance_id = reload_app(ctx, args)
                    print(f"        reloaded app (instance {instance_id})")
                except Exception as re:
                    print(f"        reload FAILED ({re}); aborting suite.")
                    break
        else:
            continue
        break  # a failed reload broke the inner loop → stop entirely

    print(f"\n{'='*60}")
    print(f"Rejected cleanly: {rejected}/{total}")
    if accepted:
        print(f"UNDER-REJECTED  : {len(accepted)}  {', '.join(accepted)}")
    if crashed:
        print(f"CRASHED         : {len(crashed)}  {', '.join(crashed)}")
    if not accepted and not crashed:
        print("All negative cases rejected cleanly!")
        return 0
    return 1


def describe_txn(kind: str, txn: transaction.Transaction) -> str:
    """One-line description for logging."""
    if kind == "pay":
        return f"pay amt={txn.amt} from={txn.sender[:8]}… to={txn.receiver[:8]}…"
    elif kind == "keyreg":
        return f"keyreg nonpart={getattr(txn, 'nonpart', False)}"
    elif kind == "axfer":
        return f"axfer xaid={txn.index} amt={txn.amount}"
    elif kind == "afrz":
        return f"afrz faid={txn.index} frozen={txn.new_freeze_state}"
    elif kind == "acfg":
        if txn.index == 0:
            return f"acfg create"
        elif hasattr(txn, 'asset_name') and txn.asset_name:
            return f"acfg reconfig id={txn.index}"
        else:
            return f"acfg destroy id={txn.index}"
    elif kind == "appl":
        return f"appl oc={txn.on_complete} apid={txn.index}"
    return kind


def main():
    parser = argparse.ArgumentParser(description="Fuzz-test Algorand transaction signing")
    parser.add_argument("--count", type=int, default=5,
                        help="Number of iterations per kind-group-size combination")
    parser.add_argument("--kinds", type=str, default="all",
                        help="Comma-separated list: pay,keyreg,axfer,afrz,acfg,appl (or 'all')")
    parser.add_argument("--group-min", type=int, default=1,
                        help="Minimum group size (1 = singletons)")
    parser.add_argument("--group-max", type=int, default=8,
                        help="Maximum group size (max 16)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip signature verification (offline dev)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate and validate txns locally, skip device")
    parser.add_argument("--interactive", action="store_true",
                        help="Wait for manual confirmation on each prompt")
    parser.add_argument("--stress", action="store_true",
                        help="Stress-test with maximal-size transactions")
    parser.add_argument("--negative", action="store_true",
                        help="Rejection-test with malformed/oversized/tampered payloads")
    add_app_args(parser)
    args = parser.parse_args()

    if args.negative and args.dry_run:
        sys.exit("--negative requires a device (cannot be combined with --dry-run)")

    if args.seed is not None:
        random.seed(args.seed)

    if args.stress:
        kinds = list(STRESS_GENERATORS)
        generators = STRESS_GENERATORS
        print("Stress mode: maximal-size transactions\n")
    elif args.kinds == "all":
        kinds = list(GENERATORS)
        generators = GENERATORS
    else:
        kinds = [k.strip() for k in args.kinds.split(",")]
        generators = GENERATORS
        for k in kinds:
            if k not in GENERATORS:
                sys.exit(f"Unknown kind '{k}'. Valid: {', '.join(GENERATORS)}")

    group_max = min(args.group_max, 16)
    group_min = max(args.group_min, 1)
    if args.stress:
        # Stress: default to a range from a single maximal txn up to a group
        # of 8. A ~10 KiB stress-appl × 8 is ~80 KiB — near the device's 96 KiB
        # group cap and well past CHUNK_SIZE, so it exercises the chunked upload
        # and the group-staging buffer without exceeding the limit.
        if not any(a in sys.argv for a in ("--group-min", "--group-max")):
            group_min = 1
            group_max = 8
    if group_min > group_max:
        sys.exit("--group-min must be <= --group-max")

    if args.dry_run:
        print("Dry-run mode: generating transactions locally, no device.\n")
        session = None
        instance_id = 0
        device_pk = b"\x00" * 32
    else:
        # Debug session so the on-device confirmations can be driven
        # automatically (via confirm_flow), letting the fuzzer run unattended.
        transport = get_transport(os.environ.get("TREZOR_PATH"))
        ctx = TrezorTestContext(transport, auto_interact=True)
        session = ctx.get_session()
        instance_id = load_app(session, args)
        print(f"App loaded (instance {instance_id}).\n")

        # Derive the sender public key once for the BIP-32 path we use.
        from algorand_messages import AlgorandGetPublicKey, AlgorandPublicKey
        pk_req = AlgorandGetPublicKey(
            address_n=list(BIP44_ALGORAND),
            show_display=False,
        )
        pk_buf = io.BytesIO()
        protobuf.dump_message(pk_buf, pk_req)
        pk_envelope = messages.TrezorAppMessage(
            instance_id=instance_id,
            message_id=0,  # GetPublicKey
            data=pk_buf.getvalue(),
        )
        pk_resp = session.call(pk_envelope, expect=messages.TrezorAppResponse)
        pk_msg = protobuf.load_message(io.BytesIO(pk_resp.data), AlgorandPublicKey)
        device_pk = pk_msg.public_key
        print(f"Device public key: {device_pk.hex()}")
        print(f"Device address:    {pk_msg.address}\n")

    if args.negative:
        sys.exit(run_negative_suite(session, instance_id, ctx, args))

    total_tests = 0
    total_passed = 0

    for group_size in range(group_min, group_max + 1):
        for kind in kinds:
            for i in range(args.count):
                total_tests += 1
                rng = random.Random(f"{args.seed}-{kind}-{group_size}-{i}" if args.seed else None)
                try:
                    txns_blobs: list[bytes] = []
                    txn_objs: list[transaction.Transaction] = []
                    genesis_hashes: list[bytes] = []

                    # All members share one network (genesis hash + id) so the
                    # device validates the group consistently.
                    shared_gh, shared_gen = choose_network(rng)
                    shared_gh_b64 = base64.b64encode(shared_gh).decode()
                    for _ in range(group_size):
                        gen = generators[kind]
                        txn_obj, _ = gen(rng)
                        # algosdk stores genesis_hash as base64 internally.
                        txn_obj.genesis_hash = shared_gh_b64
                        txn_obj.genesis_id = shared_gen
                        # Random header fields (fee/note/lease/rekey) on every type.
                        decorate(txn_obj, rng)
                        # Encode without grp first for group-ID computation.
                        blob = canonical_txn_bytes(txn_obj, grp=None)
                        txns_blobs.append(blob)
                        txn_objs.append(txn_obj)

                    # If group, compute the group ID (algosdk) and re-encode
                    # each member carrying it.
                    if group_size >= 2:
                        gid = transaction.calculate_group_id(txn_objs)
                        txns_blobs = [
                            canonical_txn_bytes(txn_objs[i], grp=gid)
                            for i in range(group_size)
                        ]

                    if args.dry_run:
                        # No device: generation already ran each member through
                        # algosdk's canonical encoder and calculate_group_id
                        # (either raises on an invalid txn), so just sanity-check
                        # that non-empty canonical bytes came out.
                        sigs = [b"\x00" * 64] * group_size
                        for blob in txns_blobs:
                            assert len(blob) > 0, "empty txn blob"
                    else:
                        # Send to device.
                        sigs = send_and_sign(session, instance_id, txns_blobs)

                    assert len(sigs) == group_size, \
                        f"Expected {group_size} signatures, got {len(sigs)}"

                    # Verify signatures.
                    if not args.no_verify and not args.dry_run:
                        for idx, sig in enumerate(sigs):
                            ok = verify_sig(txns_blobs[idx], sig, device_pk)
                            assert ok, f"Signature verification failed for txn {idx}"

                    descs = "; ".join(describe_txn(kind, t) for t in txn_objs)
                    print(f"  OK  [{total_tests:3d}] {kind} ×{group_size}  {descs}")
                    total_passed += 1

                except Exception as e:
                    print(f"  FAIL [{total_tests:3d}] {kind} ×{group_size}: {e}")
                    if args.seed is not None:
                        print(f"        (seed={args.seed}, kind={kind}, group={group_size}, iter={i})")

    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total_tests} passed")
    if total_passed == total_tests:
        print("All tests passed!")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
