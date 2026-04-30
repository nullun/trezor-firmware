# flake8: noqa: F403,F405
from common import *  # isort:skip

from apps.algorand.msgpack import msgpack_encode
from apps.algorand.transaction import Transaction
from apps.algorand.types import TxType


class TestTransactionParser(unittest.TestCase):

    def _make_canonical_payment(
        self,
        sender: bytes = b"\x01" * 32,
        receiver: bytes = b"\x02" * 32,
        amount: int = 1000000,
        fee: int = 1000,
        first_valid: int = 1000,
        last_valid: int = 2000,
        genesis_hash: bytes = b"\x03" * 32,
    ) -> bytes:
        """Build a minimal canonical MsgPack payment transaction.

        Canonical encoding: fixmap, keys sorted lexicographically,
        minimal integer types, zero-valued fields omitted.
        """
        import struct

        parts = []
        fields = {}

        # Collect non-zero fields with their MsgPack keys
        fields["amt"] = amount
        fields["fee"] = fee
        fields["fv"] = first_valid
        fields["gh"] = genesis_hash
        fields["lv"] = last_valid
        fields["rcv"] = receiver
        fields["snd"] = sender
        fields["type"] = "pay"

        # Sort keys lexicographically (canonical)
        sorted_keys = sorted(fields.keys())

        # Encode as fixmap
        parts.append(bytes([0x80 | len(sorted_keys)]))

        for key in sorted_keys:
            # Encode key as fixstr
            key_bytes = key.encode("utf-8")
            parts.append(bytes([0xA0 | len(key_bytes)]) + key_bytes)

            # Encode value
            val = fields[key]
            if isinstance(val, str):
                val_bytes = val.encode("utf-8")
                parts.append(bytes([0xA0 | len(val_bytes)]) + val_bytes)
            elif isinstance(val, bytes):
                # bin8 for 32-byte fields
                parts.append(bytes([0xC4, len(val)]) + val)
            elif isinstance(val, int):
                if val <= 0x7F:
                    parts.append(bytes([val]))
                elif val <= 0xFF:
                    parts.append(bytes([0xCC, val]))
                elif val <= 0xFFFF:
                    parts.append(bytes([0xCD]) + struct.pack(">H", val))
                elif val <= 0xFFFFFFFF:
                    parts.append(bytes([0xCE]) + struct.pack(">I", val))
                else:
                    parts.append(bytes([0xCF]) + struct.pack(">Q", val))

        return b"".join(parts)

    def test_parse_payment(self):
        raw = self._make_canonical_payment()
        tx = Transaction(raw)
        self.assertEqual(tx.tx_type, TxType.PAYMENT)
        self.assertEqual(tx.sender, b"\x01" * 32)
        self.assertEqual(tx.fee, 1000)
        self.assertEqual(tx.first_valid, 1000)
        self.assertEqual(tx.last_valid, 2000)
        self.assertEqual(tx.genesis_hash, b"\x03" * 32)
        self.assertEqual(tx.type_data["receiver"], b"\x02" * 32)
        self.assertEqual(tx.type_data["amount"], 1000000)
        self.assertIsNone(tx.type_data["close_to"])

    def test_parse_payment_optional_fields(self):
        """Verify optional common fields default to None."""
        raw = self._make_canonical_payment()
        tx = Transaction(raw)
        self.assertIsNone(tx.genesis_id)
        self.assertIsNone(tx.lease)
        self.assertIsNone(tx.group_id)
        self.assertIsNone(tx.note)
        self.assertIsNone(tx.rekey)

    def test_trailing_data_raises(self):
        with self.assertRaises(Exception):
            Transaction(self._make_canonical_payment() + b"\x00")

    def test_noncanonical_key_order_raises(self):
        import struct

        parts = [bytes([0x87])]
        fields = [
            ("snd", b"\x01" * 32),
            ("amt", 1000000),
            ("fee", 1000),
            ("fv", 1000),
            ("gh", b"\x03" * 32),
            ("lv", 2000),
            ("rcv", b"\x02" * 32),
            ("type", "pay"),
        ]
        for key, val in fields:
            key_bytes = key.encode("utf-8")
            parts.append(bytes([0xA0 | len(key_bytes)]) + key_bytes)
            if isinstance(val, str):
                val_bytes = val.encode("utf-8")
                parts.append(bytes([0xA0 | len(val_bytes)]) + val_bytes)
            elif isinstance(val, bytes):
                parts.append(bytes([0xC4, len(val)]) + val)
            else:
                if val <= 0xFF:
                    parts.append(bytes([0xCC, val]))
                elif val <= 0xFFFF:
                    parts.append(bytes([0xCD]) + struct.pack(">H", val))
                else:
                    parts.append(bytes([0xCE]) + struct.pack(">I", val))
        with self.assertRaises(Exception):
            Transaction(b"".join(parts))

    def test_missing_type_raises(self):
        """Transaction without 'type' field should raise DataError."""
        # fixmap with 1 entry: {"snd": b"\x01"*32}
        data = bytes([0x81, 0xA3]) + b"snd" + bytes([0xC4, 32]) + b"\x01" * 32
        with self.assertRaises(Exception):
            Transaction(data)

    def test_unknown_type_raises(self):
        """Transaction with unknown type string should raise DataError."""
        import struct

        parts = []
        fields = {
            "fee": 1000,
            "fv": 1000,
            "gh": b"\x03" * 32,
            "lv": 2000,
            "snd": b"\x01" * 32,
            "type": "unknown",
        }
        sorted_keys = sorted(fields.keys())
        parts.append(bytes([0x80 | len(sorted_keys)]))
        for key in sorted_keys:
            key_bytes = key.encode("utf-8")
            parts.append(bytes([0xA0 | len(key_bytes)]) + key_bytes)
            val = fields[key]
            if isinstance(val, str):
                val_bytes = val.encode("utf-8")
                parts.append(bytes([0xA0 | len(val_bytes)]) + val_bytes)
            elif isinstance(val, bytes):
                parts.append(bytes([0xC4, len(val)]) + val)
            elif isinstance(val, int):
                if val <= 0xFF:
                    parts.append(bytes([0xCC, val]))
                else:
                    parts.append(bytes([0xCD]) + struct.pack(">H", val))
        raw = b"".join(parts)
        with self.assertRaises(Exception):
            Transaction(raw)

    def test_negative_fee_raises(self):
        raw = msgpack_encode(
            {
                "amt": 1000,
                "fee": -1,
                "fv": 1000,
                "gh": b"\x03" * 32,
                "lv": 2000,
                "rcv": b"\x02" * 32,
                "snd": b"\x01" * 32,
                "type": "pay",
            }
        )
        with self.assertRaises(Exception):
            Transaction(raw)

    def test_invalid_sender_length_raises(self):
        raw = msgpack_encode(
            {
                "amt": 1000,
                "fee": 1000,
                "fv": 1000,
                "gh": b"\x03" * 32,
                "lv": 2000,
                "rcv": b"\x02" * 32,
                "snd": b"\x01" * 31,
                "type": "pay",
            }
        )
        with self.assertRaises(Exception):
            Transaction(raw)

    def test_invalid_foreign_app_id_raises(self):
        raw = msgpack_encode(
            {
                "apid": 1,
                "apfa": [-1],
                "fee": 1000,
                "fv": 1000,
                "gh": b"\x03" * 32,
                "lv": 2000,
                "snd": b"\x01" * 32,
                "type": "appl",
            }
        )
        with self.assertRaises(Exception):
            Transaction(raw)

    def test_missing_sender_raises(self):
        """Transaction without 'snd' should raise DataError."""
        import struct

        parts = []
        fields = {
            "amt": 1000,
            "fee": 1000,
            "fv": 1000,
            "gh": b"\x03" * 32,
            "lv": 2000,
            "rcv": b"\x02" * 32,
            "type": "pay",
        }
        sorted_keys = sorted(fields.keys())
        parts.append(bytes([0x80 | len(sorted_keys)]))
        for key in sorted_keys:
            key_bytes = key.encode("utf-8")
            parts.append(bytes([0xA0 | len(key_bytes)]) + key_bytes)
            val = fields[key]
            if isinstance(val, str):
                val_bytes = val.encode("utf-8")
                parts.append(bytes([0xA0 | len(val_bytes)]) + val_bytes)
            elif isinstance(val, bytes):
                parts.append(bytes([0xC4, len(val)]) + val)
            elif isinstance(val, int):
                if val <= 0xFF:
                    parts.append(bytes([0xCC, val]))
                else:
                    parts.append(bytes([0xCD]) + struct.pack(">H", val))
        raw = b"".join(parts)
        with self.assertRaises(Exception):
            Transaction(raw)

    # TODO: Add test vectors for keyreg, axfer, afrz, acfg, appl transaction types
    # TODO: Add validation constraint tests (max accounts, max app args, etc.)
    # TODO: Add tests using real canonical MsgPack from algosdk or Ledger CLI


if __name__ == "__main__":
    unittest.main()
