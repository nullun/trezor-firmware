# flake8: noqa: F403,F405
from common import *  # isort:skip

from apps.algorand.msgpack import MsgPackDecoder, MsgPackEncoder, msgpack_encode


class TestMsgPackDecoder(unittest.TestCase):

    def test_positive_fixint(self):
        # 0x00 = 0, 0x7F = 127
        d = MsgPackDecoder(bytes([0x00]))
        self.assertEqual(d.read_value(), 0)
        d = MsgPackDecoder(bytes([0x7F]))
        self.assertEqual(d.read_value(), 127)
        d = MsgPackDecoder(bytes([0x2A]))
        self.assertEqual(d.read_value(), 42)

    def test_negative_fixint(self):
        # 0xE0 = -32, 0xFF = -1
        d = MsgPackDecoder(bytes([0xFF]))
        self.assertEqual(d.read_value(), -1)
        d = MsgPackDecoder(bytes([0xE0]))
        self.assertEqual(d.read_value(), -32)

    def test_nil(self):
        d = MsgPackDecoder(bytes([0xC0]))
        self.assertIsNone(d.read_value())

    def test_bool(self):
        d = MsgPackDecoder(bytes([0xC2]))
        self.assertFalse(d.read_value())
        d = MsgPackDecoder(bytes([0xC3]))
        self.assertTrue(d.read_value())

    def test_uint8(self):
        d = MsgPackDecoder(bytes([0xCC, 0xFF]))
        self.assertEqual(d.read_value(), 255)

    def test_uint16(self):
        d = MsgPackDecoder(bytes([0xCD, 0x01, 0x00]))
        self.assertEqual(d.read_value(), 256)

    def test_uint32(self):
        d = MsgPackDecoder(bytes([0xCE, 0x00, 0x01, 0x00, 0x00]))
        self.assertEqual(d.read_value(), 65536)

    def test_uint64(self):
        d = MsgPackDecoder(bytes([0xCF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))
        self.assertEqual(d.read_value(), 4294967296)

    def test_int8(self):
        d = MsgPackDecoder(bytes([0xD0, 0x80]))
        self.assertEqual(d.read_value(), -128)
        d = MsgPackDecoder(bytes([0xD0, 0x7F]))
        self.assertEqual(d.read_value(), 127)

    def test_int16(self):
        d = MsgPackDecoder(bytes([0xD1, 0x80, 0x00]))
        self.assertEqual(d.read_value(), -32768)

    def test_fixstr(self):
        # fixstr with length 3: 0xA3 + b"abc"
        d = MsgPackDecoder(bytes([0xA3]) + b"abc")
        self.assertEqual(d.read_value(), "abc")

    def test_fixstr_empty(self):
        d = MsgPackDecoder(bytes([0xA0]))
        self.assertEqual(d.read_value(), "")

    def test_str8(self):
        # str8: 0xD9 + 1-byte length + data
        s = b"hello world"
        d = MsgPackDecoder(bytes([0xD9, len(s)]) + s)
        self.assertEqual(d.read_value(), "hello world")

    def test_bin8(self):
        # bin8: 0xC4 + 1-byte length + data
        data = bytes(range(10))
        d = MsgPackDecoder(bytes([0xC4, 10]) + data)
        self.assertEqual(d.read_value(), data)

    def test_bin16(self):
        # bin16: 0xC5 + 2-byte length + data
        data = bytes(range(256))
        d = MsgPackDecoder(bytes([0xC5, 0x01, 0x00]) + data)
        self.assertEqual(d.read_value(), data)

    def test_fixmap(self):
        # fixmap with 1 entry: 0x81 + key + value
        # key = fixstr "a" (0xA1 + b"a"), value = fixint 1
        d = MsgPackDecoder(bytes([0x81, 0xA1]) + b"a" + bytes([0x01]))
        result = d.read_value()
        self.assertEqual(result, {"a": 1})

    def test_fixarray(self):
        # fixarray with 3 elements: 0x93 + 1, 2, 3
        d = MsgPackDecoder(bytes([0x93, 0x01, 0x02, 0x03]))
        result = d.read_value()
        self.assertEqual(result, [1, 2, 3])

    def test_array16(self):
        # array16: 0xDC + 2-byte count + elements
        d = MsgPackDecoder(bytes([0xDC, 0x00, 0x02, 0x01, 0x02]))
        result = d.read_value()
        self.assertEqual(result, [1, 2])

    def test_map16(self):
        # map16: 0xDE + 2-byte count + entries
        d = MsgPackDecoder(bytes([0xDE, 0x00, 0x01, 0xA1]) + b"x" + bytes([0x05]))
        result = d.read_value()
        self.assertEqual(result, {"x": 5})

    def test_read_map(self):
        # fixmap with 2 entries
        data = bytes([0x82, 0xA1]) + b"a" + bytes([0x01, 0xA1]) + b"b" + bytes([0x02])
        d = MsgPackDecoder(data)
        result = d.read_map()
        self.assertEqual(result, {"a": 1, "b": 2})

    def test_nested_map(self):
        # map containing a map: {"k": {"n": 1}}
        inner = bytes([0x81, 0xA1]) + b"n" + bytes([0x01])
        outer = bytes([0x81, 0xA1]) + b"k" + inner
        d = MsgPackDecoder(outer)
        result = d.read_map()
        self.assertEqual(result, {"k": {"n": 1}})

    def test_unsupported_type_raises(self):
        # 0xC1 is unused/never used in MsgPack
        d = MsgPackDecoder(bytes([0xC1]))
        with self.assertRaises(Exception):
            d.read_value()

    def test_truncated_data_raises(self):
        # uint16 expects 2 bytes after marker, only 1 provided
        d = MsgPackDecoder(bytes([0xCD, 0x01]))
        with self.assertRaises(Exception):
            d.read_value()

    def test_non_string_map_key_raises(self):
        # fixmap with integer key: 0x81 + fixint 1 + fixint 2
        d = MsgPackDecoder(bytes([0x81, 0x01, 0x02]))
        with self.assertRaises(Exception):
            d.read_value()

    def test_canonical_algorand_payment(self):
        """Test decoding a minimal canonical Algorand payment transaction.

        Canonical MsgPack: keys sorted lexicographically, minimal int types.
        """
        # TODO: Add a real canonical MsgPack payment transaction bytes
        # and verify the decoded dict matches expected structure.
        # Can be generated with: algosdk.transaction.PaymentTxn(...).dictify()
        pass


class TestMsgPackEncoder(unittest.TestCase):

    def test_positive_fixint(self):
        self.assertEqual(msgpack_encode(0), bytes([0x00]))
        self.assertEqual(msgpack_encode(127), bytes([0x7F]))
        self.assertEqual(msgpack_encode(42), bytes([0x2A]))

    def test_negative_fixint(self):
        self.assertEqual(msgpack_encode(-1), bytes([0xFF]))
        self.assertEqual(msgpack_encode(-32), bytes([0xE0]))

    def test_nil(self):
        self.assertEqual(msgpack_encode(None), bytes([0xC0]))

    def test_bool(self):
        self.assertEqual(msgpack_encode(False), bytes([0xC2]))
        self.assertEqual(msgpack_encode(True), bytes([0xC3]))

    def test_uint8(self):
        self.assertEqual(msgpack_encode(255), bytes([0xCC, 0xFF]))
        self.assertEqual(msgpack_encode(128), bytes([0xCC, 0x80]))

    def test_uint16(self):
        self.assertEqual(msgpack_encode(256), bytes([0xCD, 0x01, 0x00]))
        self.assertEqual(msgpack_encode(65535), bytes([0xCD, 0xFF, 0xFF]))

    def test_uint32(self):
        self.assertEqual(msgpack_encode(65536), bytes([0xCE, 0x00, 0x01, 0x00, 0x00]))

    def test_uint64(self):
        self.assertEqual(
            msgpack_encode(4294967296),
            bytes([0xCF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        )

    def test_int8(self):
        self.assertEqual(msgpack_encode(-33), bytes([0xD0, 0xDF]))
        self.assertEqual(msgpack_encode(-128), bytes([0xD0, 0x80]))

    def test_int16(self):
        self.assertEqual(msgpack_encode(-32768), bytes([0xD1, 0x80, 0x00]))

    def test_fixstr(self):
        self.assertEqual(msgpack_encode("abc"), bytes([0xA3]) + b"abc")
        self.assertEqual(msgpack_encode(""), bytes([0xA0]))

    def test_str8(self):
        s = "a" * 32
        expected = bytes([0xD9, 32]) + s.encode("utf-8")
        self.assertEqual(msgpack_encode(s), expected)

    def test_bin8(self):
        data = bytes(range(10))
        self.assertEqual(msgpack_encode(data), bytes([0xC4, 10]) + data)

    def test_bin16(self):
        data = bytes(range(256))
        self.assertEqual(msgpack_encode(data), bytes([0xC5, 0x01, 0x00]) + data)

    def test_fixarray(self):
        self.assertEqual(msgpack_encode([1, 2, 3]), bytes([0x93, 0x01, 0x02, 0x03]))

    def test_fixmap_sorted_keys(self):
        # Keys must be sorted lexicographically in canonical encoding
        result = msgpack_encode({"b": 2, "a": 1})
        expected = bytes([0x82, 0xA1]) + b"a" + bytes([0x01, 0xA1]) + b"b" + bytes([0x02])
        self.assertEqual(result, expected)

    def test_nested_map(self):
        result = msgpack_encode({"k": {"n": 1}})
        inner = bytes([0x81, 0xA1]) + b"n" + bytes([0x01])
        expected = bytes([0x81, 0xA1]) + b"k" + inner
        self.assertEqual(result, expected)

    def test_round_trip_simple(self):
        """Decode then encode should produce identical bytes for canonical input."""
        # fixmap with sorted keys
        original = bytes([0x82, 0xA1]) + b"a" + bytes([0x01, 0xA1]) + b"b" + bytes([0x02])
        d = MsgPackDecoder(original)
        decoded = d.read_value()
        re_encoded = msgpack_encode(decoded)
        self.assertEqual(re_encoded, original)

    def test_round_trip_payment(self):
        """Round-trip a canonical payment transaction."""
        import struct

        fields = {
            "amt": 1000000,
            "fee": 1000,
            "fv": 1000,
            "gh": b"\x03" * 32,
            "lv": 2000,
            "rcv": b"\x02" * 32,
            "snd": b"\x01" * 32,
            "type": "pay",
        }
        sorted_keys = sorted(fields.keys())
        parts = [bytes([0x80 | len(sorted_keys)])]
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
                if val <= 0x7F:
                    parts.append(bytes([val]))
                elif val <= 0xFF:
                    parts.append(bytes([0xCC, val]))
                elif val <= 0xFFFF:
                    parts.append(bytes([0xCD]) + struct.pack(">H", val))
                elif val <= 0xFFFFFFFF:
                    parts.append(bytes([0xCE]) + struct.pack(">I", val))
        original = b"".join(parts)

        d = MsgPackDecoder(original)
        decoded = d.read_value()
        re_encoded = msgpack_encode(decoded)
        self.assertEqual(re_encoded, original)

    def test_encode_map_strips_key(self):
        """Verify that removing a key and re-encoding works correctly."""
        original_dict = {"a": 1, "grp": b"\xff" * 32, "z": 2}
        stripped = dict(original_dict)
        del stripped["grp"]

        result = msgpack_encode(stripped)
        expected = msgpack_encode({"a": 1, "z": 2})
        self.assertEqual(result, expected)

        # Verify the grp data is not in the output
        d = MsgPackDecoder(result)
        decoded = d.read_value()
        self.assertTrue("grp" not in decoded)


if __name__ == "__main__":
    unittest.main()
