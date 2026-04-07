from trezor.wire import DataError


class MsgPackDecoder:
    """Minimal MsgPack decoder for Algorand canonical MsgPack transactions."""

    def __init__(self, data: bytes) -> None:
        self.data = memoryview(data)
        self.offset = 0

    def _read_byte(self) -> int:
        if self.offset >= len(self.data):
            raise DataError("MsgPack: unexpected end of data")
        b = self.data[self.offset]
        self.offset += 1
        return b

    def _read_bytes(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise DataError("MsgPack: unexpected end of data")
        result = bytes(self.data[self.offset : self.offset + n])
        self.offset += n
        return result

    def _read_uint16(self) -> int:
        b = self._read_bytes(2)
        return (b[0] << 8) | b[1]

    def _read_uint32(self) -> int:
        b = self._read_bytes(4)
        return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]

    def _read_uint64(self) -> int:
        b = self._read_bytes(8)
        result = 0
        for i in range(8):
            result = (result << 8) | b[i]
        return result

    def _read_str(self, length: int) -> str:
        raw = self._read_bytes(length)
        try:
            return raw.decode("utf-8")
        except UnicodeError:
            raise DataError("MsgPack: invalid UTF-8 string")

    def _read_map_entries(self, count: int) -> dict:
        result: dict = {}
        for _ in range(count):
            key = self.read_value()
            if not isinstance(key, str):
                raise DataError("MsgPack: map key must be string")
            value = self.read_value()
            result[key] = value
        return result

    def _read_array_entries(self, count: int) -> list:
        return [self.read_value() for _ in range(count)]

    def read_value(self) -> Any:
        """Read a single MsgPack value and return it as a Python object."""
        byte = self._read_byte()

        # Positive fixint: 0x00-0x7F
        if byte <= 0x7F:
            return byte

        # Fixmap: 0x80-0x8F
        if 0x80 <= byte <= 0x8F:
            return self._read_map_entries(byte & 0x0F)

        # Fixarray: 0x90-0x9F
        if 0x90 <= byte <= 0x9F:
            return self._read_array_entries(byte & 0x0F)

        # Fixstr: 0xA0-0xBF
        if 0xA0 <= byte <= 0xBF:
            return self._read_str(byte & 0x1F)

        # Nil
        if byte == 0xC0:
            return None

        # Bool
        if byte == 0xC2:
            return False
        if byte == 0xC3:
            return True

        # Bin8
        if byte == 0xC4:
            length = self._read_byte()
            return self._read_bytes(length)

        # Bin16
        if byte == 0xC5:
            length = self._read_uint16()
            return self._read_bytes(length)

        # Uint8
        if byte == 0xCC:
            return self._read_byte()

        # Uint16
        if byte == 0xCD:
            return self._read_uint16()

        # Uint32
        if byte == 0xCE:
            return self._read_uint32()

        # Uint64
        if byte == 0xCF:
            return self._read_uint64()

        # Int8
        if byte == 0xD0:
            val = self._read_byte()
            return val - 256 if val >= 128 else val

        # Int16
        if byte == 0xD1:
            val = self._read_uint16()
            return val - 65536 if val >= 32768 else val

        # Str8
        if byte == 0xD9:
            length = self._read_byte()
            return self._read_str(length)

        # Array16
        if byte == 0xDC:
            count = self._read_uint16()
            return self._read_array_entries(count)

        # Map16
        if byte == 0xDE:
            count = self._read_uint16()
            return self._read_map_entries(count)

        # Negative fixint: 0xE0-0xFF
        if byte >= 0xE0:
            return byte - 256

        raise DataError("MsgPack: unsupported type")

    def read_map(self) -> dict:
        """Read a MsgPack map. Returns dict with string keys."""
        byte = self.data[self.offset]
        if 0x80 <= byte <= 0x8F or byte == 0xDE:
            return self.read_value()  # type: ignore [return-value]
        raise DataError("MsgPack: expected map")


class MsgPackEncoder:
    """Minimal MsgPack encoder producing Algorand canonical encoding.

    Canonical: sorted map keys, minimal integer encoding.
    """

    def __init__(self) -> None:
        self.buf = bytearray()

    def _write_uint16(self, val: int) -> None:
        self.buf.append((val >> 8) & 0xFF)
        self.buf.append(val & 0xFF)

    def _write_uint32(self, val: int) -> None:
        self.buf.append((val >> 24) & 0xFF)
        self.buf.append((val >> 16) & 0xFF)
        self.buf.append((val >> 8) & 0xFF)
        self.buf.append(val & 0xFF)

    def _write_uint64(self, val: int) -> None:
        for i in range(7, -1, -1):
            self.buf.append((val >> (i * 8)) & 0xFF)

    def _encode_int(self, val: int) -> None:
        if 0 <= val <= 0x7F:
            self.buf.append(val)
        elif 0 <= val <= 0xFF:
            self.buf.append(0xCC)
            self.buf.append(val)
        elif 0 <= val <= 0xFFFF:
            self.buf.append(0xCD)
            self._write_uint16(val)
        elif 0 <= val <= 0xFFFFFFFF:
            self.buf.append(0xCE)
            self._write_uint32(val)
        elif 0 <= val <= 0xFFFFFFFFFFFFFFFF:
            self.buf.append(0xCF)
            self._write_uint64(val)
        elif -32 <= val < 0:
            self.buf.append(val & 0xFF)
        elif -128 <= val < 0:
            self.buf.append(0xD0)
            self.buf.append(val & 0xFF)
        elif -32768 <= val < 0:
            self.buf.append(0xD1)
            self._write_uint16(val & 0xFFFF)
        else:
            raise DataError("MsgPack: integer out of range")

    def _encode_str(self, val: str) -> None:
        encoded = val.encode("utf-8")
        length = len(encoded)
        if length <= 31:
            self.buf.append(0xA0 | length)
        elif length <= 0xFF:
            self.buf.append(0xD9)
            self.buf.append(length)
        else:
            raise DataError("MsgPack: string too long")
        self.buf.extend(encoded)

    def _encode_bin(self, val: bytes) -> None:
        length = len(val)
        if length <= 0xFF:
            self.buf.append(0xC4)
            self.buf.append(length)
        elif length <= 0xFFFF:
            self.buf.append(0xC5)
            self._write_uint16(length)
        else:
            raise DataError("MsgPack: binary too long")
        self.buf.extend(val)

    def _encode_array(self, val: list) -> None:
        length = len(val)
        if length <= 15:
            self.buf.append(0x90 | length)
        elif length <= 0xFFFF:
            self.buf.append(0xDC)
            self._write_uint16(length)
        else:
            raise DataError("MsgPack: array too long")
        for item in val:
            self.encode_value(item)

    def _encode_map(self, val: dict) -> None:
        sorted_keys = sorted(val.keys())
        length = len(sorted_keys)
        if length <= 15:
            self.buf.append(0x80 | length)
        elif length <= 0xFFFF:
            self.buf.append(0xDE)
            self._write_uint16(length)
        else:
            raise DataError("MsgPack: map too long")
        for key in sorted_keys:
            self._encode_str(key)
            self.encode_value(val[key])

    def encode_value(self, value) -> None:
        """Encode a single value in canonical MsgPack format."""
        if value is None:
            self.buf.append(0xC0)
        elif isinstance(value, bool):
            self.buf.append(0xC3 if value else 0xC2)
        elif isinstance(value, int):
            self._encode_int(value)
        elif isinstance(value, str):
            self._encode_str(value)
        elif isinstance(value, (bytes, memoryview)):
            self._encode_bin(bytes(value))
        elif isinstance(value, list):
            self._encode_array(value)
        elif isinstance(value, dict):
            self._encode_map(value)
        else:
            raise DataError("MsgPack: unsupported type")


def msgpack_encode(value) -> bytes:
    """Encode a value to canonical MsgPack bytes."""
    encoder = MsgPackEncoder()
    encoder.encode_value(value)
    return bytes(encoder.buf)
