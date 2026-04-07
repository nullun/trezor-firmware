from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from buffer_types import AnyBytes

_b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

_b64tab = [ord(c) for c in _b64alphabet]
_b64rev = {ord(v): k for k, v in enumerate(_b64alphabet)}


def encode(s: AnyBytes) -> str:
    s = bytes(s)
    encoded = bytearray()
    i = 0
    length = len(s)

    while i < length - 2:
        b0 = s[i]
        b1 = s[i + 1]
        b2 = s[i + 2]
        encoded.append(_b64tab[b0 >> 2])
        encoded.append(_b64tab[((b0 & 0x03) << 4) | (b1 >> 4)])
        encoded.append(_b64tab[((b1 & 0x0F) << 2) | (b2 >> 6)])
        encoded.append(_b64tab[b2 & 0x3F])
        i += 3

    remaining = length - i
    if remaining == 1:
        b0 = s[i]
        encoded.append(_b64tab[b0 >> 2])
        encoded.append(_b64tab[(b0 & 0x03) << 4])
        encoded.append(ord("="))
        encoded.append(ord("="))
    elif remaining == 2:
        b0 = s[i]
        b1 = s[i + 1]
        encoded.append(_b64tab[b0 >> 2])
        encoded.append(_b64tab[((b0 & 0x03) << 4) | (b1 >> 4)])
        encoded.append(_b64tab[(b1 & 0x0F) << 2])
        encoded.append(ord("="))

    return bytes(encoded).decode()


def decode(s: str) -> bytes:
    data = s.encode()

    # Strip padding
    padchars = 0
    while data and data[-1 - padchars] == ord("="):
        padchars += 1
    data = data[: len(data) - padchars]

    result = bytearray()
    acc = 0
    bits = 0

    for c in data:
        val = _b64rev.get(c)
        if val is None:
            raise ValueError("Non-base64 digit found")
        acc = (acc << 6) | val
        bits += 6
        if bits >= 8:
            bits -= 8
            result.append((acc >> bits) & 0xFF)

    return bytes(result)
