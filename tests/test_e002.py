from __future__ import annotations

from collections.abc import Iterable

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ebics_read import SecurityError
from ebics_read.e002 import iter_decrypt_e002, unwrap_e002_transaction_key

_KEY = bytes(range(16))
_IV = b"\0" * 16


class _KeyProvider:
    def __init__(self, result: object = _KEY) -> None:
        self.result = result
        self.wrapped_key: bytes | None = None

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        self.wrapped_key = wrapped_key
        return self.result  # type: ignore[return-value]


def _encrypt(plaintext: bytes, padding_fill: int = 0xA5) -> bytes:
    padding_length = 16 - len(plaintext) % 16
    padded = (
        plaintext
        + bytes([padding_fill]) * (padding_length - 1)
        + bytes([padding_length])
    )
    encryptor = Cipher(algorithms.AES(_KEY), modes.CBC(_IV)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _chunks(value: bytes, sizes: Iterable[int]) -> list[bytes]:
    chunks: list[bytes] = []
    offset = 0
    for size in sizes:
        chunks.append(value[offset : offset + size])
        offset += size
    chunks.append(value[offset:])
    return chunks


def test_e002_unwraps_only_one_bounded_128_bit_transaction_key() -> None:
    provider = _KeyProvider()
    assert unwrap_e002_transaction_key(b"wrapped", provider) == _KEY
    assert provider.wrapped_key == b"wrapped"

    for wrapped in (b"", b"x" * 2049):
        with pytest.raises(SecurityError, match="wrapped"):
            unwrap_e002_transaction_key(wrapped, provider)
    for result in (b"short", bytearray(_KEY)):
        with pytest.raises(SecurityError, match="128 bits"):
            unwrap_e002_transaction_key(b"wrapped", _KeyProvider(result))


def test_e002_decrypts_incrementally_with_normative_padding() -> None:
    plaintext = b"synthetic compressed order data" * 3 + b"x"
    ciphertext = _encrypt(plaintext)
    decrypted = iter_decrypt_e002(_chunks(ciphertext, [1, 15, 17, 3]), _KEY)
    assert b"".join(decrypted) == plaintext
    assert b"".join(iter_decrypt_e002([_encrypt(b"", 0)], _KEY)) == b""


def test_e002_rejects_invalid_key_ciphertext_and_padding() -> None:
    with pytest.raises(SecurityError, match="128 bits"):
        list(iter_decrypt_e002([], b"short"))
    with pytest.raises(SecurityError, match="chunk"):
        list(iter_decrypt_e002([bytearray(16)], _KEY))  # type: ignore[list-item]
    for ciphertext in (b"", b"x" * 15, _encrypt(b"payload")[:-1]):
        with pytest.raises(SecurityError, match="length"):
            list(iter_decrypt_e002([ciphertext], _KEY))

    for last_byte in (0, 17):
        encryptor = Cipher(algorithms.AES(_KEY), modes.CBC(_IV)).encryptor()
        invalid = encryptor.update(b"x" * 15 + bytes([last_byte]))
        with pytest.raises(SecurityError, match="padding"):
            list(iter_decrypt_e002([invalid], _KEY))
