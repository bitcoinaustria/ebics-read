"""Fixed E002 decryption for authenticated EBICS order data."""

from collections.abc import Iterable, Iterator

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import SecurityError
from .interfaces import KeyProvider

_AES_KEY_BYTES = 16
_AES_BLOCK_BYTES = 16
_MAX_WRAPPED_KEY_BYTES = 2048  # 16384-bit maximum from the certificate profile.


def unwrap_e002_transaction_key(
    wrapped_key: bytes, key_provider: KeyProvider
) -> bytes:
    """Unwrap one bounded E002 key and require the normative 128-bit result."""

    if (
        type(wrapped_key) is not bytes
        or not 1 <= len(wrapped_key) <= _MAX_WRAPPED_KEY_BYTES
    ):
        raise SecurityError("E002 wrapped transaction key length is invalid")
    transaction_key = key_provider.decrypt_e002_transaction_key(wrapped_key)
    if type(transaction_key) is not bytes or len(transaction_key) != _AES_KEY_BYTES:
        raise SecurityError("E002 transaction key is not 128 bits")
    return transaction_key


def iter_decrypt_e002(
    ciphertext_chunks: Iterable[bytes], transaction_key: bytes
) -> Iterator[bytes]:
    """Yield provisional plaintext while retaining and validating the final block.

    Callers must keep yielded bytes unpublished until the iterator completes.
    """

    if type(transaction_key) is not bytes or len(transaction_key) != _AES_KEY_BYTES:
        raise SecurityError("E002 transaction key is not 128 bits")

    decryptor = Cipher(
        algorithms.AES(transaction_key), modes.CBC(b"\0" * _AES_BLOCK_BYTES)
    ).decryptor()
    pending = b""
    for chunk in ciphertext_chunks:
        if type(chunk) is not bytes:
            raise SecurityError("E002 ciphertext chunk is not bytes")
        pending += chunk
        process_length = max(
            0,
            ((len(pending) - _AES_BLOCK_BYTES) // _AES_BLOCK_BYTES)
            * _AES_BLOCK_BYTES,
        )
        if process_length:
            yield decryptor.update(pending[:process_length])
            pending = pending[process_length:]

    if len(pending) != _AES_BLOCK_BYTES:
        raise SecurityError("E002 ciphertext length is invalid")
    final_block = decryptor.update(pending) + decryptor.finalize()

    padding_length = final_block[-1]
    if not 1 <= padding_length <= _AES_BLOCK_BYTES:
        raise SecurityError("E002 padding is invalid")
    final_plaintext = final_block[:-padding_length]
    if final_plaintext:
        yield final_plaintext
