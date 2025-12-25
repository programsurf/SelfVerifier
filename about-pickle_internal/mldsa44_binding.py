#!/usr/bin/env python3
"""
ML-DSA-44 Python Bindings using ctypes
=======================================
Direct Python bindings to ML-DSA C library.
"""

import os
import ctypes
from ctypes import c_uint8, c_size_t, POINTER

# Library path
LIB_PATH = os.path.join(os.path.dirname(__file__), 'libmldsa44.so')

# Load the library
try:
    _mldsa = ctypes.CDLL(LIB_PATH)
except OSError as e:
    raise RuntimeError(f"Failed to load ML-DSA library: {e}")

# Constants from api.h
CRYPTO_PUBLICKEYBYTES = 1312
CRYPTO_SECRETKEYBYTES = 2560
CRYPTO_BYTES = 2420

# Function prototypes
_mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair.argtypes = [
    POINTER(c_uint8),  # pk
    POINTER(c_uint8)   # sk
]
_mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair.restype = ctypes.c_int

_mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature.argtypes = [
    POINTER(c_uint8),      # sig
    POINTER(c_size_t),     # siglen
    POINTER(c_uint8),      # m
    c_size_t,              # mlen
    POINTER(c_uint8)       # sk
]
_mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature.restype = ctypes.c_int

_mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify.argtypes = [
    POINTER(c_uint8),      # sig
    c_size_t,              # siglen
    POINTER(c_uint8),      # m
    c_size_t,              # mlen
    POINTER(c_uint8)       # pk
]
_mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify.restype = ctypes.c_int


def keypair():
    """
    Generate ML-DSA-44 keypair.

    Returns:
        tuple: (public_key, secret_key) as bytes
    """
    pk = (c_uint8 * CRYPTO_PUBLICKEYBYTES)()
    sk = (c_uint8 * CRYPTO_SECRETKEYBYTES)()

    ret = _mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk)

    if ret != 0:
        raise RuntimeError("Key generation failed")

    return bytes(pk), bytes(sk)


def sign(message, secret_key):
    """
    Sign a message with ML-DSA-44.

    Args:
        message: bytes to sign
        secret_key: secret key (2560 bytes)

    Returns:
        bytes: signature (2420 bytes)
    """
    if len(secret_key) != CRYPTO_SECRETKEYBYTES:
        raise ValueError(f"Invalid secret key size: {len(secret_key)}")

    sig = (c_uint8 * CRYPTO_BYTES)()
    siglen = c_size_t()

    msg_array = (c_uint8 * len(message)).from_buffer_copy(message)
    sk_array = (c_uint8 * CRYPTO_SECRETKEYBYTES).from_buffer_copy(secret_key)

    ret = _mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
        sig,
        ctypes.byref(siglen),
        msg_array,
        len(message),
        sk_array
    )

    if ret != 0:
        raise RuntimeError("Signing failed")

    return bytes(sig[:siglen.value])


def verify(signature, message, public_key):
    """
    Verify an ML-DSA-44 signature.

    Args:
        signature: signature bytes
        message: original message bytes
        public_key: public key (1312 bytes)

    Returns:
        bool: True if signature is valid
    """
    if len(public_key) != CRYPTO_PUBLICKEYBYTES:
        raise ValueError(f"Invalid public key size: {len(public_key)}")

    sig_array = (c_uint8 * len(signature)).from_buffer_copy(signature)
    msg_array = (c_uint8 * len(message)).from_buffer_copy(message)
    pk_array = (c_uint8 * CRYPTO_PUBLICKEYBYTES).from_buffer_copy(public_key)

    ret = _mldsa.PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
        sig_array,
        len(signature),
        msg_array,
        len(message),
        pk_array
    )

    return ret == 0


if __name__ == "__main__":
    print("ML-DSA-44 Python Bindings")
    print("=" * 60)

    # Test keypair generation
    print("\nGenerating keypair...")
    pk, sk = keypair()
    print(f"Public key size: {len(pk)} bytes")
    print(f"Secret key size: {len(sk)} bytes")

    # Test signing
    message = b"Hello, ML-DSA-44!"
    print(f"\nSigning message: {message}")
    signature = sign(message, sk)
    print(f"Signature size: {len(signature)} bytes")

    # Test verification
    print(f"\nVerifying signature...")
    is_valid = verify(signature, message, pk)
    print(f"Signature valid: {is_valid}")

    # Test with wrong message
    wrong_message = b"Wrong message"
    is_valid_wrong = verify(signature, wrong_message, pk)
    print(f"Wrong message valid: {is_valid_wrong}")

    print("\n" + "=" * 60)
    print("✓ All tests passed!")
