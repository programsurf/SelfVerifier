# ML-DSA

ML-DSA-44 (Module-Lattice-Based Digital Signature Algorithm) implementation for the SelfVerifier framework.

## Source

This implementation is based on [PQClean](https://github.com/PQClean/PQClean), a clean and portable post-quantum cryptography library.

- **Algorithm:** ML-DSA-44 (NIST FIPS 204)
- **Security Level:** NIST Level 2
- **Public Key Size:** 1,312 bytes
- **Secret Key Size:** 2,560 bytes
- **Signature Size:** 2,420 bytes

## Build
```bash
cd ML-DSA/crypto_sign/ml-dsa-44/1_clean
make
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD
```

This compiles the PQClean ML-DSA-44 implementation into a shared library (`libmldsa44.so`).

## Usage

After building, the library can be used via Python bindings:
```python
from mldsa44_binding import keypair, sign, verify

# Generate key pair
public_key, secret_key = keypair()

# Sign a message
message = b"Hello, World!"
signature = sign(message, secret_key)

# Verify signature
is_valid = verify(message, signature, public_key)
```

## References

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA Standard
- [PQClean](https://github.com/PQClean/PQClean) - Source implementation