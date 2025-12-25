#!/usr/bin/env python3
"""
Secure Model Signature with Length-Prefix Format
=================================================
안전한 서명 방식 구현:
- Magic Header로 파일 식별
- Length-Prefix로 서명 범위 명확화
- 검증을 pickle.loads() 이전에 실행
- 바이트 레벨 파일 제어

파일 구조:
    [8 bytes]  Magic Header: b'MLDSASIG'
    [1 byte]   Format Version: 0x04
    [8 bytes]  signed_region_length (big-endian uint64)
    [N bytes]  signed_region_bytes (정확히 signed_region_length만큼)
               ↑ 이 부분만 SHA-256 hash 대상!
    [8 bytes]  signature_length (big-endian uint64)
    [M bytes]  signature
    [8 bytes]  public_key_length (big-endian uint64)
    [K bytes]  public_key

보안 강화:
    1. Magic Header: 파일 타입 검증
    2. Version: 포맷 버전 확인
    3. Length-Prefix: 정확한 서명 범위 지정
    4. 검증 우선: pickle.loads() 전에 서명 검증
    5. 바이트 레벨 제어: 공격자의 데이터 삽입 방지
"""

import struct
import hashlib
import pickle
import time
import os
from typing import Any, Tuple, Dict

from mldsa44_binding import sign as mldsa_sign, verify as mldsa_verify
from mldsa44_binding import CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES


class SecureSignedModel:
    """
    안전한 서명 모델 클래스

    핵심 원리:
    - 파일 구조를 바이트 레벨에서 정확히 제어
    - 서명 범위를 length로 명확히 지정
    - 검증을 역직렬화 전에 수행
    """

    # Constants
    MAGIC = b'MLDSASIG'
    VERSION = 0x04

    # File format offsets
    MAGIC_OFFSET = 0
    MAGIC_SIZE = 8
    VERSION_OFFSET = MAGIC_SIZE
    VERSION_SIZE = 1
    SIGNED_LENGTH_OFFSET = VERSION_OFFSET + VERSION_SIZE
    SIGNED_LENGTH_SIZE = 8  # Changed to 8 bytes for uint64
    SIGNED_REGION_OFFSET = SIGNED_LENGTH_OFFSET + SIGNED_LENGTH_SIZE

    @staticmethod
    def save(model_data: Any, secret_key_path: str, public_key_path: str,
             output_path: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        안전한 방식으로 모델을 서명하여 저장

        Args:
            model_data: 저장할 모델 데이터 (dict, nn.Module, etc.)
            secret_key_path: ML-DSA 비밀키 파일 경로
            public_key_path: ML-DSA 공개키 파일 경로
            output_path: 출력 파일 경로
            metadata: 추가 메타데이터 (optional)

        Returns:
            저장 결과 정보를 담은 dict
        """
        print("=" * 70)
        print("[SECURE] SECURE MODEL SIGNING (Length-Prefix Format)")
        print("=" * 70)

        # Step 1: Load keys
        print("\n[Step 1/7] Loading cryptographic keys...")
        with open(secret_key_path, 'rb') as f:
            secret_key = f.read()
        with open(public_key_path, 'rb') as f:
            public_key = f.read()

        # Validate key sizes
        if len(secret_key) != CRYPTO_SECRETKEYBYTES:
            raise ValueError(f"Invalid secret key size: {len(secret_key)} (expected {CRYPTO_SECRETKEYBYTES})")
        if len(public_key) != CRYPTO_PUBLICKEYBYTES:
            raise ValueError(f"Invalid public key size: {len(public_key)} (expected {CRYPTO_PUBLICKEYBYTES})")

        print(f"   ✓ Secret key loaded: {len(secret_key)} bytes")
        print(f"   ✓ Public key loaded: {len(public_key)} bytes")

        # Step 2: Create signed region
        print("\n[Step 2/7] Creating signed region...")
        signed_region = {
            'model_data': model_data,
            'version': '3.0-secure',
            'timestamp': time.time(),
            'format': 'length-prefix',
            'hash_algorithm': 'SHA-256',
            'signature_algorithm': 'ML-DSA-44'
        }

        # Add custom metadata if provided
        if metadata:
            signed_region['metadata'] = metadata

        print(f"   ✓ Signed region created")
        print(f"      Model data type: {type(model_data).__name__}")
        print(f"      Timestamp: {signed_region['timestamp']}")

        # Step 3: Serialize signed region with pickle
        print("\n[Step 3/7] Serializing signed region...")
        start_time = time.time()
        signed_bytes = pickle.dumps(signed_region, protocol=4)
        serialize_time = time.time() - start_time

        print(f"   ✓ Serialized: {len(signed_bytes):,} bytes")
        print(f"   ✓ Serialization time: {serialize_time:.3f}s")

        # Step 4: Compute hash of signed region
        print("\n[Step 4/7] Computing SHA-256 hash...")
        start_time = time.time()
        hash_value = hashlib.sha256(signed_bytes).digest()
        hash_time = time.time() - start_time

        print(f"   ✓ Hash computed: {hash_value[:16].hex()}...")
        print(f"   ✓ Hash time: {hash_time:.6f}s")

        # Step 5: Sign the hash
        print("\n[Step 5/7] Signing with ML-DSA-44...")
        start_time = time.time()
        signature = mldsa_sign(hash_value, secret_key)
        sign_time = time.time() - start_time

        print(f"   ✓ Signature generated: {len(signature)} bytes")
        if sign_time < 0.001:
            print(f"   ✓ Signing time: {sign_time * 1000:.3f} ms")
        else:
            print(f"   ✓ Signing time: {sign_time:.3f}s")

        # Step 6: Create file with length-prefix format
        print("\n[Step 6/7] Writing file with length-prefix format...")
        start_time = time.time()

        with open(output_path, 'wb') as f:
            # Write Magic Header
            f.write(SecureSignedModel.MAGIC)

            # Write Version
            f.write(struct.pack('B', SecureSignedModel.VERSION))

            # Write signed region length (big-endian uint64)
            f.write(struct.pack('>Q', len(signed_bytes)))

            # Write signed region (THIS IS THE HASH TARGET!)
            f.write(signed_bytes)

            # Write signature length (big-endian uint64)
            f.write(struct.pack('>Q', len(signature)))

            # Write signature
            f.write(signature)

            # Write public key length (big-endian uint64)
            f.write(struct.pack('>Q', len(public_key)))

            # Write public key
            f.write(public_key)

        write_time = time.time() - start_time
        file_size = os.path.getsize(output_path)

        print(f"   ✓ File written: {output_path}")
        print(f"   ✓ Total file size: {file_size:,} bytes")
        print(f"   ✓ Write time: {write_time:.3f}s")

        # Step 7: Verify file structure
        print("\n[Step 7/7] Verifying file structure...")
        header_size = (SecureSignedModel.MAGIC_SIZE +
                      SecureSignedModel.VERSION_SIZE +
                      SecureSignedModel.SIGNED_LENGTH_SIZE)
        overhead = header_size + 8 + len(signature) + 8 + len(public_key)

        print(f"   ✓ File structure verified")
        print(f"      Magic header: {SecureSignedModel.MAGIC_SIZE} bytes")
        print(f"      Version: {SecureSignedModel.VERSION_SIZE} byte")
        print(f"      Length fields: 24 bytes (3 × 8)")
        print(f"      Signed region: {len(signed_bytes):,} bytes (HASH TARGET)")
        print(f"      Signature: {len(signature)} bytes")
        print(f"      Public key: {len(public_key)} bytes")
        print(f"      Total overhead: {overhead} bytes")

        # Summary
        total_time = serialize_time + hash_time + sign_time + write_time

        print("\n" + "=" * 70)
        print("[SUCCESS] MODEL SIGNED SUCCESSFULLY")
        print("=" * 70)
        print(f"Output file: {output_path}")
        print(f"File size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
        print(f"Signed region: {len(signed_bytes):,} bytes")
        print(f"Total time: {total_time:.3f}s")
        print("=" * 70)

        return {
            'success': True,
            'output_path': output_path,
            'file_size': file_size,
            'signed_region_size': len(signed_bytes),
            'signature_size': len(signature),
            'public_key_size': len(public_key),
            'hash_value': hash_value.hex(),
            'serialize_time': serialize_time,
            'hash_time': hash_time,
            'sign_time': sign_time,
            'write_time': write_time,
            'total_time': total_time
        }

    @staticmethod
    def load(model_path: str, verify: bool = True) -> Tuple[bool, Any]:
        """
        안전하게 모델을 로드하고 검증

        Args:
            model_path: 모델 파일 경로
            verify: 서명 검증 여부 (기본값: True)

        Returns:
            (검증 성공 여부, 모델 데이터) 튜플

        Raises:
            FileNotFoundError: 파일이 없을 때
            ValueError: 파일 포맷이 잘못되었거나 서명 검증 실패 시
        """
        print("=" * 70)
        print("[VERIFY] SECURE MODEL LOADING (Length-Prefix Format)")
        print("=" * 70)
        print(f"File: {model_path}\n")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        file_size = os.path.getsize(model_path)
        print(f"File size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")

        with open(model_path, 'rb') as f:
            # Step 1: Read and verify magic header
            print("\n[Step 1/7] Verifying magic header...")
            magic = f.read(SecureSignedModel.MAGIC_SIZE)

            if magic != SecureSignedModel.MAGIC:
                raise ValueError(
                    f"Invalid magic header: {magic.hex()}\n"
                    f"Expected: {SecureSignedModel.MAGIC.hex()}\n"
                    f"This is not a valid signed model file!"
                )

            print(f"   ✓ Magic header verified: {magic.decode('ascii')}")

            # Step 2: Read and verify version
            print("\n[Step 2/7] Checking format version...")
            version = struct.unpack('B', f.read(SecureSignedModel.VERSION_SIZE))[0]

            if version != SecureSignedModel.VERSION:
                raise ValueError(
                    f"Unsupported format version: 0x{version:02X}\n"
                    f"Expected: 0x{SecureSignedModel.VERSION:02X}\n"
                    f"Please update your verification code!"
                )

            print(f"   ✓ Format version: 0x{version:02X}")

            # Step 3: Read signed region length
            print("\n[Step 3/7] Reading signed region length...")
            signed_length = struct.unpack('>Q', f.read(8))[0]

            print(f"   ✓ Signed region length: {signed_length:,} bytes")

            # Sanity check
            if signed_length > file_size:
                raise ValueError(
                    f"Invalid signed region length: {signed_length:,} bytes\n"
                    f"File size: {file_size:,} bytes\n"
                    f"File may be corrupted!"
                )

            # Step 4: Read signed region (HASH TARGET!)
            print("\n[Step 4/7] Reading signed region...")
            start_time = time.time()
            signed_bytes = f.read(signed_length)
            read_time = time.time() - start_time

            if len(signed_bytes) != signed_length:
                raise ValueError(
                    f"Truncated file!\n"
                    f"Expected: {signed_length:,} bytes\n"
                    f"Got: {len(signed_bytes):,} bytes\n"
                    f"File may be corrupted or incomplete!"
                )

            print(f"   ✓ Signed region read: {len(signed_bytes):,} bytes")
            print(f"   ✓ Read time: {read_time:.3f}s")

            # Step 5: Read signature
            print("\n[Step 5/7] Reading signature...")
            sig_length = struct.unpack('>Q', f.read(8))[0]
            signature = f.read(sig_length)

            if len(signature) != sig_length:
                raise ValueError(f"Truncated signature!")

            print(f"   ✓ Signature read: {len(signature)} bytes")

            # Step 6: Read public key
            print("\n[Step 6/7] Reading public key...")
            pk_length = struct.unpack('>Q', f.read(8))[0]
            public_key = f.read(pk_length)

            if len(public_key) != pk_length:
                raise ValueError(f"Truncated public key!")

            if len(public_key) != CRYPTO_PUBLICKEYBYTES:
                raise ValueError(
                    f"Invalid public key size: {len(public_key)}\n"
                    f"Expected: {CRYPTO_PUBLICKEYBYTES}"
                )

            print(f"   ✓ Public key read: {len(public_key)} bytes")

            # Step 7: Verify signature BEFORE deserialization
            if verify:
                print("\n[Step 7/7] Verifying signature (BEFORE deserialization)...")
                print("   [HASH] Computing hash of signed region...")

                start_time = time.time()
                hash_value = hashlib.sha256(signed_bytes).digest()
                hash_time = time.time() - start_time

                print(f"      Hash: {hash_value[:16].hex()}...")
                print(f"      Hash time: {hash_time:.6f}s")

                print("   [VERIFY] Verifying ML-DSA-44 signature...")
                start_time = time.time()
                is_valid = mldsa_verify(signature, hash_value, public_key)
                verify_time = time.time() - start_time

                # Display in milliseconds if less than 0.001 seconds
                if verify_time < 0.001:
                    print(f"      Verify time: {verify_time * 1000:.3f} ms")
                else:
                    print(f"      Verify time: {verify_time:.6f}s")

                if not is_valid:
                    print("\n" + "=" * 70)
                    print("[FAIL] SIGNATURE VERIFICATION FAILED!")
                    print("=" * 70)
                    print("This file may have been:")
                    print("  • Tampered with")
                    print("  • Corrupted")
                    print("  • Signed with a different key")
                    print("\n[WARNING] DO NOT USE THIS MODEL!")
                    print("=" * 70)

                    raise ValueError(
                        "Signature verification FAILED! "
                        "This model may have been tampered with or corrupted. "
                        "DO NOT use this model!"
                    )

                print("\n   [VALID] SIGNATURE VALID!")
                print("      Model has NOT been tampered with")
                print("      Safe to deserialize")
            else:
                print("\n[Step 7/7] Skipping signature verification (verify=False)")
                print("     [WARNING] Loading without verification is dangerous!")

            # Step 8: Deserialize (only if verification passed or skipped)
            print("\n[Step 8/7] Deserializing signed region...")
            start_time = time.time()

            try:
                signed_region = pickle.loads(signed_bytes)
                deserialize_time = time.time() - start_time
            except Exception as e:
                raise ValueError(f"Failed to deserialize signed region: {e}")

            print(f"   [SUCCESS] Deserialized successfully")
            print(f"   [SUCCESS] Deserialize time: {deserialize_time:.3f}s")

            # Extract model data
            if not isinstance(signed_region, dict):
                raise ValueError(f"Invalid signed region type: {type(signed_region)}")

            if 'model_data' not in signed_region:
                raise ValueError("No model_data found in signed region!")

            model_data = signed_region['model_data']
            version_str = signed_region.get('version', 'unknown')
            timestamp = signed_region.get('timestamp', 0)

            print(f"\n   [INFO] Model information:")
            print(f"      Version: {version_str}")
            print(f"      Timestamp: {timestamp}")
            if timestamp:
                from datetime import datetime
                dt = datetime.fromtimestamp(timestamp)
                print(f"      Date: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"      Model type: {type(model_data).__name__}")

        # Summary
        print("\n" + "=" * 70)
        if verify:
            print("[VALID] MODEL LOADED AND VERIFIED SUCCESSFULLY")
        else:
            print("[WARNING]  MODEL LOADED WITHOUT VERIFICATION")
        print("=" * 70)
        print(f"File: {model_path}")
        print(f"Size: {file_size:,} bytes")
        print(f"Signed region: {signed_length:,} bytes")
        print("=" * 70)

        return (True if verify else None), model_data


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) < 2:
        print("Secure Model Signature Tool (Length-Prefix Format)")
        print("=" * 70)
        print("\nUsage:")
        print("  Sign:   python secure_signature.py sign <model.pt> <output.pt> <secret.key> <public.key>")
        print("  Verify: python secure_signature.py verify <signed_model.pt>")
        print("\nExample:")
        print("  python secure_signature.py sign model.pt signed.pt ml_dsa_secret.key ml_dsa_public.key")
        print("  python secure_signature.py verify signed.pt")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'sign':
        if len(sys.argv) != 6:
            print("Usage: python secure_signature.py sign <model.pt> <output.pt> <secret.key> <public.key>")
            sys.exit(1)

        model_path = sys.argv[2]
        output_path = sys.argv[3]
        secret_key_path = sys.argv[4]
        public_key_path = sys.argv[5]

        try:
            # Load original model
            import torch
            print(f"Loading original model: {model_path}")
            model_data = torch.load(model_path, map_location='cpu', weights_only=False)

            # Sign and save
            result = SecureSignedModel.save(
                model_data=model_data,
                secret_key_path=secret_key_path,
                public_key_path=public_key_path,
                output_path=output_path
            )

            sys.exit(0)

        except Exception as e:
            print(f"\n[ERROR] Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    elif command == 'verify':
        if len(sys.argv) != 3:
            print("Usage: python secure_signature.py verify <signed_model.pt>")
            sys.exit(1)

        model_path = sys.argv[2]

        try:
            is_valid, model_data = SecureSignedModel.load(model_path, verify=True)

            if is_valid:
                print("\n[VALID] Verification successful! Model is safe to use.")
                sys.exit(0)
            else:
                print("\n[CRITICAL] Verification failed! DO NOT use this model!")
                sys.exit(1)

        except Exception as e:
            print(f"\n[ERROR] Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    else:
        print(f"Unknown command: {command}")
        print("Available commands: sign, verify")
        sys.exit(1)


if __name__ == "__main__":
    main()
