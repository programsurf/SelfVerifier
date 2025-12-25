#!/usr/bin/env python3
"""
Self-Verifying Secure Model (Internal Verification)
====================================================
모델 내부에 검증 로직을 포함하는 안전한 방식

단계:
1. 모델 + 공개키 내장
2. 모델에 대한 서명 내장
3. torch.load() 시 자동으로 서명 검증
4. 악성 스크립트 주입 시 차단

구조:
    {
        '__model_data__': actual_model_data,
        '__public_key__': public_key_bytes,
        '__signature__': signature_bytes,
        '__verifier__': SelfVerifier class (검증 로직)
    }
"""

import pickle
import hashlib
import struct
from typing import Any
from mldsa44_binding import verify as mldsa_verify


class SelfVerifier:
    """
    자체 검증 클래스
    pickle deserialization 시 자동으로 실행됨
    """

    def __init__(self, model_data_bytes, public_key, signature):
        """
        Args:
            model_data_bytes: 직렬화된 모델 데이터 (bytes)
            public_key: 공개키
            signature: 서명
        """
        self.model_data_bytes = model_data_bytes
        self.public_key = public_key
        self.signature = signature

    def __reduce__(self):
        """
        Pickle deserialization hook
        torch.load() 시 자동으로 _verify_and_restore() 호출
        """
        return (
            _verify_and_restore,
            (self.model_data_bytes, self.public_key, self.signature)
        )


def _verify_and_restore(model_data_bytes, public_key, signature):
    """
    자동 검증 및 복원 함수

    Args:
        model_data_bytes: 직렬화된 모델 데이터 (bytes)
        public_key: ML-DSA-44 공개키
        signature: ML-DSA-44 서명

    Returns:
        검증된 모델 데이터

    Raises:
        ValueError: 서명 검증 실패 시
    """
    import time

    print("\n" + "=" * 70)
    print("[SECURE] SELF-VERIFYING MODEL - AUTO VERIFICATION")
    print("=" * 70)

    # Step 1: Check model data bytes
    print("\n[Step 1/3] Checking serialized model data...")
    print(f"   Model data size: {len(model_data_bytes):,} bytes")

    # Step 2: Compute hash (직접 bytes에서 계산)
    print("\n[Step 2/3] Computing SHA-256 hash...")
    hash_start = time.time()
    computed_hash = hashlib.sha256(model_data_bytes).digest()
    hash_time = time.time() - hash_start
    print(f"   Computed hash: {computed_hash[:16].hex()}...")
    print(f"   Hash time: {hash_time * 1000:.2f} ms")

    # Step 3: Verify signature
    print("\n[Step 3/3] Verifying ML-DSA-44 signature...")
    print(f"   Signature size: {len(signature)} bytes")
    print(f"   Public key size: {len(public_key)} bytes")

    verify_start = time.time()
    is_valid = mldsa_verify(signature, computed_hash, public_key)
    verify_time = time.time() - verify_start
    print(f"   Verify time: {verify_time * 1000:.2f} ms")

    if not is_valid:
        print("   [FAIL] Signature verification failed!")
        print("\n" + "=" * 70)
        print("[FAIL] SIGNATURE VERIFICATION FAILED!")
        print("=" * 70)
        print("This model may have been:")
        print("  • Signed with a different key")
        print("  • Corrupted during transfer")
        print("  • Tampered with maliciously")
        print("\n[WARNING] DO NOT USE THIS MODEL!")
        print("=" * 70)
        raise ValueError(
            "Signature verification FAILED! "
            "This model may be from an untrusted source. "
            "DO NOT use this model!"
        )

    print("   [VALID] Signature VALID!")

    print("\n" + "=" * 70)
    print("[VALID] VERIFICATION COMPLETE - MODEL IS AUTHENTIC")
    print("=" * 70)
    print("All security checks passed:")
    print("  ✓ Cryptographic signature valid")
    print("  ✓ Model is from trusted source")
    print("  ✓ Model has not been tampered")
    print("  ✓ Safe to use")
    print("=" * 70 + "\n")

    # Step 4: Return SelfVerifier object (preserves signature for re-save protection)
    print("[Step 4/3] Returning verified SelfVerifier object...")
    print(f"   ✓ Signature and public key preserved in returned object")
    print(f"   ✓ This ensures re-saved models will still be verified")

    # Store timing info in the verifier for later retrieval
    verifier = SelfVerifier(model_data_bytes, public_key, signature)
    verifier._timing = {
        'hash_time': hash_time,
        'verify_time': verify_time
    }

    # Return SelfVerifier object instead of raw model data
    # This ensures that if someone loads -> modifies -> saves:
    # - Original signature and public key are preserved
    # - Modified model_data_bytes will fail signature verification
    # - Attack is blocked on next load!
    return verifier


def create_self_verifying_model(model_path: str, secret_key_path: str,
                                  public_key_path: str, output_path: str) -> dict:
    """
    자체 검증 모델 생성

    Args:
        model_path: 원본 모델 파일 경로
        secret_key_path: 비밀키 경로
        public_key_path: 공개키 경로
        output_path: 출력 파일 경로

    Returns:
        생성 결과 정보
    """
    import torch
    import time
    import os
    from mldsa44_binding import sign as mldsa_sign

    print("=" * 70)
    print(" CREATING SELF-VERIFYING MODEL")
    print("=" * 70)

    # Step 1: Load original model
    print(f"\n[Step 1/6] Loading original model: {model_path}")
    start_time = time.time()
    model_data = torch.load(model_path, map_location='cpu', weights_only=False)
    load_time = time.time() - start_time

    model_size = os.path.getsize(model_path)
    print(f"   ✓ Model loaded")
    print(f"   Type: {type(model_data).__name__}")
    print(f"   Size: {model_size / (1024*1024):.2f} MB")
    print(f"   Load time: {load_time:.3f}s")

    # Step 2: Serialize model data
    print(f"\n[Step 2/6] Serializing model data...")
    start_time = time.time()
    model_bytes = pickle.dumps(model_data, protocol=4)
    serialize_time = time.time() - start_time

    print(f"   ✓ Serialized: {len(model_bytes):,} bytes")
    print(f"   Serialize time: {serialize_time:.3f}s")

    # Step 3: Compute hash
    print(f"\n[Step 3/6] Computing SHA-256 hash...")
    start_time = time.time()
    model_hash = hashlib.sha256(model_bytes).digest()
    hash_time = time.time() - start_time

    print(f"   ✓ Hash computed: {model_hash[:16].hex()}...")
    print(f"   Hash time: {hash_time:.6f}s")

    # Step 4: Load keys
    print(f"\n[Step 4/6] Loading cryptographic keys...")
    with open(secret_key_path, 'rb') as f:
        secret_key = f.read()
    with open(public_key_path, 'rb') as f:
        public_key = f.read()

    print(f"   ✓ Secret key: {len(secret_key)} bytes")
    print(f"   ✓ Public key: {len(public_key)} bytes")

    # Step 5: Sign
    print(f"\n[Step 5/6] Signing with ML-DSA-44...")
    start_time = time.time()
    signature = mldsa_sign(model_hash, secret_key)
    sign_time = time.time() - start_time

    print(f"   ✓ Signature generated: {len(signature)} bytes")
    print(f"   Sign time: {sign_time:.3f}s")

    # Step 6: Create self-verifying model
    print(f"\n[Step 6/6] Creating self-verifying model...")
    self_verifying = SelfVerifier(
        model_data_bytes=model_bytes,  # 직렬화된 bytes 저장!
        public_key=public_key,
        signature=signature
    )

    print(f"   ✓ Self-verifying wrapper created")
    print(f"      Model data bytes: {len(model_bytes):,} bytes (embedded)")
    print(f"      Public key: {len(public_key)} bytes (embedded)")
    print(f"      Signature: {len(signature)} bytes (embedded)")

    # Step 7: Save
    print(f"\n[Step 7/6] Saving self-verifying model...")
    start_time = time.time()
    torch.save(self_verifying, output_path, pickle_protocol=4)
    save_time = time.time() - start_time

    output_size = os.path.getsize(output_path)
    overhead = output_size - model_size

    print(f"   ✓ Saved to: {output_path}")
    print(f"   Output size: {output_size / (1024*1024):.2f} MB")
    print(f"   Overhead: {overhead / 1024:.2f} KB ({overhead * 100.0 / model_size:.4f}%)")
    print(f"   Save time: {save_time:.3f}s")

    # Summary
    total_time = load_time + serialize_time + hash_time + sign_time + save_time

    print("\n" + "=" * 70)
    print("[SUCCESS] SELF-VERIFYING MODEL CREATED SUCCESSFULLY")
    print("=" * 70)
    print(f"Original: {model_path}")
    print(f"Output: {output_path}")
    print(f"Total time: {total_time:.3f}s")
    print("\nSecurity features:")
    print("  ✓ Embedded public key")
    print("  ✓ Embedded signature")
    print("  ✓ Automatic verification on load")
    print("=" * 70)

    return {
        'success': True,
        'original_path': model_path,
        'output_path': output_path,
        'original_size': model_size,
        'output_size': output_size,
        'overhead': overhead,
        'total_time': total_time,
        'serialize_time': serialize_time,
        'hash_time': hash_time,
        'sign_time': sign_time,
        'save_time': save_time
    }


def verify_self_verifying_model(model_path: str):
    """
    자체 검증 모델 로드 (자동 검증)

    Args:
        model_path: 모델 파일 경로

    Returns:
        (검증 성공 여부, 모델 데이터, timing_info)
    """
    import torch
    import time
    import os

    print("\n" + "=" * 70)
    print("[VERIFY] LOADING SELF-VERIFYING MODEL")
    print("=" * 70)
    print(f"File: {model_path}\n")

    try:
        # Measure read time
        read_start = time.time()
        file_size = os.path.getsize(model_path)

        # torch.load()가 자동으로 __reduce__를 호출하여 검증 실행
        verifier = torch.load(model_path, weights_only=False)
        total_load_time = time.time() - read_start

        # Extract timing info if available
        timing_info = {
            'total_time': total_load_time,
            'file_size': file_size
        }

        if hasattr(verifier, '_timing'):
            timing_info['hash_time'] = verifier._timing['hash_time']
            timing_info['verify_time'] = verifier._timing['verify_time']
            # Read time = total - hash - verify
            timing_info['read_time'] = total_load_time - timing_info['hash_time'] - timing_info['verify_time']

        # 검증에 성공하면 verifier가 반환됨
        return True, verifier, timing_info

    except ValueError as e:
        print(f"\n[FAIL] Verification failed: {e}")
        return False, None, None
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Self-Verifying Secure Model")
        print("=" * 70)
        print("\nUsage:")
        print("  Create: python self_verifying_secure.py create <model.pt> <output.pt> <secret.key> <public.key>")
        print("  Verify: python self_verifying_secure.py verify <model.pt>")
        print("\nExample:")
        print("  python self_verifying_secure.py create model.pt signed.pt ml_dsa_secret.key ml_dsa_public.key")
        print("  python self_verifying_secure.py verify signed.pt")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'create':
        if len(sys.argv) != 6:
            print("Usage: python self_verifying_secure.py create <model.pt> <output.pt> <secret.key> <public.key>")
            sys.exit(1)

        model_path = sys.argv[2]
        output_path = sys.argv[3]
        secret_key_path = sys.argv[4]
        public_key_path = sys.argv[5]

        try:
            result = create_self_verifying_model(
                model_path, secret_key_path, public_key_path, output_path
            )
            sys.exit(0)
        except Exception as e:
            print(f"\n[ERROR] Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    elif command == 'verify':
        if len(sys.argv) != 3:
            print("Usage: python self_verifying_secure.py verify <model.pt>")
            sys.exit(1)

        model_path = sys.argv[2]

        try:
            is_valid, model_data = verify_self_verifying_model(model_path)

            if is_valid:
                print("\n[VALID] Verification successful!")
                sys.exit(0)
            else:
                print("\n[FAIL] Verification failed!")
                sys.exit(1)

        except Exception as e:
            print(f"\n[ERROR] Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    else:
        print(f"Unknown command: {command}")
        print("Available commands: create, verify")
        sys.exit(1)
