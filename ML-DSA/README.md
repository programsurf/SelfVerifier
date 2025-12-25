# Software Testing Application - Technical Specification Document

## Applicant Information

- **Organization**: Korea Institute of Energy Technology
- **Contact**: 010-9203-6961
- **Product Name**: Lattice-Based Digital Signature System with Adaptive Cache-Friendly NTT Operator v1.0
- **Number of Test Items**: 2

---

## 1. Product Installation and Test Configuration

### 1.1 Lattice-Based Digital Signature System with Adaptive Cache-Optimized NTT Operator v1.0

**Components**:

#### ① ML-DSA Cryptographic Library
- FIPS 204 compliant ML-DSA-44/65/87 digital signature algorithms
- ML-DSA public/private key generation functionality
- ML-DSA signature generation functionality
- ML-DSA signature verification functionality
- API interface for application programs

#### ② Adaptive NTT Operation Module
- Number Theoretic Transform (NTT) operation execution
- Improved cache hit rate through cache-friendly memory access patterns
- Performance optimization through vectorized operations using SIMD instructions

#### ③ Measurement Tools
- Verification of proper execution of key generation/signature generation/signature verification operations
- Measurement of CPU cycles and processing time for key generation/signature generation/signature verification operations

#### ④ Test Control Terminal
- Bash shell terminal
- Test program execution control
- Automated test script execution
- Test environment configuration and management
- Test result log collection and storage

#### ⑤ Computing Equipment
- Computing hardware platform for cryptographic algorithm operation processing

---

## 2. Test Equipment and System Specifications

### 2.1 Computing Equipment

- **OS**: Ubuntu 24.04.2 LTS 64-bit
- **CPU**: Intel(R) Core(TM) i9-14900K
- **RAM**: 192GB
- **SSD**: 3.6TB

---

## 3. Test Items

### Test Item No.1

**Test Item Name**: ML-DSA Cryptographic Algorithm Normal Execution Test

#### Test Criteria
- ML-DSA-44/65/87 key generation (Keygen) function operates normally and generates public/private keys
- ML-DSA-44/65/87 signature generation (Sign) function operates normally and generates digital signatures
- ML-DSA-44/65/87 signature verification (Verify) function operates normally and successfully validates signatures

#### Test Method

**1. Test Conditions**

1) Test Network Configuration
   - Test control terminal: DHCP
   - Computing equipment: 192.168.0.100
   - Subnet Mask: 255.255.255.0

**2. Test Procedure**

1) Boot test control terminal and cryptographic operation device, prepare test environment
   - ① Connect 1 test control terminal (laptop) and 1 computing equipment to power supply and boot
   - ② Execute terminal (Bash) from test control terminal

2) ML-DSA-44/65/87 Normal Execution Test
   - ① Navigate to ML-DSA-44 directory in terminal:
```bash
     cd /home/sunwoo/Official_Test/crypto_sign/ml-dsa-44/our-work
```
   - ② Execute test program:
```bash
     ./test_mldsa44
```
   - ③ Verify output results:
     - Confirm "SUCCESS: keypair generated" message
     - Confirm "SUCCESS: message signed" message
     - Confirm "SUCCESS: signature verified" message
   
   - ④ Navigate to ML-DSA-65 directory in terminal:
```bash
     cd /home/sunwoo/Official_Test/crypto_sign/ml-dsa-65/our-work
```
   - ⑤ Execute test program:
```bash
     ./test_mldsa65
```
   - ⑥ Verify output results:
     - Confirm "SUCCESS: keypair generated" message
     - Confirm "SUCCESS: message signed" message
     - Confirm "SUCCESS: signature verified" message
   
   - ⑦ Navigate to ML-DSA-87 directory in terminal:
```bash
     cd /home/sunwoo/Official_Test/crypto_sign/ml-dsa-87/our-work
```
   - ⑧ Execute test program:
```bash
     ./test_mldsa87
```
   - ⑨ Verify output results:
     - Confirm "SUCCESS: keypair generated" message
     - Confirm "SUCCESS: message signed" message
     - Confirm "SUCCESS: signature verified" message

---

### Test Item No.2

**Test Item Name**: ML-DSA Performance Measurement Data Normal Output Test

#### Test Criteria
- ML-DSA-44/65/87 performance benchmark program executes normally
- CPU cycle measurements for key generation (Keygen), signature generation (Sign), and signature verification (Verify) operations are output normally
- Processing time measurements for key generation, signature generation, and signature verification are output normally

#### Test Method

**1. Test Conditions**

1) Test Network Configuration
   - Test control terminal: DHCP
   - Computing equipment: 192.168.0.100
   - Subnet Mask: 255.255.255.0

**2. Test Procedure**

1) Boot test control terminal and cryptographic operation device, prepare test environment
   - ① Connect 1 test control terminal (laptop) and 1 computing equipment to power supply and boot
   - ② Execute terminal (Bash) from test control terminal

2) Execute configuration script for stable performance measurement
```bash
   cd /home/sunwoo/Official_Test
   sudo ./setting.sh
```

3) ML-DSA-44/65/87 Performance Measurement Program Normal Measurement Test
   - ① Navigate to ML-DSA-44 directory in terminal:
```bash
     cd /home/sunwoo/Official_Test/crypto_sign/ml-dsa-44/our-work
```
   - ② Execute test program:
```bash
     ./benchmark_mldsa44
```
   - ③ Verify output results:
     - Confirm Keygen CPU cycles and processing time (ms) output
     - Confirm Sign CPU cycles and processing time (ms) output
     - Confirm Verify CPU cycles and processing time (ms) output
   
   - ④ Navigate to ML-DSA-65 directory in terminal:
```bash
     cd /home/sunwoo/Official_Test/crypto_sign/ml-dsa-65/our-work
```
   - ⑤ Execute test program:
```bash
     ./benchmark_mldsa65
```
   - ⑥ Verify output results:
     - Confirm Keygen CPU cycles and processing time (ms) output
     - Confirm Sign CPU cycles and processing time (ms) output
     - Confirm Verify CPU cycles and processing time (ms) output
   
   - ⑦ Navigate to ML-DSA-87 directory in terminal:
```bash
     cd /home/sunwoo/Official_Test/crypto_sign/ml-dsa-87/our-work
```
   - ⑧ Execute test program:
```bash
     ./benchmark_mldsa87
```
   - ⑨ Verify output results:
     - Confirm Keygen CPU cycles and processing time (ms) output
     - Confirm Sign CPU cycles and processing time (ms) output
     - Confirm Verify CPU cycles and processing time (ms) output

---

## Certification

Regarding the above product for which software testing has been requested, the applicant-provided specifications (standards) and test methods are submitted as above.

**Date**: November 3, 2025

**Applicant**: Seunghyun Yoon (Signature or Seal)

**To**: Director of Jeonnam Technopark