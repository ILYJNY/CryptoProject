# ML-KEM-768 (FIPS 203 parameter set)

This directory contains an in-tree, portable C++ implementation of ML-KEM-768. It no longer calls
`BCryptEncapsulate` or `BCryptDecapsulate`, so the KEM implementation itself does not require the
Windows 11 CNG ML-KEM APIs and can run on Windows 10 as well as other supported platforms.

The implementation includes Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, SHAKE256, the ML-KEM
NTT/inverse NTT operations, polynomial/vector operations, canonical encodings and compression,
K-PKE key generation/encryption/decryption, and the ML-KEM encapsulation/decapsulation transforms
with implicit rejection.

## ML-KEM-768 sizes

- Encapsulation key: 1184 bytes
- Decapsulation key: 2400 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes

## Build and demo

`MLKEM768.cpp` is already part of `crypto_system_standard`. The main menu's ML-KEM option runs an
end-to-end key generation / encapsulation / decapsulation self-test.

## Security status

This is a readable, portable project implementation intended for learning, integration work, and
conformance testing. It has not undergone an independent security audit or NIST ACVP validation.
Do not treat it as production-ready cryptography until it has passed official ML-KEM test vectors,
independent interoperability tests, side-channel review, and expert audit. Secret buffers are
cleared on a best-effort basis; ordinary C++ containers and the platform/compiler may retain copies.

The educational Module-LWE model under `CryptoSystem/Educational/ModuleLWE/` remains a separate,
intentionally insecure teaching example and is not ML-KEM.

## Specification

- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- NIST ACVP ML-KEM test specification: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html
