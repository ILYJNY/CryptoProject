# CryptoSetAnalysis and IntegratedCryptoAnalysis

## Design rule

There are two separate top-level modules:

1. `CryptoSetAnalysis/` runs and compares each cryptosystem independently.
2. `IntegratedCryptoAnalysis/` runs all three independent analyses in a single batch and aggregates their resource/time output.

The integrated module is not a hybrid cryptosystem. It does not concatenate the three shared secrets or generate one cipher that contains all three algorithms.

## Independent sets

| Set | Key establishment / transport | Signature | Symmetric encryption | Hash/KDF |
|---|---|---|---|---|
| AES-SHA-ECDSA | P-256 ECDH | P-256 ECDSA | AES-128-GCM | SHA-256 / HKDF-SHA-256 |
| AES-SHA-RSAPSS | RSA-OAEP-SHA-256 transports a fresh secret | RSA-PSS-SHA-256 | AES-128-GCM | SHA-256 / HKDF-SHA-256 |
| SHA-AES-MLKEM | ML-KEM-768 | None in this set | AES-128-GCM | SHA-256 / HKDF-SHA-256 |

RSA-PSS and ECDSA are signatures; neither is itself a key-agreement algorithm. For the first set, P-256 ECDH establishes the secret and ECDSA authenticates the signed ciphertext metadata. For the second set, RSA-OAEP transports the random secret and RSA-PSS authenticates the ciphertext metadata.

For compactness the RSA teaching runner reuses its single generated RSA key pair for OAEP and PSS. A production protocol should use separate key pairs for key transport/encryption and signatures. The ML-KEM set authenticates ciphertext integrity with AES-GCM but does not authenticate the sender's identity because it has no digital signature.

## Measured operations

The `SetRunResult` contains:

- key generation time;
- key establishment/encapsulation time;
- SHA-256 and HKDF-SHA-256 time;
- AES-GCM encryption and decryption time;
- signature generation and verification time when the set has a signature;
- total cryptosystem operation time and ciphertext length;
- result flags for shared-secret agreement, signature verification, and end-to-end decryption.

Quantum toy-simulator time is recorded separately from cryptosystem operation time.

## Quantum model

### Grover

The AES-128 key-search query estimate uses the ideal unstructured-search model:

`(pi/4) * sqrt(2^128) = (pi/4) * 2^64` iterations.

The SHA-256 generic preimage model uses:

`(pi/4) * sqrt(2^256) = (pi/4) * 2^128` iterations.

The report also converts these query counts into an illustrative time using an explicitly assumed 1 microsecond per logical iteration. This is not a measured quantum hardware iteration time. The 3-qubit Grover run is a toy circuit simulation only.

### Shor

- P-256 ECDH/ECDSA: Shor applies to the elliptic-curve discrete logarithm. The project currently displays a coarse `3*n+1` register-size illustration, not a full logical-qubit estimate.
- RSA: Shor applies to integer factorization. The same coarse register-size illustration is used for the selected RSA modulus size.
- ML-KEM-768: Shor's factoring/discrete-log algorithm is not a direct Module-LWE attack. The project reports this as not applicable rather than inventing resource numbers.

The `N=15` Shor simulation is a tiny educational example. Its measured elapsed milliseconds are not a time-to-break estimate for RSA or P-256.

## Aggregation semantics

`IntegratedCryptoAnalysis` executes the three set runs sequentially and records:

- orchestration wall time;
- sum of individual set operation times;
- maximum single-set operation time;
- sum of the small toy quantum simulator times;
- Grover query totals across the three independent AES keys and three SHA-256 preimage models;
- sum and peak of the separate Shor register-size illustrations.

The sum of Shor register illustrations is a ledger across distinct problems; it is not a claim that one circuit needs that many qubits. The peak value is the largest individual modeled register if a hypothetical machine is reused sequentially.
