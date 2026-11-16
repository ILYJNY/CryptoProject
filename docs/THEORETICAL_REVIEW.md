# Theoretical review — CryptoProject v2.1

This review is a source-level mathematical and architectural review. It is not a build, runtime test,
formal proof, cryptographic certification, or independent security audit.

## 1. Educational Module-LWE model

The earlier toy implementation used a rectangular matrix over `Z_q` and computed `b = A s + e`.
That is ordinary LWE, not Module-LWE. The v2.0 educational model has been corrected to use

`R_q = Z_257[x] / (x^4 + 1)`

and the module relation

`b = A s + e`, where `A` is a 2 x 2 matrix over `R_q`, and `s`, `e`, and `b` are rank-2 vectors
whose entries are polynomials of degree less than 4.

The ring multiplication uses the relation `x^4 = -1`. Thus a product term of degree 4, 5, or 6
wraps to degree 0, 1, or 2 respectively with a negative sign. Each secret coefficient and each
error coefficient is sampled from `{-1, 0, 1}`. The analyzer enumerates `3^(2*4) = 6561`
possible secret coefficient vectors and checks whether each residual coefficient is a permitted
small error. This makes the algebraic structure Module-LWE-like at the teaching level, but the
parameters are tiny and provide no meaningful security. It is not ML-KEM.

## 2. Toy ECC group

For `y^2 = x^3 + 2x + 3 (mod 97)`, the discriminant condition is nonzero:
`4a^3 + 27b^2 = 275 = 81 (mod 97)`. The curve is therefore nonsingular over `F_97`.
The chosen point `(0,10)` lies on the curve because `10^2 mod 97 = 100 mod 97 = 3`,
which equals `0^3 + 2*0 + 3 mod 97`. Repeated addition of this point returns to the identity
after 50 additions, so its order is 50. The curve has 100 points including its identity. This check supports the constants used by the scalar-multiplication demonstration;
it does not make the group cryptographically secure.

## 3. Toy RSA

The toy modulus is formed from two small primes and uses the ordinary RSA relationship
`ed = 1 mod phi(n)`. The toy analyzer performs trial division, checks both factors, derives `d`,
and decrypts the generated public instance. The maximum modulus is 32 bits, so this is an arithmetic
exercise and not a proxy for RSA-4096.

## 4. Toy AES keyspace and truncated hash

The AES exercise retains the AES-128-GCM primitive and fixes all but 4-16 key bits. The analyzer
tries only this restricted candidate space and accepts a key only when GCM authentication succeeds.
This does not weaken the AES primitive to a smaller key size in general; it changes the experiment's
key-generation distribution. The SHA exercise keeps SHA-256 but truncates the observed output to
4-16 bits, so its collisions are collisions in the truncated function only.

## 5. Standard cryptographic implementation caveats

- RSA OAEP/PSS functionality uses custom arithmetic over Boost.Multiprecision. The arithmetic and
  private-key operations are not constant-time hardened.
- P-256 point operations and scalar multiplication are straightforward variable-time routines.
  ECDH output is the raw shared x-coordinate and must not be used as a session key without a KDF.
- AES-GCM and SHA-256 are custom implementations. The limited in-project known-answer tests are
  smoke checks, not a complete set of test vectors.
- The standard analyzer's SHA/AES KATs and RSA size-policy helper do not constitute a complete audit.

## 6. ML-KEM-768 implementation

The project now includes a portable C++ implementation of the ML-KEM-768 parameter set. The
implementation contains Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, SHAKE256, the NTT and inverse
NTT, polynomial/vector encoding and compression, K-PKE, key generation, encapsulation, decapsulation,
and implicit rejection. ML-KEM no longer depends on the Windows CNG `BCryptEncapsulate` or
`BCryptDecapsulate` functions, so this platform-specific API is not a runtime requirement.

The primitive tests compare SHA3/SHAKE outputs with known-answer values; the arithmetic test compares
NTT-domain multiplication with direct negacyclic polynomial multiplication. The KEM round-trip,
invalid-ciphertext implicit-rejection behavior, and decapsulation-key hash check are also covered by
a CTest target. During development, bidirectional encapsulation/decapsulation interoperability with
OpenSSL 3.5.5 ML-KEM-768 passed. These checks do not equal NIST ACVP validation, formal verification,
or an independent security audit. The implementation must not be treated as production-ready.

NIST's FIPS 203 publication page records a planning note dated November 17, 2025 that an issue was
identified for correction in a future update/revision. Check the official publication and current
errata before using the implementation for standards or compliance work.

## 7. Quantum simulation limits

The simulator represents a pure quantum state with `2^n` complex amplitudes. With 16-byte complex
amplitudes, the raw amplitude storage is approximately `16 * 2^n` bytes (excluding container and
working memory). At 22 qubits this is about 64 MiB for the amplitude array alone. This is classical
state-vector emulation and has exponential scaling.

The Grover and QFT examples operate on small registers. The Shor example is limited to odd composite
integers up to 15, uses a reversible modular-permutation representation, and performs a direct
state-vector QFT. Its reported qubit and depth counters are simulator/model counters; they are not
fault-tolerant quantum hardware resource estimates.

## 8. CUDA implementation boundaries

- The vector-add API supports CPU, a selected GPU, automatic GPU selection, and splitting a workload
  across visible GPUs. Multi-GPU mode distributes work; it does not compare GPU results to one another.
- The CUDA SHA-256 batch kernel handles exactly one 512-bit padded block per message, hence at most
  55 input bytes. The regular CPU SHA-256 method accepts longer input.
- CUDA quantum entry points implement Hadamard, phase flip, and diffusion state-vector operations.
  The normal experiment helper functions currently call CPU gate methods; GPU kernels are available
  as explicit low-level methods rather than automatically selected for all quantum experiments.
- The CUDA code was not compiled or run on the target GPU in this delivery.

## 9. Overall conclusion

At a conceptual level, the project now has a coherent educational separation between standard
cryptographic demonstrations, intentionally weak toy instances, controlled analysis, and a classical
quantum simulator. The most important semantic correction in this delivery is the polynomial-ring
Module-LWE teaching model. The most important implementation caveats remain variable-time custom
cryptography, incomplete KAT coverage and lack of an independent ML-KEM audit/ACVP validation,
limited CUDA routing, and the exponential state-vector simulator cost.
