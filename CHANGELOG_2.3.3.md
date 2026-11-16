# CryptoProject 2.3.3

## Educational custom-message simulation

- Added an input prompt under `Educational CryptoSystem -> Educational CryptoSetAnalysis`:
  `5. Enter plaintext and run toy encryption / key-recovery simulation`.
- The entered UTF-8 message is passed to the educational AES-GCM sample generator instead of the previous fixed demonstration sentence.
- Each of the three independent educational sets now encrypts the same entered message using the restricted 12-bit unknown-key space, runs the toy AES key-search analyzer, decrypts with the recovered key, and checks exact plaintext equality.
- The entered message is also processed by Toy SHA-256 (the real SHA-256 computation truncated to 16 output bits); those digest bytes are passed into AES-GCM as associated authenticated data (AAD), so SHA is connected to the encryption/authentication operation rather than only printed.
- Each set separately runs its existing toy key-establishment/key-recovery analogue (toy ECC, toy RSA, or tiny Module-LWE).
- Reports distinguish toy analogues from real ECDSA, RSA-PSS, and standardized ML-KEM; they do not claim signature functionality that is not implemented.

## Limitations

- The AES primitive is AES-128-GCM, but the unknown keyspace is intentionally reduced to 12 bits for the educational attack demonstration. It is not a secure AES-128 deployment.
- The ECC/RSA/Module-LWE components remain tiny educational analogues and are not standards-compliant ECDSA, RSA-PSS, or ML-KEM implementations.
- The SHA digest shown for the user's message is not itself a collision search. Collision search remains a separate experiment.
- GPU execution is not claimed by this custom-message simulation; it is not silently replaced with a different workload.
