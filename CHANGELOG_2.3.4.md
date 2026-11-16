# CryptoProject 2.3.4

## Educational Toy SHA integration across all three custom-message composite demonstrations

- Bound the entered message's 16-bit truncated SHA-256 digest to each of the three independent educational composites, beyond the shared AES-GCM AAD binding.
- Toy ECC set: derive a small challenge from the digest and verify a response using the recovered toy scalar.
- Toy RSA set: derive a message representative from the digest and verify RSA public/private modular exponentiation after toy factor recovery.
- Toy Module-LWE set: derive sender/receiver teaching shared-key values from the message digest and secret coefficients using Toy SHA.
- Extended the EducationalCryptoSetAnalysis smoke test to require all three message-bound SHA paths and exact plaintext recovery for `Hello`.
- No claim of standards-compliant ECDSA, RSA-PSS, or ML-KEM is made; these remain educational analogues.
