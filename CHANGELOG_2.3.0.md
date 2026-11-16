# CryptoProject 2.3.0

- Added `EducationalCryptoSetAnalysis` with three independent toy analogues corresponding to the standard AES-SHA-ECDSA, AES-SHA-RSAPSS, and SHA-AES-MLKEM sets.
- Added `IntegratedEducationalCryptoAnalysis` to batch-run the three toy sets and aggregate measured toy attack runtimes.
- Added TXT and CSV report export under `Output/EducationalCryptoSetAnalysis` and `Output/IntegratedEducationalCryptoAnalysis`.
- Added measured classical toy-attack time, candidate counts, and measured tiny Grover/Shor state-vector simulator runtime.
- Added a dedicated educational smoke test.
- Explicitly labels all toy outputs as educational only; no real-world security or full-size compromise-time claims are made.
