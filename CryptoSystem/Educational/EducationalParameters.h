#pragma once

#include <cstddef>

namespace crypto::educational
{
    // Canonical parameters of the three independent educational composite sets
    // (AES-SHA-ECDSA analogue, AES-SHA-RSAPSS analogue, SHA-AES-MLKEM analogue).
    //
    // EducationalCryptoSetAnalysis (classical analysis) and EducationalQuantumAttack
    // (quantum attack analysis, 2.3.5) both read these values, so a quantum attack
    // report always refers to the same toy parameters as the classical report.
    inline constexpr std::size_t ToySetAesUnknownKeyBits = 12U;
    inline constexpr std::size_t ToySetRsaModulusBits = 24U;
    inline constexpr std::size_t ToySetShaOutputBits = 16U;
}
