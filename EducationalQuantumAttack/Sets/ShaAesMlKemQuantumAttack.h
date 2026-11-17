#pragma once

// Independent quantum-attack analysis of the educational SHA-AES-MLKEM analogue:
// Toy SHA (truncated SHA-256) + Toy AES (restricted-keyspace AES-128-GCM) + toy Module-LWE.
// The Module-LWE component is a tiny teaching construction, not ML-KEM-768.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/EducationalParameters.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"

#include <cstddef>
#include <string>

namespace crypto::educational_quantum_attack
{
    struct ShaAesMlKemTarget
    {
        std::string plaintext;
        std::size_t toy_sha_output_bits = educational::ToySetShaOutputBits;
        educational::ToyAesSample aes;
        educational::ToyLweSample lwe;
    };

    // Generates the instance with the same generators and parameters as the classical
    // EducationalCryptoSetAnalysis: 12 unknown AES key bits and Module-LWE with n = 4,
    // k = 2, q = 257.
    [[nodiscard]] ShaAesMlKemTarget generate_sha_aes_mlkem_target(const std::string& plaintext);

    // Analyzes exactly the instance it is given.
    [[nodiscard]] SetAttackReport run_sha_aes_mlkem_quantum_attack(
        const ShaAesMlKemTarget& target, const QuantumAttackConfig& config = {});
}
