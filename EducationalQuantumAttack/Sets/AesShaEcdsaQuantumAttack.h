#pragma once

// Independent quantum-attack analysis of the educational AES-SHA-ECDSA analogue:
// Toy AES (restricted-keyspace AES-128-GCM) + Toy SHA (truncated SHA-256) + the toy
// elliptic curve. The ECC component is an educational analogue, not standard ECDSA.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/EducationalParameters.h"

#include <cstddef>
#include <string>

namespace crypto::educational_quantum_attack
{
    // One generated instance of the set: public data plus the withheld ground truth, which
    // is used only to check results after an attack has finished.
    struct AesShaEcdsaTarget
    {
        std::string plaintext;
        std::size_t toy_sha_output_bits = educational::ToySetShaOutputBits;
        educational::ToyAesSample aes;
        educational::ToyEccSample ecc;
    };

    // Generates the instance with the same generators and parameters as the classical
    // EducationalCryptoSetAnalysis: 12 unknown AES key bits and the fixed toy curve.
    [[nodiscard]] AesShaEcdsaTarget generate_aes_sha_ecdsa_target(const std::string& plaintext);

    // Analyzes exactly the instance it is given.
    [[nodiscard]] SetAttackReport run_aes_sha_ecdsa_quantum_attack(
        const AesShaEcdsaTarget& target, const QuantumAttackConfig& config = {});
}
