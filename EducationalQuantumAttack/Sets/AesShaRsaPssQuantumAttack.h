#pragma once

// Independent quantum-attack analysis of the educational AES-SHA-RSAPSS analogue:
// Toy AES (restricted-keyspace AES-128-GCM) + Toy SHA (truncated SHA-256) + toy RSA.
// The RSA component is an educational analogue, not a standard RSA-PSS signature.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/EducationalParameters.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"

#include <cstddef>
#include <string>

namespace crypto::educational_quantum_attack
{
    struct AesShaRsaPssTarget
    {
        std::string plaintext;
        std::size_t toy_sha_output_bits = educational::ToySetShaOutputBits;
        educational::ToyAesSample aes;
        educational::ToyRsaSample rsa;
    };

    // Generates the instance with the same generators and parameters as the classical
    // EducationalCryptoSetAnalysis: 12 unknown AES key bits and a 24-bit RSA modulus.
    // A different modulus size (16 to 32 bits) can be requested for experiments; the
    // report always states the size that was actually generated.
    [[nodiscard]] AesShaRsaPssTarget generate_aes_sha_rsapss_target(
        const std::string& plaintext,
        std::size_t rsa_modulus_bits = educational::ToySetRsaModulusBits);

    // Analyzes exactly the instance it is given.
    [[nodiscard]] SetAttackReport run_aes_sha_rsapss_quantum_attack(
        const AesShaRsaPssTarget& target, const QuantumAttackConfig& config = {});
}
