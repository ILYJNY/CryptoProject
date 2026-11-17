#pragma once

// Grover key search against the restricted-keyspace Toy AES of the educational sets.
//
// Target: the real public Toy AES record (AES-128-GCM ciphertext, nonce, tag and the Toy
// SHA digest used as associated data) with `unknown_bits` unknown key bits.
// Problem: unstructured search for the key k in a space of N = 2^unknown_bits candidates
// such that AES-128-GCM authenticates the record under k.
// Algorithm: Grover search with R ~ (pi/4) * sqrt(N / M) iterations.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"

#include <cstdint>
#include <string>

namespace crypto::educational_quantum_attack
{
    struct ToyAesGroverAttack
    {
        AttackResult report;
        bool key_recovered = false;
        standard::Aes128Key recovered_key{};
        std::string recovered_plaintext;
    };

    // Receives only the public instance. `seed` drives the measurement sampling.
    [[nodiscard]] ToyAesGroverAttack attack_toy_aes_with_grover(
        const educational::ToyAesPublicInstance& instance,
        const QuantumAttackConfig& config,
        std::uint64_t seed);
}
