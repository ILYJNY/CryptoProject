#pragma once

// Quantum attacks on Toy SHA, the real SHA-256 truncated to `output_bits` bits.
//
// Two different problems, two different algorithms, two separate reports:
//
//   PREIMAGE  - given a digest d, find a message m with ToySHA(m) = d.
//               Grover search: about (pi/4) * 2^(b/2) oracle calls for a b-bit digest.
//
//   COLLISION - find two different messages with the same digest; there is no target.
//               Brassard-Hoyer-Tapp (BHT): a classical table of about 2^(b/3) digests,
//               then Grover amplification of a table-membership oracle, about 2^(b/3)
//               queries in total, at the price of a quantum-accessible table.
//
// A collision search is never reported as "Grover" alone, and the two results are never
// merged into one figure.
//
// Messages are drawn from a message family { prefix + decimal(counter) }, the same shape
// the existing classical Toy SHA experiments use.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace crypto::educational_quantum_attack
{
    struct ToyShaPreimageAttack
    {
        AttackResult report;
        bool preimage_found = false;
        std::uint64_t message_counter = 0U;
        std::string message;
    };

    [[nodiscard]] ToyShaPreimageAttack attack_toy_sha_preimage_with_grover(
        std::uint32_t target_digest,
        std::size_t output_bits,
        std::string_view family_prefix,
        const QuantumAttackConfig& config,
        std::uint64_t seed);

    struct ToyShaCollisionAttack
    {
        AttackResult report;
        bool collision_found = false;
        std::uint64_t first_counter = 0U;
        std::uint64_t second_counter = 0U;
        std::string first_message;
        std::string second_message;
        std::uint32_t digest = 0U;
    };

    [[nodiscard]] ToyShaCollisionAttack attack_toy_sha_collision_with_bht(
        std::size_t output_bits,
        std::string_view family_prefix,
        const QuantumAttackConfig& config,
        std::uint64_t seed);
}
