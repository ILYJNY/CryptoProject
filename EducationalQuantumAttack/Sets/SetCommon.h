#pragma once

// Pieces shared by the three independent set analyses. Each set owns its own toy AES
// record and its own Toy SHA experiments; nothing is shared between the sets at run time.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::educational_quantum_attack
{
    struct SymmetricAndHashOutcome
    {
        std::uint32_t message_digest = 0U;      // Toy SHA digest of the set's message
        bool preimage_found = false;
        std::string preimage_message;           // another message with the same digest
    };

    // Runs the three attacks every set has in common and appends their reports:
    //   Toy AES (Grover), Toy SHA preimage (Grover), Toy SHA collision (BHT).
    // `set_tag` separates the Toy SHA message families of the sets.
    [[nodiscard]] SymmetricAndHashOutcome run_symmetric_and_hash_attacks(
        std::string_view set_tag,
        const std::string& set_name,
        const std::string& plaintext,
        const educational::ToyAesSample& aes,
        std::size_t toy_sha_output_bits,
        const QuantumAttackConfig& config,
        std::uint64_t root_seed,
        std::vector<AttackResult>& attacks);

    // FAILED if an executed attack failed or raised an error; ALL SUCCEEDED if every attack
    // was executed and succeeded; PARTIAL otherwise.
    [[nodiscard]] SetStatus evaluate_set_status(const std::vector<AttackResult>& attacks);

    // The message description lines shared by every set report.
    void describe_message(
        NamedValues& instance, const std::string& plaintext,
        std::uint32_t message_digest, std::size_t toy_sha_output_bits,
        const educational::ToyAesSample& aes);
}
