#include "SetCommon.h"

#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "EducationalQuantumAttack/Attacks/AttackCommon.h"
#include "EducationalQuantumAttack/Attacks/ToyAesGroverAttack.h"
#include "EducationalQuantumAttack/Attacks/ToyShaQuantumAttack.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"

#include <sstream>

namespace crypto::educational_quantum_attack
{
    SymmetricAndHashOutcome run_symmetric_and_hash_attacks(
        const std::string_view set_tag,
        const std::string& set_name,
        const std::string& plaintext,
        const educational::ToyAesSample& aes,
        const std::size_t toy_sha_output_bits,
        const QuantumAttackConfig& config,
        const std::uint64_t root_seed,
        std::vector<AttackResult>& attacks)
    {
        SymmetricAndHashOutcome outcome;
        const std::string tag(set_tag);

        // ---- Toy AES: Grover -------------------------------------------------------------
        report_progress(config, set_name + ": Toy AES - Grover key search");
        {
            // Only the public record goes into the attack; the ground truth stays here.
            ToyAesGroverAttack attack = attack_toy_aes_with_grover(
                aes.public_instance, config, derive_seed(root_seed, tag + "/aes"));
            attack.report.system_name = set_name;
            if (attack.key_recovered)
            {
                const bool key_matches = attack.recovered_key == aes.ground_truth.key;
                const bool plaintext_matches = attack.recovered_plaintext == aes.ground_truth.plaintext;
                attack.report.matches_ground_truth = key_matches && plaintext_matches;
                if (!(key_matches && plaintext_matches))
                {
                    // A verified key that is not the generated one would be a second
                    // authenticating key; report it rather than hide it.
                    attack.report.notes.push_back(
                        "The verified key or plaintext differs from the withheld ground truth.");
                }
            }
            attacks.push_back(std::move(attack.report));
        }

        // ---- Toy SHA: preimage (Grover) ---------------------------------------------------
        outcome.message_digest = educational::truncated_sha256(plaintext, toy_sha_output_bits);
        const std::string preimage_family = "CryptoProject ToySHA preimage " + tag + ":";
        report_progress(config, set_name + ": Toy SHA - Grover preimage search");
        {
            ToyShaPreimageAttack attack = attack_toy_sha_preimage_with_grover(
                outcome.message_digest, toy_sha_output_bits, preimage_family, config,
                derive_seed(root_seed, tag + "/sha-preimage"));
            attack.report.system_name = set_name;
            attack.report.parameters.emplace_back(
                "Origin of the target digest", "Toy SHA digest of this set's message (also its AES-GCM associated data)");
            if (attack.preimage_found)
            {
                outcome.preimage_found = true;
                outcome.preimage_message = attack.message;
                // A preimage search has no withheld secret to compare with: any message with
                // the target digest is a correct answer, and it is verified by recomputation.
                attack.report.notes.push_back(
                    "The found message differs from the set's original message but has the same Toy SHA "
                    "digest, so it would be accepted wherever only the digest is checked.");
            }
            attacks.push_back(std::move(attack.report));
        }

        // ---- Toy SHA: collision (BHT) -----------------------------------------------------
        const std::string collision_family = "CryptoProject ToySHA collision " + tag + ":";
        report_progress(config, set_name + ": Toy SHA - BHT collision search");
        {
            ToyShaCollisionAttack attack = attack_toy_sha_collision_with_bht(
                toy_sha_output_bits, collision_family, config,
                derive_seed(root_seed, tag + "/sha-collision"));
            attack.report.system_name = set_name;
            // A collision has no withheld secret either; the attack verifies it by recomputation.
            attacks.push_back(std::move(attack.report));
        }
        return outcome;
    }

    SetStatus evaluate_set_status(const std::vector<AttackResult>& attacks)
    {
        bool all_succeeded = !attacks.empty();
        for (const AttackResult& attack : attacks)
        {
            if (attack.outcome == AttackOutcome::Failed || attack.execution == ExecutionStatus::Error)
                return SetStatus::Failed;
            if (attack.outcome != AttackOutcome::Succeeded) all_succeeded = false;
        }
        return all_succeeded ? SetStatus::AllSucceeded : SetStatus::Partial;
    }

    void describe_message(
        NamedValues& instance, const std::string& plaintext,
        const std::uint32_t message_digest, const std::size_t toy_sha_output_bits,
        const educational::ToyAesSample& aes)
    {
        instance.emplace_back("Message", printable(plaintext));
        instance.emplace_back("Message bytes", std::to_string(plaintext.size()));
        instance.emplace_back(
            "Toy SHA digest of the message (" + std::to_string(toy_sha_output_bits) + " bits)",
            hex_value(message_digest, 4U));
        instance.emplace_back(
            "Toy AES record", "AES-128-GCM, " + std::to_string(aes.public_instance.unknown_bits) +
            " unknown key bits, " + std::to_string(aes.public_instance.ciphertext.ciphertext.size()) +
            " ciphertext bytes, associated data " + hex_string(aes.public_instance.associated_data));
    }
}
