#include "AesShaRsaPssQuantumAttack.h"

#include "SetCommon.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "EducationalQuantumAttack/Attacks/ToyPublicKeyAnalysis.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"

namespace crypto::educational_quantum_attack
{
    AesShaRsaPssTarget generate_aes_sha_rsapss_target(
        const std::string& plaintext, const std::size_t rsa_modulus_bits)
    {
        AesShaRsaPssTarget target;
        target.plaintext = plaintext;
        target.aes = educational::generate_toy_aes_sample(educational::ToySetAesUnknownKeyBits, plaintext);
        target.rsa = educational::generate_toy_rsa_sample(rsa_modulus_bits);
        return target;
    }

    SetAttackReport run_aes_sha_rsapss_quantum_attack(
        const AesShaRsaPssTarget& target, const QuantumAttackConfig& config)
    {
        const Stopwatch stopwatch;
        SetAttackReport report;
        report.id = SetId::AesShaRsaPss;
        report.name = "Educational AES-SHA-RSAPSS analogue";
        report.composition =
            "Toy AES (real AES-128-GCM, restricted key space) + Toy SHA (real SHA-256, truncated digest) + "
            "toy RSA";
        report.disclaimer =
            "An educational analogue with deliberately tiny parameters. The RSA component is not a standard "
            "RSA-PSS signature or RSA-2048, the AES key space is not that of AES-128, and the digest is not "
            "full SHA-256.";

        const std::uint64_t root_seed = resolve_seed(config.seed);
        const SymmetricAndHashOutcome common = run_symmetric_and_hash_attacks(
            "B", report.name, target.plaintext, target.aes, target.toy_sha_output_bits,
            config, root_seed, report.attacks);

        const std::uint64_t modulus = target.rsa.public_instance.modulus;
        describe_message(
            report.instance, target.plaintext, common.message_digest, target.toy_sha_output_bits, target.aes);
        report.instance.emplace_back(
            "Toy RSA public key", "N = " + std::to_string(modulus) + " (" +
            std::to_string(bit_length(modulus)) + " bits), e = " +
            std::to_string(target.rsa.public_instance.public_exponent));
        // 2.3.4 binding: the digest selects a small RSA message representative.
        if (modulus > 1U)
        {
            const std::uint64_t representative = (static_cast<std::uint64_t>(common.message_digest) % (modulus - 1U)) + 1U;
            report.instance.emplace_back(
                "Toy SHA binding in this set",
                "digest-derived RSA message representative (digest mod (N - 1)) + 1 = " + std::to_string(representative));
            if (common.preimage_found)
            {
                const std::uint64_t other_representative =
                    (static_cast<std::uint64_t>(educational::truncated_sha256(
                         common.preimage_message, target.toy_sha_output_bits)) % (modulus - 1U)) + 1U;
                report.instance.emplace_back(
                    "Effect of the Toy SHA preimage on the binding",
                    other_representative == representative
                        ? "the found message yields the same RSA message representative as the original message"
                        : "the found message yields a different RSA message representative");
            }
        }

        report_progress(config, report.name + ": Toy RSA - Shor (factoring) correspondence and resource model");
        AttackResult rsa = analyze_toy_rsa_shor_theory(target.rsa.public_instance, config);
        rsa.system_name = report.name;
        report.attacks.push_back(std::move(rsa));

        report.status = evaluate_set_status(report.attacks);
        report.wall_ms = stopwatch.elapsed_ms();
        return report;
    }
}
