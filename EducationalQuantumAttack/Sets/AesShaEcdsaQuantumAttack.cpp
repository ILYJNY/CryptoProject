#include "AesShaEcdsaQuantumAttack.h"

#include "SetCommon.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "EducationalQuantumAttack/Attacks/ToyPublicKeyAnalysis.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"

namespace crypto::educational_quantum_attack
{
    AesShaEcdsaTarget generate_aes_sha_ecdsa_target(const std::string& plaintext)
    {
        AesShaEcdsaTarget target;
        target.plaintext = plaintext;
        target.aes = educational::generate_toy_aes_sample(educational::ToySetAesUnknownKeyBits, plaintext);
        target.ecc = educational::generate_toy_ecc_sample();
        return target;
    }

    SetAttackReport run_aes_sha_ecdsa_quantum_attack(
        const AesShaEcdsaTarget& target, const QuantumAttackConfig& config)
    {
        const Stopwatch stopwatch;
        SetAttackReport report;
        report.id = SetId::AesShaEcdsa;
        report.name = "Educational AES-SHA-ECDSA analogue";
        report.composition =
            "Toy AES (real AES-128-GCM, restricted key space) + Toy SHA (real SHA-256, truncated digest) + "
            "toy elliptic curve";
        report.disclaimer =
            "An educational analogue with deliberately tiny parameters. The ECC component is not standard "
            "ECDSA or P-256, the AES key space is not that of AES-128, and the digest is not full SHA-256.";

        const std::uint64_t root_seed = resolve_seed(config.seed);
        const SymmetricAndHashOutcome common = run_symmetric_and_hash_attacks(
            "A", report.name, target.plaintext, target.aes, target.toy_sha_output_bits,
            config, root_seed, report.attacks);

        const educational::ToyEccCurveParameters curve = educational::toy_ecc_curve_parameters();
        describe_message(
            report.instance, target.plaintext, common.message_digest, target.toy_sha_output_bits, target.aes);
        report.instance.emplace_back(
            "Toy ECC public point", "(" + std::to_string(target.ecc.public_instance.public_x) + ", " +
            std::to_string(target.ecc.public_instance.public_y) + ")");
        // 2.3.4 binding: the digest selects a small challenge on the toy curve.
        const std::uint32_t challenge_modulus = curve.base_point_order > 1U ? curve.base_point_order - 1U : 1U;
        const std::uint32_t challenge = (common.message_digest % challenge_modulus) + 1U;
        report.instance.emplace_back(
            "Toy SHA binding in this set", "digest-derived ECC challenge (digest mod " +
            std::to_string(challenge_modulus) + ") + 1 = " + std::to_string(challenge));
        if (common.preimage_found)
        {
            const std::uint32_t other_challenge =
                (educational::truncated_sha256(common.preimage_message, target.toy_sha_output_bits) %
                 challenge_modulus) + 1U;
            report.instance.emplace_back(
                "Effect of the Toy SHA preimage on the binding",
                other_challenge == challenge
                    ? "the found message yields the same ECC challenge as the original message"
                    : "the found message yields a different ECC challenge");
        }

        report_progress(config, report.name + ": Toy ECC - Shor (ECDLP) correspondence and resource model");
        AttackResult ecc = analyze_toy_ecc_shor_theory(target.ecc.public_instance, config);
        ecc.system_name = report.name;
        report.attacks.push_back(std::move(ecc));

        report.status = evaluate_set_status(report.attacks);
        report.wall_ms = stopwatch.elapsed_ms();
        return report;
    }
}
