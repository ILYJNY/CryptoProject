#include "ShaAesMlKemQuantumAttack.h"

#include "SetCommon.h"
#include "EducationalQuantumAttack/Attacks/ToyPublicKeyAnalysis.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"

namespace crypto::educational_quantum_attack
{
    ShaAesMlKemTarget generate_sha_aes_mlkem_target(const std::string& plaintext)
    {
        ShaAesMlKemTarget target;
        target.plaintext = plaintext;
        target.aes = educational::generate_toy_aes_sample(educational::ToySetAesUnknownKeyBits, plaintext);
        target.lwe = educational::generate_toy_lwe_sample();
        return target;
    }

    SetAttackReport run_sha_aes_mlkem_quantum_attack(
        const ShaAesMlKemTarget& target, const QuantumAttackConfig& config)
    {
        const Stopwatch stopwatch;
        SetAttackReport report;
        report.id = SetId::ShaAesMlKem;
        report.name = "Educational SHA-AES-MLKEM analogue";
        report.composition =
            "Toy SHA (real SHA-256, truncated digest) + Toy AES (real AES-128-GCM, restricted key space) + "
            "toy Module-LWE";
        report.disclaimer =
            "An educational analogue with deliberately tiny parameters. The Module-LWE component is not "
            "ML-KEM-768, the AES key space is not that of AES-128, and the digest is not full SHA-256.";

        const std::uint64_t root_seed = resolve_seed(config.seed);
        const SymmetricAndHashOutcome common = run_symmetric_and_hash_attacks(
            "C", report.name, target.plaintext, target.aes, target.toy_sha_output_bits,
            config, root_seed, report.attacks);

        describe_message(
            report.instance, target.plaintext, common.message_digest, target.toy_sha_output_bits, target.aes);
        report.instance.emplace_back(
            "Toy Module-LWE public instance",
            "matrix A (2x2 polynomials) and vector b over Z_257[x]/(x^4 + 1)");
        report.instance.emplace_back(
            "Toy SHA binding in this set",
            "the message digest and the Module-LWE secret coefficients feed the toy key-derivation hash");
        if (common.preimage_found)
        {
            report.instance.emplace_back(
                "Effect of the Toy SHA preimage on the binding",
                "the toy key derivation also hashes the message text itself, so a different message with the "
                "same digest does not by itself reproduce the derived value");
        }

        report_progress(config, report.name + ": Toy Module-LWE - NOT MODELED");
        AttackResult lwe = analyze_toy_module_lwe_not_modeled(target.lwe.public_instance, config);
        lwe.system_name = report.name;
        report.attacks.push_back(std::move(lwe));

        report.status = evaluate_set_status(report.attacks);
        report.wall_ms = stopwatch.elapsed_ms();
        return report;
    }
}
