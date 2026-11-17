#include "EducationalQuantumAttack.h"

namespace crypto::educational_quantum_attack
{
    namespace
    {
        [[nodiscard]] std::string effective_message(const std::string& plaintext)
        {
            return plaintext.empty() ? std::string(DefaultQuantumAttackMessage) : plaintext;
        }
    }

    SetAttackReport run_aes_sha_ecdsa_quantum_attack(const std::string& plaintext, const QuantumAttackConfig& config)
    {
        return run_aes_sha_ecdsa_quantum_attack(generate_aes_sha_ecdsa_target(effective_message(plaintext)), config);
    }

    SetAttackReport run_aes_sha_rsapss_quantum_attack(const std::string& plaintext, const QuantumAttackConfig& config)
    {
        return run_aes_sha_rsapss_quantum_attack(generate_aes_sha_rsapss_target(effective_message(plaintext)), config);
    }

    SetAttackReport run_sha_aes_mlkem_quantum_attack(const std::string& plaintext, const QuantumAttackConfig& config)
    {
        return run_sha_aes_mlkem_quantum_attack(generate_sha_aes_mlkem_target(effective_message(plaintext)), config);
    }

    std::vector<SetAttackReport> run_all_quantum_attacks(const std::string& plaintext, const QuantumAttackConfig& config)
    {
        // Three independent analyses: no instance, key or result is shared between sets.
        std::vector<SetAttackReport> reports;
        reports.reserve(3U);
        reports.push_back(run_aes_sha_ecdsa_quantum_attack(plaintext, config));
        reports.push_back(run_aes_sha_rsapss_quantum_attack(plaintext, config));
        reports.push_back(run_sha_aes_mlkem_quantum_attack(plaintext, config));
        return reports;
    }
}
