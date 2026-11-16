#include "CryptoSetAnalysis/CryptoSetAnalysis.h"
#include "IntegratedCryptoAnalysis/IntegratedCryptoAnalysis.h"

#include <iostream>

int main()
{
    constexpr const char* message = "CryptoProject separate-set integration test";
    const auto results = crypto::set_analysis::run_all_sets(message, 1024U, false);
    if (results.size() != 3U)
    {
        std::cerr << "Expected exactly three independent crypto sets.\n";
        return 1;
    }
    for (const auto& result : results)
    {
        if (!result.passed || !result.shared_secret_match)
        {
            std::cerr << result.name << " failed: " << result.detail << '\n';
            return 2;
        }
        if (result.quantum.grover_time_at_one_microsecond_seconds <= 0.0L ||
            result.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds <= 0.0L ||
            result.quantum.fastest_quantified_attack_seconds <= 0.0L)
        {
            std::cerr << result.name << " did not produce attack-time scenario estimates.\n";
            return 3;
        }
        if (result.id == crypto::set_analysis::SetId::AesShaEcdsa &&
            (!result.quantum.shor_applies_to_public_key_component ||
             result.quantum.shor_toffoli_gates_estimate <= 0.0L ||
             result.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds <= 0.0L))
        {
            std::cerr << "P-256 Shor attack-time estimate is missing.\n";
            return 4;
        }
        if (result.id == crypto::set_analysis::SetId::AesShaRsaPss &&
            (!result.quantum.shor_applies_to_public_key_component ||
             result.quantum.shor_toffoli_gates_estimate <= 0.0L ||
             result.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds <= 0.0L))
        {
            std::cerr << "RSA Shor attack-time estimate is missing.\n";
            return 5;
        }
        if (result.id == crypto::set_analysis::SetId::ShaAesMlKem &&
            (result.quantum.shor_applies_to_public_key_component ||
             result.quantum.fastest_quantified_attack_is_complete_for_set))
        {
            std::cerr << "ML-KEM must not claim an unmodeled Module-LWE break time.\n";
            return 6;
        }
        if (result.name == "SHA-AES-MLKEM" && result.signature_present)
        {
            std::cerr << "The ML-KEM set must not claim a digital signature.\n";
            return 7;
        }
    }

    const auto individual_report = crypto::set_analysis::format_set_report(results.front());
    const auto comparison_report = crypto::set_analysis::format_comparison_report(results);
    if (individual_report.find("ESTIMATED TIME TO COMPROMISE THIS SET") == std::string::npos ||
        individual_report.find("Measured quantum toy-simulator runtime") == std::string::npos ||
        comparison_report.find("ESTIMATED TIME TO COMPROMISE THIS SET") == std::string::npos)
    {
        std::cerr << "Individual or comparison output is missing the separate estimated break-time field.\n";
        return 10;
    }

    const auto mlkem_report = crypto::set_analysis::format_set_report(results.back());
    if (mlkem_report.find("ESTIMATED TIME TO COMPROMISE THIS SET: NOT ESTIMABLE") == std::string::npos)
    {
        std::cerr << "ML-KEM output must not claim a complete attack time without a Module-LWE model.\n";
        return 11;
    }

    const auto integrated = crypto::integrated_crypto_analysis::run_integrated_analysis(
        message, 1024U, false);
    if (!integrated.all_sets_passed || integrated.sets.size() != 3U ||
        integrated.sum_of_set_operation_ms <= 0.0 || integrated.shor_applicable_sets != 2U)
    {
        std::cerr << "Integrated all-three-set analysis did not aggregate expected metrics.\n";
        return 8;
    }
    if (integrated.report.find("ESTIMATED TIME TO COMPROMISE EACH CRYPTO SET") == std::string::npos ||
        integrated.report.find("ESTIMATED TIME TO COMPROMISE THIS SET") == std::string::npos ||
        integrated.report.find("All-three-sets completion time: NOT ESTIMABLE") == std::string::npos)
    {
        std::cerr << "Integrated report is missing per-set attack-time scenario output.\n";
        return 9;
    }

    std::cout << "[PASS] Three independent sets and integrated batch analysis succeeded.\n";
    return 0;
}
