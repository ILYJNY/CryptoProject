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
        if (result.name == "SHA-AES-MLKEM" && result.signature_present)
        {
            std::cerr << "The ML-KEM set must not claim a digital signature.\n";
            return 3;
        }
    }

    const auto integrated = crypto::integrated_crypto_analysis::run_integrated_analysis(
        message, 1024U, false);
    if (!integrated.all_sets_passed || integrated.sets.size() != 3U ||
        integrated.sum_of_set_operation_ms <= 0.0 || integrated.shor_applicable_sets != 2U)
    {
        std::cerr << "Integrated all-three-set analysis did not aggregate expected metrics.\n";
        return 4;
    }

    std::cout << "[PASS] Three independent sets and integrated batch analysis succeeded.\n";
    return 0;
}
