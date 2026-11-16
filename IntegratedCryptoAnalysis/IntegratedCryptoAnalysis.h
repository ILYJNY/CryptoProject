#pragma once

#include "CryptoSetAnalysis/CryptoSetAnalysis.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::integrated_crypto_analysis
{
    struct IntegratedAnalysisResult
    {
        bool all_sets_passed = false;
        std::vector<set_analysis::SetRunResult> sets;
        double orchestration_wall_ms = 0.0;
        double sum_of_set_operation_ms = 0.0;
        double peak_single_set_operation_ms = 0.0;
        double sum_of_toy_quantum_simulation_ms = 0.0;
        long double total_grover_iterations_for_three_aes_keys = 0.0L;
        long double illustrative_grover_seconds_at_one_microsecond = 0.0L;
        long double total_sha256_preimage_grover_iterations = 0.0L;
        long double illustrative_sha256_grover_seconds_at_one_microsecond = 0.0L;
        std::size_t sum_of_shor_register_qubits = 0U;
        std::size_t peak_shor_register_qubits = 0U;
        std::size_t shor_applicable_sets = 0U;
        std::string report;
    };

    [[nodiscard]] IntegratedAnalysisResult run_integrated_analysis(
        std::string_view plaintext, std::size_t rsa_modulus_bits = 4096U,
        bool run_quantum_toy_simulations = true);
    [[nodiscard]] bool export_integrated_analysis(
        const IntegratedAnalysisResult& result, const std::string& directory,
        std::string& report_path, std::string& csv_path);
}
