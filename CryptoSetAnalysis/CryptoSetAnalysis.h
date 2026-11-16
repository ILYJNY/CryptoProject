#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::set_analysis
{
    enum class SetId
    {
        AesShaEcdsa,
        AesShaRsaPss,
        ShaAesMlKem
    };

    struct OperationTimings
    {
        double key_generation_ms = 0.0;
        double key_establishment_ms = 0.0;
        double sha256_ms = 0.0;
        double hkdf_ms = 0.0;
        double aes_encrypt_ms = 0.0;
        double signature_ms = 0.0;
        double signature_verify_ms = 0.0;
        double aes_decrypt_ms = 0.0;
        double total_ms = 0.0;
    };

    struct QuantumAttackSummary
    {
        bool grover_applies_to_aes = true;
        std::size_t grover_search_qubits = 128U;
        long double grover_ideal_iterations = 0.0L;
        long double grover_time_at_one_microsecond_seconds = 0.0L;
        std::size_t sha256_preimage_search_qubits = 256U;
        long double sha256_preimage_grover_iterations = 0.0L;
        long double sha256_preimage_grover_time_at_one_microsecond_seconds = 0.0L;
        double grover_toy_simulator_ms = 0.0;
        bool shor_applies_to_public_key_component = false;
        std::string shor_target = "Not applicable";
        std::size_t shor_register_qubits = 0U;
        double shor_toy_simulator_ms = 0.0;
        bool shor_toy_demo_passed = false;
        std::string shor_toy_status = "NOT_RUN";

        // Separate full-parameter attack-time scenario estimates. These are not
        // the wall-clock time of the tiny classical simulator demonstrations.
        long double shor_toffoli_gates_estimate = 0.0L;
        long double shor_attack_time_at_one_microsecond_per_toffoli_seconds = 0.0L;
        std::string fastest_quantified_attack = "Not estimated";
        long double fastest_quantified_attack_seconds = 0.0L;
        bool fastest_quantified_attack_is_complete_for_set = false;
        std::string attack_time_scope;
        std::string qualification;
    };

    struct SetRunResult
    {
        SetId id = SetId::AesShaEcdsa;
        std::string name;
        std::string key_establishment;
        std::string authentication;
        bool passed = false;
        bool shared_secret_match = false;
        bool signature_present = false;
        bool signature_verified = false;
        std::size_t ciphertext_bytes = 0U;
        std::size_t public_key_parameter_bits = 0U;
        std::size_t shared_secret_bytes = 32U;
        std::string plaintext_sha256;
        std::string detail;
        OperationTimings timings;
        QuantumAttackSummary quantum;
    };

    [[nodiscard]] SetRunResult run_aes_sha_ecdsa(std::string_view plaintext, bool run_quantum_demo = true);
    [[nodiscard]] SetRunResult run_aes_sha_rsa_pss(
        std::string_view plaintext, std::size_t rsa_modulus_bits = 4096U, bool run_quantum_demo = true);
    [[nodiscard]] SetRunResult run_sha_aes_mlkem(std::string_view plaintext, bool run_quantum_demo = true);

    [[nodiscard]] std::vector<SetRunResult> run_all_sets(
        std::string_view plaintext, std::size_t rsa_modulus_bits = 4096U, bool run_quantum_demo = true);

    [[nodiscard]] std::string set_name(SetId id);
    [[nodiscard]] std::string format_set_report(const SetRunResult& result);
    [[nodiscard]] std::string format_comparison_report(const std::vector<SetRunResult>& results);
    [[nodiscard]] bool export_set_report(const SetRunResult& result, const std::string& directory,
                                         std::string& report_path, std::string& csv_path);
    [[nodiscard]] bool export_comparison_report(const std::vector<SetRunResult>& results,
                                                const std::string& directory,
                                                std::string& report_path, std::string& csv_path);
}
