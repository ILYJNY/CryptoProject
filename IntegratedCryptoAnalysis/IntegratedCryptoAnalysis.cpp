#include "IntegratedCryptoAnalysis.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace crypto::integrated_crypto_analysis
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        [[nodiscard]] long double grover_years(const long double seconds)
        {
            return seconds / (365.25L * 24.0L * 60.0L * 60.0L);
        }

        [[nodiscard]] std::string csv_escape(const std::string& value)
        {
            std::string result = "\"";
            for (const char c : value)
            {
                if (c == '\"') result += "\"\"";
                else result += c;
            }
            result += '\"';
            return result;
        }

        void write_file(const std::string& path, const std::string& content)
        {
            const std::filesystem::path target(path);
            if (target.has_parent_path()) std::filesystem::create_directories(target.parent_path());
            std::ofstream output(target, std::ios::binary | std::ios::trunc);
            if (!output) throw std::runtime_error("Cannot create report file: " + path);
            output << content;
            if (!output) throw std::runtime_error("Failed writing report file: " + path);
        }

        [[nodiscard]] std::string build_report(const IntegratedAnalysisResult& r)
        {
            std::ostringstream out;
            out << "=====================================================================\n"
                << "INTEGRATED CRYPTO ANALYSIS - ALL THREE SETS IN ONE ANALYSIS RUN\n"
                << "=====================================================================\n"
                << "IMPORTANT: this is an analysis of three independent crypto sets. It does NOT combine their keys or algorithms into one hybrid cipher.\n\n"
                << "Sets executed: " << r.sets.size() << '\n'
                << "Overall result: " << (r.all_sets_passed ? "ALL PASS" : "ONE OR MORE SETS FAILED") << '\n'
                << std::fixed << std::setprecision(3)
                << "Orchestration wall time: " << r.orchestration_wall_ms << " ms\n"
                << "Sum of individual crypto-operation times: " << r.sum_of_set_operation_ms << " ms\n"
                << "Peak single-set crypto-operation time: " << r.peak_single_set_operation_ms << " ms\n"
                << "Sum of toy quantum simulator times: " << r.sum_of_toy_quantum_simulation_ms << " ms\n\n"
                << "[Individual set summary]\n"
                << std::left << std::setw(20) << "Set" << std::setw(10) << "Status"
                << std::setw(18) << "Key setup(ms)" << std::setw(18) << "Key share(ms)"
                << std::setw(16) << "AES encrypt(ms)" << "Total(ms)\n"
                << std::string(100U, '-') << '\n';
            for (const auto& set : r.sets)
            {
                out << std::left << std::setw(20) << set.name
                    << std::setw(10) << (set.passed ? "PASS" : "FAIL")
                    << std::setw(18) << set.timings.key_generation_ms
                    << std::setw(18) << set.timings.key_establishment_ms
                    << std::setw(16) << set.timings.aes_encrypt_ms
                    << set.timings.total_ms << '\n';
            }

            out << "\n[Combined quantum resource ledger]\n"
                << "Grover target: the AES-128 key in each independent set\n"
                << std::scientific << std::setprecision(6)
                << "Grover iterations per AES-128 key (ideal query model): "
                << (r.sets.empty() ? 0.0L : r.sets.front().quantum.grover_ideal_iterations) << '\n'
                << "Grover iterations summed across three independent AES keys: "
                << r.total_grover_iterations_for_three_aes_keys << '\n'
                << std::fixed << std::setprecision(2)
                << "Illustrative sequential time at 1 microsecond per logical iteration: "
                << grover_years(r.illustrative_grover_seconds_at_one_microsecond) << " years\n"
                << "This 1-microsecond iteration duration is an explicit assumption, not a hardware measurement.\n"
                << "SHA-256 preimage Grover iterations summed across three independent 256-bit hashes: "
                << r.total_sha256_preimage_grover_iterations << '\n'
                << "Illustrative sequential SHA-256 preimage search time at 1 microsecond per iteration: "
                << grover_years(r.illustrative_sha256_grover_seconds_at_one_microsecond) << " years\n\n"
                << "Shor applicability: " << r.shor_applicable_sets << " of 3 sets\n"
                << "Sum of the two separate Shor register illustrations: " << r.sum_of_shor_register_qubits << " qubits\n"
                << "Peak single Shor register illustration (if hardware is reused sequentially): "
                << r.peak_shor_register_qubits << " qubits\n";

            for (const auto& set : r.sets)
            {
                out << "- " << set.name << ": " << set.quantum.shor_target
                    << "; Shor register illustration=" << set.quantum.shor_register_qubits << " qubits"
                    << "; toy Shor status=" << set.quantum.shor_toy_status << '\n';
            }

            out << "\n[Interpretation and limitations]\n"
                << "1. AES-128 is the symmetric layer in all three sets; Grover's generic search model gives approximately sqrt(2^128) oracle iterations.\n"
                << "2. Shor applies in principle to P-256 discrete logarithms and RSA factorization. The qubit figures here are coarse register-size illustrations only.\n"
                << "3. Shor is not a direct algorithmic break of ML-KEM's Module-LWE problem. The project does not fabricate an ML-KEM Shor/Grover resource estimate.\n"
                << "4. Toy Grover and Shor simulator times are classical state-vector simulation times on tiny examples, not elapsed time to break real AES, RSA, ECC or ML-KEM.\n"
                << "5. The measured cryptographic operation times are measurements of this educational implementation on the current CPU build, not standardized performance claims.\n";
            return out.str();
        }
    }

    IntegratedAnalysisResult run_integrated_analysis(
        const std::string_view plaintext, const std::size_t rsa_modulus_bits,
        const bool run_quantum_toy_simulations)
    {
        IntegratedAnalysisResult result;
        const auto start = Clock::now();
        result.sets = set_analysis::run_all_sets(plaintext, rsa_modulus_bits, run_quantum_toy_simulations);
        for (const auto& set : result.sets)
        {
            result.sum_of_set_operation_ms += set.timings.total_ms;
            if (set.timings.total_ms > result.peak_single_set_operation_ms)
                result.peak_single_set_operation_ms = set.timings.total_ms;
            result.sum_of_toy_quantum_simulation_ms +=
                set.quantum.grover_toy_simulator_ms + set.quantum.shor_toy_simulator_ms;
            result.total_grover_iterations_for_three_aes_keys += set.quantum.grover_ideal_iterations;
            result.illustrative_grover_seconds_at_one_microsecond +=
                set.quantum.grover_time_at_one_microsecond_seconds;
            result.total_sha256_preimage_grover_iterations +=
                set.quantum.sha256_preimage_grover_iterations;
            result.illustrative_sha256_grover_seconds_at_one_microsecond +=
                set.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds;
            if (set.quantum.shor_applies_to_public_key_component)
            {
                ++result.shor_applicable_sets;
                result.sum_of_shor_register_qubits += set.quantum.shor_register_qubits;
                if (set.quantum.shor_register_qubits > result.peak_shor_register_qubits)
                    result.peak_shor_register_qubits = set.quantum.shor_register_qubits;
            }
        }
        result.all_sets_passed = !result.sets.empty();
        for (const auto& set : result.sets) result.all_sets_passed = result.all_sets_passed && set.passed;
        result.orchestration_wall_ms =
            std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        result.report = build_report(result);
        return result;
    }

    bool export_integrated_analysis(const IntegratedAnalysisResult& result,
                                    const std::string& directory,
                                    std::string& report_path, std::string& csv_path)
    {
        try
        {
            std::filesystem::create_directories(directory);
            report_path = (std::filesystem::path(directory) / "integrated_all_sets_report.txt").string();
            csv_path = (std::filesystem::path(directory) / "integrated_all_sets_summary.csv").string();
            write_file(report_path, result.report);

            std::ostringstream csv;
            csv << "metric,value,unit\n"
                << "all_sets_passed," << (result.all_sets_passed ? "true" : "false") << ",boolean\n"
                << std::setprecision(12)
                << "orchestration_wall_time," << result.orchestration_wall_ms << ",ms\n"
                << "sum_of_crypto_operation_times," << result.sum_of_set_operation_ms << ",ms\n"
                << "peak_single_set_crypto_time," << result.peak_single_set_operation_ms << ",ms\n"
                << "sum_of_toy_quantum_simulation_times," << result.sum_of_toy_quantum_simulation_ms << ",ms\n"
                << "sum_of_grover_iterations_three_aes_keys," << std::scientific
                << result.total_grover_iterations_for_three_aes_keys << ",iterations\n"
                << "illustrative_grover_time_at_1us," << result.illustrative_grover_seconds_at_one_microsecond << ",seconds\n"
                << "sum_of_sha256_preimage_grover_iterations," << std::scientific
                << result.total_sha256_preimage_grover_iterations << ",iterations\n"
                << "illustrative_sha256_preimage_time_at_1us,"
                << result.illustrative_sha256_grover_seconds_at_one_microsecond << ",seconds\n"
                << "sum_of_shor_register_qubits," << result.sum_of_shor_register_qubits << ",logical_register_qubits\n"
                << "peak_shor_register_qubits," << result.peak_shor_register_qubits << ",logical_register_qubits\n"
                << "shor_applicable_sets," << result.shor_applicable_sets << ",sets\n";
            for (const auto& set : result.sets)
            {
                csv << csv_escape(set.name) << "_total_ms," << set.timings.total_ms << ",ms\n"
                    << csv_escape(set.name) << "_shor_register_qubits," << set.quantum.shor_register_qubits << ",logical_register_qubits\n";
            }
            write_file(csv_path, csv.str());
            return true;
        }
        catch (...) { return false; }
    }
}
