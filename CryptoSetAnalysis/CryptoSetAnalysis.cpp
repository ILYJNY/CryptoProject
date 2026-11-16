#include "CryptoSetAnalysis.h"
#include "Detail/QuantumAttackAnalysis.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace crypto::set_analysis
{
    namespace
    {
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

        [[nodiscard]] long double grover_years(const long double seconds)
        {
            return seconds / (365.25L * 24.0L * 60.0L * 60.0L);
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

        std::string csv_header()
        {
            return "set,passed,key_establishment,authentication,key_generation_ms,key_establishment_ms,sha256_ms,hkdf_ms,"
                   "aes_encrypt_ms,signature_ms,signature_verify_ms,aes_decrypt_ms,total_ms,ciphertext_bytes,"
                   "grover_ideal_iterations,grover_time_at_1us_years,sha256_preimage_grover_iterations,sha256_preimage_time_at_1us_years,grover_toy_sim_ms,shor_applies,shor_target,"
                   "shor_register_qubits,shor_toy_sim_ms,shor_toy_status\n";
        }

        std::string csv_row(const SetRunResult& r)
        {
            std::ostringstream out;
            out << csv_escape(r.name) << ',' << (r.passed ? "true" : "false") << ','
                << csv_escape(r.key_establishment) << ',' << csv_escape(r.authentication) << ','
                << std::setprecision(12) << r.timings.key_generation_ms << ','
                << r.timings.key_establishment_ms << ',' << r.timings.sha256_ms << ',' << r.timings.hkdf_ms << ','
                << r.timings.aes_encrypt_ms << ',' << r.timings.signature_ms << ','
                << r.timings.signature_verify_ms << ',' << r.timings.aes_decrypt_ms << ','
                << r.timings.total_ms << ',' << r.ciphertext_bytes << ','
                << std::scientific << r.quantum.grover_ideal_iterations << ','
                << grover_years(r.quantum.grover_time_at_one_microsecond_seconds) << ','
                << r.quantum.sha256_preimage_grover_iterations << ','
                << grover_years(r.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds) << ','
                << std::fixed << r.quantum.grover_toy_simulator_ms << ','
                << (r.quantum.shor_applies_to_public_key_component ? "true" : "false") << ','
                << csv_escape(r.quantum.shor_target) << ',' << r.quantum.shor_register_qubits << ','
                << r.quantum.shor_toy_simulator_ms << ',' << csv_escape(r.quantum.shor_toy_status) << '\n';
            return out.str();
        }
    }

    std::string set_name(const SetId id)
    {
        switch (id)
        {
        case SetId::AesShaEcdsa: return "AES-SHA-ECDSA";
        case SetId::AesShaRsaPss: return "AES-SHA-RSAPSS";
        case SetId::ShaAesMlKem: return "SHA-AES-MLKEM";
        }
        return "UNKNOWN";
    }

    std::vector<SetRunResult> run_all_sets(
        const std::string_view plaintext, const std::size_t rsa_modulus_bits, const bool run_quantum_demo)
    {
        std::vector<SetRunResult> results;
        results.reserve(3U);
        results.push_back(run_aes_sha_ecdsa(plaintext, run_quantum_demo));
        results.push_back(run_aes_sha_rsa_pss(plaintext, rsa_modulus_bits, run_quantum_demo));
        results.push_back(run_sha_aes_mlkem(plaintext, run_quantum_demo));
        return results;
    }

    std::string format_set_report(const SetRunResult& r)
    {
        std::ostringstream out;
        out << "============================================================\n"
            << "Crypto Set: " << r.name << "\n"
            << "============================================================\n"
            << "Result: " << (r.passed ? "PASS" : "FAIL") << '\n'
            << "Key establishment: " << r.key_establishment << '\n'
            << "Authentication: " << r.authentication << '\n'
            << "Shared secret matched: " << (r.shared_secret_match ? "YES" : "NO") << '\n'
            << "Digital signature present: " << (r.signature_present ? "YES" : "NO") << '\n';
        if (r.signature_present) out << "Digital signature verified: " << (r.signature_verified ? "YES" : "NO") << '\n';
        out << "AES ciphertext bytes: " << r.ciphertext_bytes << '\n'
            << "SHA-256: " << r.plaintext_sha256 << '\n'
            << "\n[Measured cryptosystem operation times]\n"
            << std::fixed << std::setprecision(3)
            << "Key generation: " << r.timings.key_generation_ms << " ms\n"
            << "Key establishment / encapsulation: " << r.timings.key_establishment_ms << " ms\n"
            << "SHA-256: " << r.timings.sha256_ms << " ms\n"
            << "HKDF-SHA-256: " << r.timings.hkdf_ms << " ms\n"
            << "AES-128-GCM encryption: " << r.timings.aes_encrypt_ms << " ms\n"
            << "Signature generation: " << r.timings.signature_ms << " ms\n"
            << "Signature verification: " << r.timings.signature_verify_ms << " ms\n"
            << "AES-128-GCM decryption: " << r.timings.aes_decrypt_ms << " ms\n"
            << "Total measured time: " << r.timings.total_ms << " ms\n"
            << "\n[Quantum attack analysis]\n"
            << "Grover target: AES-128 symmetric key search\n"
            << "Search-register qubits (lower-bound only): " << r.quantum.grover_search_qubits << '\n'
            << std::scientific << std::setprecision(5)
            << "Ideal Grover iterations: " << r.quantum.grover_ideal_iterations << '\n'
            << "Illustrative time at 1 microsecond per logical iteration: "
            << grover_years(r.quantum.grover_time_at_one_microsecond_seconds) << " years\n"
            << "Grover target: full SHA-256 preimage search model (256-bit digest)\n"
            << std::scientific << std::setprecision(5)
            << "Ideal SHA-256 preimage Grover iterations: "
            << r.quantum.sha256_preimage_grover_iterations << '\n'
            << "Illustrative SHA-256 preimage time at 1 microsecond per iteration: "
            << grover_years(r.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds) << " years\n"
            << std::fixed << std::setprecision(3)
            << "3-qubit Grover toy simulator elapsed: " << r.quantum.grover_toy_simulator_ms << " ms\n"
            << "Shor target: " << r.quantum.shor_target << '\n';
        if (r.quantum.shor_applies_to_public_key_component)
        {
            out << "Illustrative Shor register qubits: " << r.quantum.shor_register_qubits << '\n'
                << "N=15 toy Shor simulator elapsed: " << r.quantum.shor_toy_simulator_ms << " ms\n"
                << "N=15 toy status: " << r.quantum.shor_toy_status << '\n';
        }
        else
        {
            out << "Shor register qubits: N/A\n"
                << "Shor toy simulator: not run for ML-KEM\n";
        }
        out << "Qualification: " << r.quantum.qualification << '\n'
            << "\n[Interpretation]\n"
            << r.detail << '\n'
            << "All quantum times above are either measured tiny toy-simulator times or explicitly assumed query-time illustrations. "
            << "They are not full-size cryptographic break times on quantum hardware.\n";
        return out.str();
    }

    std::string format_comparison_report(const std::vector<SetRunResult>& results)
    {
        std::ostringstream out;
        out << "============================================================\n"
            << "CRYPTO SETS - SEPARATE COMPARISON\n"
            << "============================================================\n"
            << "Each row is a separate construction; they are not combined into one hybrid cipher.\n\n"
            << std::left << std::setw(19) << "Set"
            << std::setw(9) << "Result"
            << std::setw(16) << "Key setup(ms)"
            << std::setw(17) << "Key share(ms)"
            << std::setw(14) << "AES(ms)"
            << std::setw(14) << "Sign(ms)"
            << std::setw(14) << "Verify(ms)"
            << "Total(ms)\n";
        out << std::string(112U, '-') << '\n';
        for (const auto& r : results)
        {
            out << std::left << std::setw(19) << r.name
                << std::setw(9) << (r.passed ? "PASS" : "FAIL")
                << std::setw(16) << std::fixed << std::setprecision(3) << r.timings.key_generation_ms
                << std::setw(17) << r.timings.key_establishment_ms
                << std::setw(14) << r.timings.aes_encrypt_ms
                << std::setw(14) << r.timings.signature_ms
                << std::setw(14) << r.timings.signature_verify_ms
                << r.timings.total_ms << '\n';
        }
        out << "\n[Quantum comparison]\n";
        for (const auto& r : results)
        {
            out << "- " << r.name << ": Grover(AES-128)=" << std::scientific
                << r.quantum.grover_ideal_iterations << " ideal iterations; Grover(SHA-256 preimage)="
                << r.quantum.sha256_preimage_grover_iterations << " ideal iterations; Shor="
                << (r.quantum.shor_applies_to_public_key_component ? r.quantum.shor_target : "not directly applicable")
                << "; Shor register illustration=" << r.quantum.shor_register_qubits << " qubits.\n";
        }
        out << "\nCaveat: operation times are measured on the current classical CPU build. "
            << "Shor/Grover resource counts are simplified theoretical illustrations, not measured hardware attacks.\n";
        return out.str();
    }

    bool export_set_report(const SetRunResult& result, const std::string& directory,
                           std::string& report_path, std::string& csv_path)
    {
        try
        {
            std::filesystem::create_directories(directory);
            report_path = (std::filesystem::path(directory) / (result.name + "_report.txt")).string();
            csv_path = (std::filesystem::path(directory) / (result.name + "_metrics.csv")).string();
            write_file(report_path, format_set_report(result));
            write_file(csv_path, csv_header() + csv_row(result));
            return true;
        }
        catch (...) { return false; }
    }

    bool export_comparison_report(const std::vector<SetRunResult>& results,
                                  const std::string& directory,
                                  std::string& report_path, std::string& csv_path)
    {
        try
        {
            std::filesystem::create_directories(directory);
            report_path = (std::filesystem::path(directory) / "separate_sets_comparison.txt").string();
            csv_path = (std::filesystem::path(directory) / "separate_sets_comparison.csv").string();
            write_file(report_path, format_comparison_report(results));
            std::string csv = csv_header();
            for (const auto& result : results) csv += csv_row(result);
            write_file(csv_path, csv);
            return true;
        }
        catch (...) { return false; }
    }
}
