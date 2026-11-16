#include "CryptoSetAnalysis.h"
#include "Detail/QuantumAttackAnalysis.h"
#include "Detail/AttackTimeModel.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
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
                   "grover_ideal_iterations,grover_time_at_1us_seconds,sha256_preimage_grover_iterations,sha256_preimage_time_at_1us_seconds,grover_toy_sim_ms,"
                   "shor_applies,shor_target,shor_register_qubits,shor_toffoli_gates_estimate,shor_time_at_1us_per_toffoli_seconds,shor_toy_sim_ms,shor_toy_status,"
                   "fastest_quantified_attack,fastest_quantified_attack_seconds,fastest_attack_complete_for_set,attack_time_scope,"
                   "estimated_time_to_compromise_seconds,estimated_time_to_compromise_available,estimated_time_to_compromise_path\n";
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
                << r.quantum.grover_time_at_one_microsecond_seconds << ','
                << r.quantum.sha256_preimage_grover_iterations << ','
                << r.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds << ','
                << std::fixed << r.quantum.grover_toy_simulator_ms << ','
                << (r.quantum.shor_applies_to_public_key_component ? "true" : "false") << ','
                << csv_escape(r.quantum.shor_target) << ',' << r.quantum.shor_register_qubits << ','
                << std::scientific << r.quantum.shor_toffoli_gates_estimate << ','
                << r.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds << ','
                << std::fixed << r.quantum.shor_toy_simulator_ms << ',' << csv_escape(r.quantum.shor_toy_status) << ','
                << csv_escape(r.quantum.fastest_quantified_attack) << ','
                << std::scientific << r.quantum.fastest_quantified_attack_seconds << ','
                << (r.quantum.fastest_quantified_attack_is_complete_for_set ? "true" : "false") << ','
                << csv_escape(r.quantum.attack_time_scope) << ',';
            if (r.quantum.fastest_quantified_attack_is_complete_for_set)
                out << std::scientific << r.quantum.fastest_quantified_attack_seconds << ",true,";
            else
                out << "NOT_ESTIMABLE,false,";
            out << csv_escape(r.quantum.fastest_quantified_attack) << '\n';
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
        using detail::attack_time_model::format_duration;
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
            << "Total measured cryptosystem operation time: " << r.timings.total_ms << " ms\n"
            << "\n[Measured quantum toy-simulator runtime - NOT a real attack]\n"
            << "Grover toy simulator (3-qubit example): " << r.quantum.grover_toy_simulator_ms << " ms\n"
            << "Shor toy simulator (N=15 example): " << r.quantum.shor_toy_simulator_ms << " ms\n"
            << "\n[ESTIMATED TIME TO COMPROMISE - FULL-SIZE PARAMETER SCENARIO]\n"
            << "These are calculated scenario estimates, NOT measured real-world cracking times.\n"
            << "Assumptions: 1 microsecond per ideal Grover oracle iteration; "
            << "1 microsecond per serial logical Toffoli gate.\n"
            << "AES-128 key search with Grover: "
            << format_duration(r.quantum.grover_time_at_one_microsecond_seconds) << '\n'
            << "SHA-256 preimage search with Grover: "
            << format_duration(r.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds) << '\n'
            << "Shor target: " << r.quantum.shor_target << '\n';

        if (r.quantum.shor_applies_to_public_key_component)
        {
            out << "Shor logical-register illustration: " << r.quantum.shor_register_qubits << " qubits\n"
                << std::scientific << std::setprecision(5)
                << "Estimated Shor Toffoli gate count: " << r.quantum.shor_toffoli_gates_estimate << '\n'
                << "Estimated Shor serial-equivalent time: "
                << format_duration(r.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds) << '\n'
                << std::fixed << std::setprecision(3);
        }
        else
        {
            out << "Shor attack time: NOT APPLICABLE to Module-LWE\n"
                << "ML-KEM-768 Module-LWE core attack time: NOT MODELED\n";
        }

        out << "Fastest modeled attack path: " << r.quantum.fastest_quantified_attack << '\n'
            << "Fastest modeled component-attack time: "
            << format_duration(r.quantum.fastest_quantified_attack_seconds) << '\n';
        if (r.quantum.fastest_quantified_attack_is_complete_for_set)
        {
            out << "ESTIMATED TIME TO COMPROMISE THIS SET (modeled path): "
                << format_duration(r.quantum.fastest_quantified_attack_seconds) << '\n'
                << "Compromise path: " << r.quantum.fastest_quantified_attack << '\n';
        }
        else
        {
            out << "ESTIMATED TIME TO COMPROMISE THIS SET: NOT ESTIMABLE\n"
                << "Reason: the ML-KEM-768 Module-LWE core attack cost is not modeled.\n"
                << "The AES Grover value above is only a component estimate, not a full-set break time.\n";
        }
        out << "Scope: " << r.quantum.attack_time_scope << '\n'
            << "\n[Interpretation]\n"
            << r.detail << '\n'
            << "The measured toy-simulator milliseconds above are separate from the estimated attack times. "
            << "The scenario omits error correction, fault tolerance, routing, parallel circuit depth, machine architecture and physical hardware overhead; "
            << "do not interpret it as a real-world prediction.\n";
        return out.str();
    }

    std::string format_comparison_report(const std::vector<SetRunResult>& results)
    {
        using detail::attack_time_model::format_duration;
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

        out << "\n[Attack-time comparison - separate full-parameter scenario estimates]\n"
            << "Scenario assumptions: 1 microsecond / ideal Grover oracle iteration; "
            << "1 microsecond / serial logical Toffoli gate.\n";
        for (const auto& r : results)
        {
            out << "- " << r.name << '\n'
                << "    AES-128 Grover: "
                << format_duration(r.quantum.grover_time_at_one_microsecond_seconds) << '\n'
                << "    SHA-256 preimage Grover: "
                << format_duration(r.quantum.sha256_preimage_grover_time_at_one_microsecond_seconds) << '\n';
            if (r.quantum.shor_applies_to_public_key_component)
            {
                out << "    Shor target: " << r.quantum.shor_target << '\n'
                    << "    Shor Toffoli gate estimate: " << std::scientific
                    << r.quantum.shor_toffoli_gates_estimate << '\n'
                    << "    Shor serial-equivalent attack time: "
                    << format_duration(r.quantum.shor_attack_time_at_one_microsecond_per_toffoli_seconds) << '\n';
            }
            else
            {
                out << "    Shor: not directly applicable to Module-LWE\n"
                    << "    ML-KEM-768 Module-LWE attack time: NOT MODELED\n";
            }
            out << "    Fastest modeled component path: " << r.quantum.fastest_quantified_attack
                << " / " << format_duration(r.quantum.fastest_quantified_attack_seconds) << '\n';
            if (r.quantum.fastest_quantified_attack_is_complete_for_set)
            {
                out << "    >>> ESTIMATED TIME TO COMPROMISE THIS SET: "
                    << format_duration(r.quantum.fastest_quantified_attack_seconds) << " <<<\n";
            }
            else
            {
                out << "    >>> WHOLE-SET COMPROMISE TIME: NOT ESTIMABLE (Module-LWE core not modeled) <<<\n";
            }
        }
        out << "\nCaveat: operation times are measured on the current classical CPU build. "
            << "Attack-time values are scenario calculations from ideal query/gate counts and assumed rates; "
            << "they omit parallel circuit depth, error correction, fault tolerance, routing and physical hardware overhead. "
            << "The tiny Grover/Shor simulator elapsed times are not full-size cryptographic break times.\n";
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
