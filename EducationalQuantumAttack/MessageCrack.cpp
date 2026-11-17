#include "MessageCrack.h"

#include "EducationalQuantumAttack/Attacks/AttackCommon.h"
#include "EducationalQuantumAttack/Attacks/ToyAesGroverAttack.h"
#include "EducationalQuantumAttack/Common/QuantumAttackReport.h"
#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/EducationalParameters.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        constexpr const char* kDoubleRule =
            "================================================================================";

        struct SetSpec
        {
            const char* name;
            const char* tag;    // separates the per-set measurement seeds
        };

        // The three independent educational composite sets. Each encrypts the entered
        // sentence with its own Toy AES record (a fresh key), so the crack is run three
        // times on three independent instances.
        constexpr SetSpec kSets[] = {
            {"Educational AES-SHA-ECDSA analogue", "crack/A"},
            {"Educational AES-SHA-RSAPSS analogue", "crack/B"},
            {"Educational SHA-AES-MLKEM analogue", "crack/C"},
        };

        [[nodiscard]] std::string crack_ms_text(const Metric& metric)
        {
            if (!metric.has_value()) return std::string(metric_kind_label(metric.kind));
            std::ostringstream out;
            out << std::fixed << std::setprecision(3) << metric.value << " ms";
            return out.str();
        }

        [[nodiscard]] std::string estimate_text(const Metric& metric)
        {
            if (!metric.has_value()) return std::string(metric_kind_label(metric.kind));
            return format_seconds(metric.value);
        }
    }

    MessageCrackReport run_message_crack_timing(
        const std::string& plaintext, const QuantumAttackConfig& config)
    {
        MessageCrackReport report;
        report.plaintext = plaintext;
        report.plaintext_empty = plaintext.empty();
        if (report.plaintext_empty)
        {
            report.report = "No sentence was entered. Nothing was encrypted or cracked.\n";
            return report;
        }

        const std::uint64_t root_seed = resolve_seed(config.seed);

        for (const SetSpec& spec : kSets)
        {
            report_progress(config, std::string(spec.name) + ": encrypting the sentence and cracking it");

            // 1. Encrypt the entered sentence with this set's Toy AES record.
            const educational::ToyAesSample sample =
                educational::generate_toy_aes_sample(educational::ToySetAesUnknownKeyBits, plaintext);

            // 2-4. Crack it. The Grover attack also runs and measures the classical
            // restricted-key-space search (time C) on the very same ciphertext, so one call
            // yields the classical crack time, the quantum simulator runtime and the estimate.
            ToyAesGroverAttack attack = attack_toy_aes_with_grover(
                sample.public_instance, config, derive_seed(root_seed, spec.tag));

            MessageCrackSetResult result;
            result.set_name = spec.name;
            result.unknown_key_bits = sample.public_instance.unknown_bits;
            result.key_space = std::size_t{1} << sample.public_instance.unknown_bits;
            result.ciphertext_bytes = sample.public_instance.ciphertext.ciphertext.size();

            result.classical_crack_ms = attack.report.time.classical_attack_runtime_ms;
            result.classical_keys_tried = attack.report.time.classical_attack_work;
            // Recover the classical crack's own result on the same ciphertext so the reported
            // decrypted sentence and match flag belong to the classical crack specifically.
            const educational::ToyAesAnalysis classical =
                educational::analyze_toy_aes(sample.public_instance);
            result.classical_recovered = classical.success;
            if (classical.success)
            {
                try
                {
                    const auto bytes = standard::AES128GCM::decrypt(
                        classical.recovered_key, sample.public_instance.ciphertext,
                        sample.public_instance.associated_data);
                    result.classical_decrypted.assign(bytes.begin(), bytes.end());
                    result.classical_plaintext_matches = result.classical_decrypted == plaintext;
                }
                catch (const std::exception&)
                {
                    result.classical_plaintext_matches = false;
                }
            }

            result.quantum_executed = attack.report.simulator_executed;
            result.quantum_recovered = attack.key_recovered;
            result.quantum_simulator_ms = attack.report.time.simulator_runtime_ms;
            result.quantum_estimated_seconds = attack.report.time.estimated_quantum_attack_seconds;
            result.grover_iterations = attack.report.simulated.oracle_calls;
            result.simulated_qubits = attack.report.simulated.total_qubits;
            result.attack = std::move(attack.report);

            report.sets.push_back(std::move(result));
        }

        report.report = format_message_crack_report(report);
        return report;
    }

    std::string format_message_crack_report(const MessageCrackReport& report)
    {
        if (report.plaintext_empty)
            return "No sentence was entered. Nothing was encrypted or cracked.\n";

        std::ostringstream out;
        out << kDoubleRule << '\n'
            << "MESSAGE ENCRYPTION AND CRACK-TIME MEASUREMENT (toy parameters, analysis only)\n"
            << kDoubleRule << '\n'
            << "Input sentence : " << printable(report.plaintext, 200U) << '\n'
            << "Sentence bytes : " << report.plaintext.size() << '\n'
            << "Each independent toy set encrypts this sentence with Toy AES-128-GCM using a\n"
            << "restricted " << educational::ToySetAesUnknownKeyBits
            << "-bit key space, then recovers the key and decrypts the sentence.\n"
            << "These are deliberately tiny educational parameters. A crack time below applies only\n"
            << "to this " << educational::ToySetAesUnknownKeyBits
            << "-bit toy, never to AES-128. Three crack times are kept apart and never added:\n"
            << "  - classical crack runtime: the existing key-space search, measured on this CPU;\n"
            << "  - quantum Grover crack: the state-vector SIMULATION runtime (a classical computer\n"
            << "    simulating the circuit), which is NOT the time a quantum computer would take;\n"
            << "  - estimated quantum attack time: a scenario estimate on hypothetical hardware.\n\n";

        for (const MessageCrackSetResult& set : report.sets)
        {
            out << "--- " << set.set_name << " ---\n"
                << "Encryption: AES-128-GCM, " << set.unknown_key_bits << " unknown key bits (key space "
                << set.key_space << "), " << set.ciphertext_bytes << " ciphertext bytes\n"
                << "Classical crack (measured on this CPU):\n"
                << "    key recovered            : " << (set.classical_recovered ? "YES" : "NO") << '\n'
                << "    decrypted sentence match : "
                << (set.classical_plaintext_matches ? "YES" : "NO");
            if (set.classical_plaintext_matches)
                out << " (\"" << printable(set.classical_decrypted, 120U) << "\")";
            out << '\n'
                << "    CRACK TIME               : " << crack_ms_text(set.classical_crack_ms) << '\n'
                << "    keys tried               : " << format_metric(set.classical_keys_tried)
                << " of up to " << set.key_space << '\n'
                << "Quantum Grover crack (simulated on the state-vector simulator):\n"
                << "    key recovered            : " << (set.quantum_recovered ? "YES" : "NO") << '\n'
                << "    Grover iterations        : " << format_metric(set.grover_iterations) << '\n'
                << "    simulated qubits         : " << format_metric(set.simulated_qubits) << '\n'
                << "    simulator runtime (A)    : " << crack_ms_text(set.quantum_simulator_ms)
                << "  [classical simulation of the circuit; not quantum time]\n"
                << "    estimated quantum time(B): " << estimate_text(set.quantum_estimated_seconds)
                << "  [scenario estimate, not a measurement]\n\n";
        }

        out << "Summary (all times measured on this CPU unless marked as an estimate):\n"
            << std::left << std::setw(38) << "Set" << std::setw(22) << "Classical crack"
            << std::setw(22) << "Grover simulator (A)" << "Est. quantum time (B)\n";
        for (const MessageCrackSetResult& set : report.sets)
        {
            out << std::left << std::setw(38) << set.set_name
                << std::setw(22) << crack_ms_text(set.classical_crack_ms)
                << std::setw(22) << crack_ms_text(set.quantum_simulator_ms)
                << estimate_text(set.quantum_estimated_seconds) << '\n';
        }
        out << "\nThe classical crack time and the Grover simulator runtime are different measurements,\n"
               "and the estimated quantum attack time is neither of them. See the Educational Quantum\n"
               "Attack report for the full circuit resources behind these numbers.\n";
        return out.str();
    }

    bool export_message_crack_report(
        const MessageCrackReport& report, const std::string& directory,
        std::string& report_path, std::string& csv_path)
    {
        try
        {
            std::filesystem::create_directories(directory);
            const auto abs = [](const std::string& path)
            {
                try { return std::filesystem::weakly_canonical(std::filesystem::absolute(path)).string(); }
                catch (const std::exception&) { return path; }
            };
            report_path = abs(directory + "/message_crack_report.txt");
            csv_path = abs(directory + "/message_crack_metrics.csv");
            {
                std::ofstream text(report_path, std::ios::out | std::ios::trunc);
                if (!text) return false;
                text << report.report;
                if (!text) return false;
            }
            {
                std::ofstream csv(csv_path, std::ios::out | std::ios::trunc);
                if (!csv) return false;
                csv << "set,unknown_key_bits,key_space,ciphertext_bytes,"
                       "classical_recovered,classical_plaintext_matches,"
                       "classical_crack_ms,classical_crack_ms_kind,"
                       "classical_keys_tried,classical_keys_tried_kind,"
                       "quantum_recovered,grover_iterations,grover_iterations_kind,"
                       "simulated_qubits,simulated_qubits_kind,"
                       "quantum_simulator_ms,quantum_simulator_ms_kind,"
                       "estimated_quantum_attack_seconds,estimated_quantum_attack_seconds_kind\n";
                const auto cells = [&csv](const Metric& metric)
                {
                    csv << ',' << csv_field(metric_cell(metric)) << ','
                        << csv_field(std::string(metric_kind_label(metric.kind)));
                };
                for (const MessageCrackSetResult& set : report.sets)
                {
                    csv << csv_field(set.set_name) << ',' << set.unknown_key_bits << ',' << set.key_space
                        << ',' << set.ciphertext_bytes << ','
                        << (set.classical_recovered ? "YES" : "NO") << ','
                        << (set.classical_plaintext_matches ? "YES" : "NO");
                    cells(set.classical_crack_ms);
                    cells(set.classical_keys_tried);
                    csv << ',' << (set.quantum_recovered ? "YES" : "NO");
                    cells(set.grover_iterations);
                    cells(set.simulated_qubits);
                    cells(set.quantum_simulator_ms);
                    cells(set.quantum_estimated_seconds);
                    csv << '\n';
                }
                if (!csv) return false;
            }
            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
}
