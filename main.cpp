#include "CryptoAnalyzer/Standard/StandardAnalyzer.h"
#include "CryptoAnalyzer/Educational/EducationalAnalyzer.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"
#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "CryptoSystem/Standard/ModuleLWE/MLKEM768.h"
#include "CryptoSystem/Standard/StandardCrypto.h"
#include "CryptoSetAnalysis/CryptoSetAnalysis.h"
#include "IntegratedCryptoAnalysis/IntegratedCryptoAnalysis.h"
#include "EducationalCryptoSetAnalysis/EducationalCryptoSetAnalysis.h"
#include "IntegratedEducationalCryptoAnalysis/IntegratedEducationalCryptoAnalysis.h"
#include "EducationalQuantumAttack/EducationalQuantumAttack.h"
#include "IntegratedEducationalQuantumAttack/IntegratedEducationalQuantumAttack.h"
#include "IntegratedEducationalQuantumAttack/QuantumAttackExport.h"
#include "IntegratedMode/IntegratedRunner.h"
#include "Benchmark/BenchmarkRunner.h"
#include "ComputeEngine/ComputeEngine.h"
#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"
#include "QuantumAttack/Educational/Experiments/EducationalExperiments.h"
#include "QuantumAttack/Educational/Visualization/QuantumVisualizer.h"
#include "QuantumAttack/Reports/QuantumReport.h"
#include "QuantumAttack/Benchmark/AlgorithmBenchmark.h"
#include "ErrorHandling/CryptoException.h"
#include "Logger/Logger.h"
#include "PerformanceMonitor/PerformanceMonitor.h"

#include <exception>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace
{
    int read_choice(const int minimum, const int maximum)
    {
        while (true)
        {
            std::cout << "Select an option: ";
            int choice{};
            if (std::cin >> choice && choice >= minimum && choice <= maximum)
            {
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                return choice;
            }
            if (std::cin.eof()) return 0;
            std::cout << "Invalid input. Please try again.\n";
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }

    std::size_t read_size(const std::string& prompt, const std::size_t minimum,
                          const std::size_t maximum, const std::size_t fallback)
    {
        std::cout << prompt;
        std::size_t value{};
        if (std::cin >> value && value >= minimum && value <= maximum)
        {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return value;
        }
        if (std::cin.eof()) return fallback;
        std::cout << "Invalid value. Using " << fallback << ".\n";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return fallback;
    }

    std::string read_message()
    {
        std::cout << "Enter a UTF-8 message: ";
        std::string message;
        std::getline(std::cin, message);
        return message;
    }

    void display_quantum_experiment(const crypto::quantum::ExperimentResult& result)
    {
        std::cout << crypto::quantum::format_experiment(result);
        std::cout << crypto::quantum::educational::render_probability_bars(result.probabilities);
    }

    void show_crypto_components()
    {
        bool back = false;
        while (!back)
        {
            std::cout << "\n========== Primitive Crypto Diagnostics (not suite analysis) ==========\n"
                      << "1. SHA-256 hash\n"
                      << "2. AES-128-GCM encrypt/decrypt demo\n"
                      << "3. RSA-4096 OAEP/PSS demo\n"
                      << "4. P-256 ECDH/ECDSA demo\n"
                      << "5. ML-KEM-768 implementation status\n"
                      << "0. Back\n";
            switch (read_choice(0, 5))
            {
            case 1:
                std::cout << crypto::standard::run_sha256_demo(read_message()) << '\n';
                break;
            case 2:
                std::cout << crypto::standard::run_aes_gcm_demo(read_message()) << '\n';
                break;
            case 3:
                std::cout << "Generating a 4096-bit RSA key pair. This may take some time.\n";
                std::cout << crypto::standard::run_rsa_demo(read_message(), 4096U) << '\n';
                break;
            case 4:
                std::cout << crypto::standard::run_p256_demo(read_message()) << '\n';
                break;
            case 5:
            {
                std::cout << crypto::standard::mlkem768_status_message() << '\n';
                if (crypto::standard::mlkem768_available())
                {
                    std::cout << "Running the portable C++ ML-KEM-768 round-trip demo...\n";
                    const auto result = crypto::standard::run_mlkem768_demo();
                    std::cout << '[' << (result.passed ? "PASS" : "FAIL") << "] "
                              << result.detail << '\n';
                    if (result.available)
                    {
                        std::cout << "Encapsulation key bytes: " << result.encapsulation_key_bytes << '\n'
                                  << "Ciphertext bytes: " << result.ciphertext_bytes << '\n'
                                  << "Shared secret bytes: " << result.shared_secret_bytes << '\n';
                    }
                }
                break;
            }
            default:
                back = true;
                break;
            }
        }
    }

    void show_standard_crypto()
    {
        show_crypto_components();
    }

    void show_educational_crypto()
    {
        std::cout << "\n========== Educational CryptoSystem ==========\n"
                  << "1. Generate a toy RSA instance\n"
                  << "2. Generate a toy elliptic-curve instance\n"
                  << "3. Generate a toy Module-LWE instance\n"
                  << "4. Find a truncated SHA-256 collision\n"
                  << "5. Generate a restricted-keyspace AES-GCM instance\n"
                  << "6. Educational CryptoSetAnalysis (three separate toy sets)\n"
                  << "7. Integrated Educational Crypto Analysis (all toy sets together)\n"
                  << "0. Back\n";
        switch (read_choice(0, 7))
        {
        case 1:
        {
            const std::size_t bits = read_size("Toy RSA modulus size (16-32 bits): ", 16U, 32U, 32U);
            const auto sample = crypto::educational::generate_toy_rsa_sample(bits);
            std::cout << "Toy RSA modulus: " << sample.modulus_bits << " bits\n"
                      << "Toy RSA public modulus: " << sample.public_instance.modulus << '\n'
                      << "Public exponent: " << sample.public_instance.public_exponent << '\n'
                      << "Ciphertext: " << sample.public_instance.ciphertext << '\n'
                      << "Ground truth is intentionally withheld from the analyzer input.\n";
            break;
        }
        case 2:
        {
            const auto sample = crypto::educational::generate_toy_ecc_sample();
            std::cout << "Toy curve: y^2 = x^3 + 2x + 3 (mod 97), fixed 7-bit field\n"
                      << "Base point: (0, 10), public point: ("
                      << sample.public_instance.public_x << ", "
                      << sample.public_instance.public_y << ")\n";
            break;
        }
        case 3:
        {
            const auto sample = crypto::educational::generate_toy_lwe_sample();
            std::cout << "Toy Module-LWE public instance generated.\n"
                      << "Parameters: ring degree n=4, module rank k=2, q=257.\n"
                      << "Secret and error polynomial coefficients are in {-1,0,1}.\n"
                      << "This is not ML-KEM and is not intended for real security.\n";
            (void)sample;
            break;
        }
        case 4:
        {
            const std::size_t outputBits = read_size("Truncated SHA-256 output size (4-16 bits): ", 4U, 16U, 16U);
            const auto collision = crypto::educational::find_truncated_sha256_collision(outputBits);
            std::cout << (collision.found ? "[PASS] Collision found.\n" : "[FAIL] No collision found.\n")
                      << "Truncated output bits: " << collision.output_bits << '\n'
                      << "Attempts: " << collision.attempts << '\n'
                      << "This demonstrates a truncated digest, not a collision in full SHA-256.\n";
            break;
        }
        case 5:
        {
            const std::size_t unknownBits = read_size("Unknown AES keyspace bits (4-16): ", 4U, 16U, 16U);
            const auto sample = crypto::educational::generate_toy_aes_sample(unknownBits);
            std::cout << "Restricted-keyspace AES-128-GCM record generated.\n"
                      << "Unknown key bits: " << sample.public_instance.unknown_bits << '\n'
                      << "This reduced keyspace is not representative of AES-128 security.\n";
            (void)sample;
            break;
        }
        case 6:
        {
            using namespace crypto::educational_set_analysis;
            std::cout << "\n========== Educational CryptoSetAnalysis ==========" << '\n'
                      << "1. Toy AES-SHA-ECDSA analogue\n"
                      << "2. Toy AES-SHA-RSAPSS analogue\n"
                      << "3. Toy SHA-AES-MLKEM analogue\n"
                      << "4. Compare all three toy sets\n"
                      << "5. Enter plaintext and run toy encryption / key-recovery simulation\n0. Back\n";
            switch (read_choice(0, 5))
            {
            case 1: { auto r=run_toy_aes_sha_ecdsa(); std::cout << format_set(r); break; }
            case 2: { auto r=run_toy_aes_sha_rsapss(); std::cout << format_set(r); break; }
            case 3: { auto r=run_toy_sha_aes_mlkem(); std::cout << format_set(r); break; }
            case 4: { auto v=run_all_toy_sets(); std::cout << format_comparison(v); std::string a,b; if(export_results(v,"Output/EducationalCryptoSetAnalysis",a,b)) std::cout << "\nReport: "<<a<<"\nCSV: "<<b<<'\n'; break; }
            case 5: { const std::string plaintext = read_message(); std::cout << run_custom_message_simulation(plaintext); break; }
            default: break;
            }
            break;
        }
        case 7:
        {
            const auto r=crypto::integrated_educational::run();
            std::cout << r.report;
            std::string a,b;
            if(crypto::integrated_educational::export_result(r,"Output/IntegratedEducationalCryptoAnalysis",a,b))
                std::cout << "Report: "<<a<<"\nCSV: "<<b<<'\n';
            break;
        }
        default:
            break;
        }
    }

    void show_standard_analyzer()
    {
        std::cout << "\n========== Standard Validation / Audit ==========\n";
        const auto results = crypto::analyzer::StandardAnalyzer::run_known_answer_tests();
        bool allPassed = true;
        for (const auto& result : results)
        {
            std::cout << '[' << (result.passed ? "PASS" : "FAIL") << "] "
                      << result.name << " - " << result.detail << '\n';
            allPassed = allPassed && result.passed;
        }
        std::cout << "Overall KAT result: " << (allPassed ? "PASS" : "FAIL") << '\n';
        std::cout << "Note: this is a limited local test set, not a certification or a complete conformance suite.\n";
    }

    void show_educational_analyzer()
    {
        bool back = false;
        while (!back)
        {
            std::cout << "\n========== Educational Analyzer ==========\n"
                      << "1. Generate and analyze a toy RSA instance\n"
                      << "2. Generate and analyze a toy elliptic-curve instance\n"
                      << "3. Generate and analyze a toy Module-LWE instance\n"
                      << "4. Generate and analyze a restricted-keyspace AES-GCM record\n"
                      << "0. Back\n";
            switch (read_choice(0, 4))
            {
            case 1:
            {
                const std::size_t bits = read_size("Toy RSA modulus size (16-32 bits): ", 16U, 32U, 32U);
                const auto sample = crypto::educational::generate_toy_rsa_sample(bits);
                const auto result = crypto::analyzer::EducationalAnalyzer::analyze(sample.public_instance);
                const bool match = result.success && result.recovered_plaintext == sample.ground_truth.plaintext;
                std::cout << '[' << (match ? "PASS" : "FAIL") << "] " << result.status
                          << "; recovered plaintext=" << result.recovered_plaintext
                          << "; candidates=" << result.trial_divisions << '\n';
                break;
            }
            case 2:
            {
                const auto sample = crypto::educational::generate_toy_ecc_sample();
                const auto result = crypto::analyzer::EducationalAnalyzer::analyze(sample.public_instance);
                const bool match = result.success && result.recovered_scalar == sample.ground_truth.private_scalar;
                std::cout << '[' << (match ? "PASS" : "FAIL") << "] " << result.status
                          << "; recovered scalar=" << result.recovered_scalar
                          << "; attempts=" << result.attempts << '\n';
                break;
            }
            case 3:
            {
                const auto sample = crypto::educational::generate_toy_lwe_sample();
                const auto result = crypto::analyzer::EducationalAnalyzer::analyze(sample.public_instance);
                const bool match = result.success && result.recovered_secret == sample.ground_truth.secret;
                std::cout << '[' << (match ? "PASS" : "FAIL") << "] " << result.status
                          << "; candidate vectors tested=" << result.candidates_tested << '\n';
                break;
            }
            case 4:
            {
                const std::size_t unknownBits = read_size("Unknown AES keyspace bits (4-16): ", 4U, 16U, 16U);
                const auto sample = crypto::educational::generate_toy_aes_sample(unknownBits);
                const auto result = crypto::analyzer::EducationalAnalyzer::analyze(sample.public_instance);
                const bool match = result.success && result.recovered_key == sample.ground_truth.key;
                std::cout << '[' << (match ? "PASS" : "FAIL") << "] " << result.status
                          << "; key candidates tested=" << result.candidates_tested << '\n';
                break;
            }
            default:
                back = true;
                break;
            }
        }
    }

    std::size_t read_rsa_modulus_bits()
    {
        std::cout << "RSA-PSS / OAEP modulus size\n"
                  << "1. 2048 bits (shorter demonstration)\n"
                  << "2. 3072 bits\n"
                  << "3. 4096 bits (project default)\n";
        const int choice = read_choice(1, 3);
        if (choice == 1) return 2048U;
        if (choice == 2) return 3072U;
        return 4096U;
    }

    void show_one_crypto_set(const crypto::set_analysis::SetRunResult& result)
    {
        std::cout << crypto::set_analysis::format_set_report(result) << '\n';
        std::string report_path;
        std::string csv_path;
        if (crypto::set_analysis::export_set_report(
                result, "Output/CryptoSetAnalysis", report_path, csv_path))
        {
            std::cout << "Report saved: " << report_path << '\n'
                      << "Metrics CSV saved: " << csv_path << '\n';
        }
        else
        {
            std::cout << "Warning: could not export the set report.\n";
        }
    }

    void show_crypto_set_analysis()
    {
        bool back = false;
        while (!back)
        {
            std::cout << "\n========== CryptoSetAnalysis ==========\n"
                      << "Independent cryptosystems; each uses its own key-sharing method.\n"
                      << "1. AES-SHA-ECDSA (P-256 ECDH + ECDSA)\n"
                      << "2. AES-SHA-RSAPSS (RSA-OAEP key transport + RSA-PSS)\n"
                      << "3. SHA-AES-MLKEM (ML-KEM-768)\n"
                      << "4. Compare all three independent sets\n"
                      << "0. Back\n";
            switch (read_choice(0, 4))
            {
            case 1:
            {
                const std::string plaintext = read_message();
                const auto result = crypto::set_analysis::run_aes_sha_ecdsa(plaintext, true);
                show_one_crypto_set(result);
                break;
            }
            case 2:
            {
                const std::string plaintext = read_message();
                const std::size_t rsa_bits = read_rsa_modulus_bits();
                std::cout << "Generating the RSA key pair. The 4096-bit option may take noticeably longer.\n";
                const auto result = crypto::set_analysis::run_aes_sha_rsa_pss(plaintext, rsa_bits, true);
                show_one_crypto_set(result);
                break;
            }
            case 3:
            {
                const std::string plaintext = read_message();
                const auto result = crypto::set_analysis::run_sha_aes_mlkem(plaintext, true);
                show_one_crypto_set(result);
                break;
            }
            case 4:
            {
                const std::string plaintext = read_message();
                const std::size_t rsa_bits = read_rsa_modulus_bits();
                std::cout << "Running the three sets independently and measuring each one.\n"
                          << "RSA key generation may take the longest.\n";
                const auto results = crypto::set_analysis::run_all_sets(plaintext, rsa_bits, true);
                std::cout << crypto::set_analysis::format_comparison_report(results) << '\n';
                for (const auto& result : results)
                    std::cout << crypto::set_analysis::format_set_report(result) << '\n';
                std::string report_path;
                std::string csv_path;
                if (crypto::set_analysis::export_comparison_report(
                        results, "Output/CryptoSetAnalysis", report_path, csv_path))
                {
                    std::cout << "Comparison report saved: " << report_path << '\n'
                              << "Comparison CSV saved: " << csv_path << '\n';
                }
                break;
            }
            default:
                back = true;
                break;
            }
        }
    }

    void show_integrated_crypto_analysis()
    {
        std::cout << "\n========== IntegratedCryptoAnalysis ==========\n"
                  << "This runs all three independent sets in one analysis batch.\n"
                  << "It aggregates operation times and quantum resource estimates; it does NOT merge the ciphers.\n";
        const std::string plaintext = read_message();
        const std::size_t rsa_bits = read_rsa_modulus_bits();
        std::cout << "Starting integrated analysis. RSA key generation may take the longest.\n";
        const auto result = crypto::integrated_crypto_analysis::run_integrated_analysis(
            plaintext, rsa_bits, true);
        std::cout << result.report << '\n';

        std::string report_path;
        std::string csv_path;
        if (crypto::integrated_crypto_analysis::export_integrated_analysis(
                result, "Output/IntegratedCryptoAnalysis", report_path, csv_path))
        {
            std::cout << "Integrated report saved: " << report_path << '\n'
                      << "Integrated CSV saved: " << csv_path << '\n';
        }
        else
        {
            std::cout << "Warning: could not export the integrated report.\n";
        }
    }

    void show_crypto_system()
    {
        std::cout << "\n========== CryptoSystem ==========\n"
                  << "1. Standard Mode\n"
                  << "2. Educational Mode\n"
                  << "0. Back\n";
        switch (read_choice(0, 2))
        {
        case 1: show_standard_crypto(); break;
        case 2: show_educational_crypto(); break;
        default: break;
        }
    }

    void show_crypto_analyzer()
    {
        std::cout << "\n========== CryptoAnalyzer ==========\n"
                  << "1. Standard Validation / Audit\n"
                  << "2. Educational Analyzer (self-generated data only)\n"
                  << "0. Back\n";
        switch (read_choice(0, 2))
        {
        case 1: show_standard_analyzer(); break;
        case 2: show_educational_analyzer(); break;
        default: break;
        }
    }

    void show_quantum_resource_estimate()
    {
        std::cout << "\nQuantum resource model\n"
                  << "1. RSA\n2. ECC\n3. AES search-space model\n4. Truncated SHA-256 model\n5. ML-KEM\n";
        const int algorithm = read_choice(1, 5);
        const std::size_t bits = read_size("Enter the parameter size in bits (1-4096): ", 1U, 4096U, 128U);
        crypto::quantum::CryptoTarget target = crypto::quantum::CryptoTarget::RSA;
        if (algorithm == 2) target = crypto::quantum::CryptoTarget::ECC;
        else if (algorithm == 3) target = crypto::quantum::CryptoTarget::AES;
        else if (algorithm == 4) target = crypto::quantum::CryptoTarget::SHA256;
        else if (algorithm == 5) target = crypto::quantum::CryptoTarget::MLKEM;
        const auto estimate = crypto::quantum::estimate_quantum_resources(target, bits, 22U);
        std::cout << crypto::quantum::format_resource_estimate(estimate);
    }

    void show_quantum_standard()
    {
        bool back = false;
        while (!back)
        {
            std::cout << "\n========== Standard Quantum Simulator ==========\n"
                      << "1. Grover search demonstration\n"
                      << "2. Quantum Fourier Transform demonstration\n"
                      << "3. Tiny Shor order-finding demonstration (N <= 15)\n"
                      << "4. Cryptographic quantum-resource model\n"
                      << "5. Export standard simulator demonstration report\n"
                      << "0. Back\n";
            switch (read_choice(0, 5))
            {
            case 1:
                display_quantum_experiment(crypto::quantum::run_grover_experiment(3U, 5U, 1024U));
                break;
            case 2:
                display_quantum_experiment(crypto::quantum::run_qft_experiment(3U));
                break;
            case 3:
                std::cout << crypto::quantum::format_shor_result(
                    crypto::quantum::run_shor_toy_experiment(15U, 2U, 2048U));
                break;
            case 4:
                show_quantum_resource_estimate();
                break;
            case 5:
            {
                std::vector<crypto::quantum::ExperimentResult> results{
                    crypto::quantum::run_superposition_experiment(),
                    crypto::quantum::run_entanglement_experiment(),
                    crypto::quantum::run_interference_experiment(),
                    crypto::quantum::run_grover_experiment(3U, 5U, 1024U),
                    crypto::quantum::run_qft_experiment(3U)
                };
                std::cout << "Report exported to: "
                          << crypto::quantum::export_quantum_report(results) << '\n';
                for (const auto& result : results) display_quantum_experiment(result);
                break;
            }
            default:
                back = true;
                break;
            }
        }
    }

    void show_quantum_educational()
    {
        bool back = false;
        while (!back)
        {
            std::cout << "\n========== Educational Quantum Simulator ==========\n"
                      << "1. Superposition\n"
                      << "2. Entanglement\n"
                      << "3. Quantum Interference\n"
                      << "4. Quantum Measurement\n"
                      << "5. Grover's Algorithm\n"
                      << "6. Quantum Fourier Transform\n"
                      << "7. Shor's Algorithm (tiny toy input)\n"
                      << "8. Run all experiments\n"
                      << "9. Cryptographic resource comparison\n"
                      << "0. Back\n";
            switch (read_choice(0, 9))
            {
            case 1: display_quantum_experiment(crypto::quantum::run_superposition_experiment()); break;
            case 2: display_quantum_experiment(crypto::quantum::run_entanglement_experiment()); break;
            case 3: display_quantum_experiment(crypto::quantum::run_interference_experiment()); break;
            case 4: display_quantum_experiment(crypto::quantum::run_measurement_experiment(1000U)); break;
            case 5:
            {
                const std::size_t qubits = read_size("Search register qubits (2-10): ", 2U, 10U, 3U);
                const std::size_t dimension = std::size_t{1} << qubits;
                const std::size_t target = read_size("Marked state index: ", 0U, dimension - 1U, 1U);
                display_quantum_experiment(crypto::quantum::run_grover_experiment(qubits, target, 2048U));
                break;
            }
            case 6:
            {
                const std::size_t qubits = read_size("QFT qubits (1-10): ", 1U, 10U, 3U);
                display_quantum_experiment(crypto::quantum::run_qft_experiment(qubits));
                break;
            }
            case 7:
            {
                std::cout << "Enter an odd composite toy number from 5 to 15 (default 15): ";
                std::size_t number = 15U;
                if (std::cin >> number && number >= 5U && number <= 15U)
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                else
                {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    number = 15U;
                }
                std::cout << crypto::quantum::format_shor_result(
                    crypto::quantum::run_shor_toy_experiment(static_cast<std::uint32_t>(number), 2U, 2048U));
                break;
            }
            case 8:
            {
                const auto results = crypto::quantum::educational::run_all_experiments();
                std::cout << "Report exported to: "
                          << crypto::quantum::export_quantum_report(results) << "\n\n";
                for (const auto& result : results) display_quantum_experiment(result);
                const auto shor = crypto::quantum::run_shor_toy_experiment(15U, 2U, 2048U);
                std::cout << crypto::quantum::format_shor_result(shor);
                break;
            }
            case 9:
                show_quantum_resource_estimate();
                break;
            default:
                back = true;
                break;
            }
        }
    }

    void show_quantum_attack()
    {
        std::cout << "\n========== QuantumAttack Simulator ==========\n"
                  << "1. Standard Simulator\n"
                  << "2. Educational Experiments\n"
                  << "0. Back\n";
        switch (read_choice(0, 2))
        {
        case 1: show_quantum_standard(); break;
        case 2: show_quantum_educational(); break;
        default: break;
        }
        std::cout << "This is a classical state-vector simulation. No quantum hardware is used.\n";
    }

    // ---------------------------------------------------------------------------------
    // 2.3.5: Educational Quantum Attack / Integrated Educational Quantum Attack /
    // Quantum Simulator Benchmark. These are separate from the classical educational
    // analyses under "Educational Mode" and from the generic simulator demos above.
    // ---------------------------------------------------------------------------------

    std::string read_quantum_attack_message()
    {
        std::cout << "The message is encrypted by each toy set before the analysis.\n"
                  << "Press Enter to use the default demonstration message.\n";
        return read_message();
    }

    crypto::educational_quantum_attack::QuantumAttackConfig read_quantum_attack_config()
    {
        crypto::educational_quantum_attack::QuantumAttackConfig config;
        std::cout << "Simulator backend for the circuits that are executed\n"
                  << "1. CPU multi-thread (default)\n"
                  << "2. CPU single-thread\n"
                  << "3. CUDA GPU\n"
                  << "4. CUDA multi-GPU\n";
        switch (read_choice(1, 4))
        {
        case 2: config.execution.backend = crypto::quantum::QuantumBackendType::CpuSingleThread; break;
        case 3: config.execution.backend = crypto::quantum::QuantumBackendType::CudaGpu; break;
        case 4: config.execution.backend = crypto::quantum::QuantumBackendType::CudaMultiGpu; break;
        default: config.execution.backend = crypto::quantum::QuantumBackendType::CpuMultiThread; break;
        }
        std::cout << "If the selected CUDA backend is unavailable, the circuits run on the CPU and the\n"
                  << "report says so; a CPU run is never reported as a GPU run.\n";
        config.progress = [](const std::string& message) { std::cout << "  ... " << message << '\n'; };
        return config;
    }

    void export_quantum_attack_sets(
        const std::vector<crypto::educational_quantum_attack::SetAttackReport>& reports)
    {
        using namespace crypto::educational_quantum_attack;
        ExportedFiles files;
        if (export_quantum_attack_reports(reports, std::string(DefaultQuantumAttackOutputDirectory), files))
        {
            for (const auto& path : files.set_reports)
                std::cout << "Report saved: " << absolute_output_path(path) << '\n';
            std::cout << "Metrics CSV saved: " << absolute_output_path(files.metrics_csv) << '\n'
                      << "Metrics JSON saved: " << absolute_output_path(files.metrics_json) << '\n';
        }
        else
        {
            std::cout << "Warning: could not export the quantum attack reports.\n";
        }
    }

    void show_educate_analysis()
    {
        using namespace crypto::educational_quantum_attack;
        std::cout << "\n========== EducateAnalysis: real quantum crack of the three toy composites ==========\n"
                  << "Enter a sentence. Each composite encrypts it, then every component is REALLY cracked\n"
                  << "on the state-vector simulator (Grover and Shor), not estimated:\n"
                  << "  Toy-AES_Toy-SHA_Toy-ECDSA  : Grover (AES, SHA) + Shor ECDLP (toy elliptic curve)\n"
                  << "  Toy-AES_Toy-SHA_Toy-RSAPSS : Grover (AES, SHA) + Shor factoring (toy RSA modulus)\n"
                  << "  Toy-AES_Toy-SHA_Toy-MLDSA  : Grover (AES, SHA) + custom Grover secret search (Module-LWE)\n"
                  << "All intermediate values are printed and the crack time is split by execution method.\n"
                  << "Tiny teaching parameters only; these crack times are not about real AES/SHA/ECDSA/RSA/ML-DSA.\n"
                  << "This can take a little while (the toy RSA Shor factoring is the slowest part).\n";
        const std::string message = read_message();
        const QuantumAttackConfig base = read_quantum_attack_config();

        EducateAnalysisConfig config;
        config.primary_execution = base.execution;
        config.progress = base.progress;
        const EducateAnalysisReport report = run_educate_analysis(message, config);
        std::cout << '\n' << report.report;
        if (report.plaintext_empty) return;

        std::string report_path;
        std::string csv_path;
        if (export_educate_analysis_report(
                report, std::string(DefaultEducateOutputDirectory), report_path, csv_path))
        {
            std::cout << "Report saved: " << report_path << '\n'
                      << "Metrics CSV saved: " << csv_path << '\n';
        }
        else
        {
            std::cout << "Warning: could not export the EducateAnalysis report.\n";
        }
    }

    void show_message_crack_timing()
    {
        using namespace crypto::educational_quantum_attack;
        std::cout << "\n========== Message Crack-Time Measurement ==========\n"
                  << "Enter a sentence. Each independent toy set encrypts it with the restricted\n"
                  << "12-bit Toy AES-128-GCM, then the key is recovered and the sentence decrypted.\n"
                  << "The measured crack time applies only to this educational 12-bit toy, not to AES-128.\n";
        const std::string message = read_message();
        const QuantumAttackConfig config = read_quantum_attack_config();
        const MessageCrackReport report = run_message_crack_timing(message, config);
        std::cout << '\n' << report.report;
        if (report.plaintext_empty) return;
        std::string report_path;
        std::string csv_path;
        if (export_message_crack_report(
                report, std::string(DefaultCrackOutputDirectory), report_path, csv_path))
        {
            std::cout << "Report saved: " << report_path << '\n'
                      << "Metrics CSV saved: " << csv_path << '\n';
        }
        else
        {
            std::cout << "Warning: could not export the message crack report.\n";
        }
    }

    void show_educational_quantum_attack()
    {
        using namespace crypto::educational_quantum_attack;
        bool back = false;
        while (!back)
        {
            std::cout << "\n========== Educational Quantum Attack ==========\n"
                      << "Independent quantum-attack analysis of each educational set (toy parameters).\n"
                      << "Executed circuits: Grover (Toy AES, Toy SHA preimage), BHT (Toy SHA collision).\n"
                      << "Theory only: Shor for Toy ECC / Toy RSA. NOT MODELED: Toy Module-LWE.\n"
                      << "1. AES-SHA-ECDSA analogue\n"
                      << "2. AES-SHA-RSAPSS analogue\n"
                      << "3. SHA-AES-MLKEM analogue\n"
                      << "4. All three sets, each analyzed independently\n"
                      << "5. Enter a sentence, encrypt it and measure the crack time\n"
                      << "0. Back\n";
            const int choice = read_choice(0, 5);
            if (choice == 0)
            {
                back = true;
                continue;
            }
            if (choice == 5)
            {
                show_message_crack_timing();
                continue;
            }
            const std::string message = read_quantum_attack_message();
            const QuantumAttackConfig config = read_quantum_attack_config();
            std::vector<SetAttackReport> reports;
            if (choice == 1) reports.push_back(run_aes_sha_ecdsa_quantum_attack(message, config));
            else if (choice == 2) reports.push_back(run_aes_sha_rsapss_quantum_attack(message, config));
            else if (choice == 3) reports.push_back(run_sha_aes_mlkem_quantum_attack(message, config));
            else reports = run_all_quantum_attacks(message, config);

            for (const auto& report : reports) std::cout << '\n' << format_set_report(report);
            std::cout << "\n========== Overview ==========\n" << format_set_overview(reports) << '\n';
            export_quantum_attack_sets(reports);
        }
    }

    void show_integrated_educational_quantum_attack()
    {
        namespace integrated = crypto::integrated_educational_quantum_attack;
        std::cout << "\n========== Integrated Educational Quantum Attack ==========\n"
                  << "Runs the three independent quantum-attack analyses and compares their results.\n"
                  << "The three sets are NOT merged, and the estimated times are NOT added together.\n";
        const std::string message = read_quantum_attack_message();
        const auto config = read_quantum_attack_config();
        const integrated::IntegratedResult result = integrated::run(message, config);
        std::cout << '\n' << result.report << '\n';

        integrated::IntegratedExportedFiles files;
        if (integrated::export_integrated_result(
                result, std::string(integrated::DefaultIntegratedOutputDirectory), files))
        {
            std::cout << "Integrated report saved: " << files.report << '\n'
                      << "Integrated metrics CSV saved: " << files.metrics_csv << '\n'
                      << "Comparison CSV saved: " << files.comparison_csv << '\n'
                      << "Metrics JSON saved: " << files.metrics_json << '\n';
        }
        else
        {
            std::cout << "Warning: could not export the integrated quantum attack report.\n";
        }
    }

    void show_quantum_simulator_benchmark()
    {
        std::cout << "\n========== Quantum Simulator Benchmark ==========\n"
                  << "General performance of the QuantumAttack state-vector simulator (Grover, QFT and the\n"
                  << "toy Shor experiment) on every backend. This is NOT an attack on any cryptosystem.\n";
        crypto::quantum::AlgorithmBenchmarkOptions options;
        options.qubit_counts = {4U, 8U, 10U};
        options.repeats = 3U;
        options.warmup_runs = 1U;
        options.shots = 512U;
        const auto results = crypto::quantum::run_algorithm_benchmark(options);
        for (const auto& result : results)
            std::cout << crypto::quantum::format_algorithm_benchmark_result(result) << '\n';
        std::cout << "CSV report: "
                  << crypto::quantum::export_algorithm_benchmark_csv(results, "Output/quantum_simulator_benchmark.csv")
                  << '\n'
                  << "Backends marked UNAVAILABLE were not run; their rows are never filled with CPU timings.\n"
                  << "All timings are classical state-vector simulation times, not quantum-hardware times.\n";
    }
}

int main()
{
    try
    {
        crypto::Logger::instance().info("CryptoProject started.");
        bool running = true;
        while (running)
        {
            std::cout << "\n====================================\n"
                      << "          CryptoProject\n"
                      << "====================================\n"
                      << "1. CryptoSetAnalysis (three independent sets)\n"
                      << "2. IntegratedCryptoAnalysis (all three sets together)\n"
                      << "3. Primitive diagnostics / educational examples (not suite analysis)\n"
                      << "4. CryptoAnalyzer\n"
                      << "5. QuantumAttack Simulator\n"
                      << "6. Educational Integrated Analysis (toy instances)\n"
                      << "7. Benchmark\n"
                      << "8. Compute Engine\n"
                      << "9. Educational Quantum Attack (three independent toy sets)\n"
                      << "10. Integrated Educational Quantum Attack (compare the three sets)\n"
                      << "11. Quantum Simulator Benchmark (QuantumAttack engine)\n"
                      << "12. EducateAnalysis (real quantum crack of a sentence; per-backend timing)\n"
                      << "0. Exit\n";

            switch (read_choice(0, 12))
            {
            case 1: show_crypto_set_analysis(); break;
            case 2: show_integrated_crypto_analysis(); break;
            case 3: show_crypto_system(); break;
            case 4: show_crypto_analyzer(); break;
            case 5: show_quantum_attack(); break;
            case 6:
            {
                const auto result = crypto::integrated::run_educational_integrated_demo();
                std::cout << "\n========== Educational Integrated Report ==========\n"
                          << result.report << '\n';
                break;
            }
            case 7:
                std::cout << crypto::benchmark::run_basic_benchmark() << '\n';
                break;
            case 8:
            {
                const auto devices = crypto::ComputeEngine::discover_gpus();
                std::cout << "CUDA compiled: " << (crypto::ComputeEngine::cuda_compiled() ? "YES" : "NO") << '\n'
                          << "Detected NVIDIA GPUs: " << devices.size() << '\n';
                for (const auto& device : devices)
                    std::cout << "GPU " << device.index << ": " << device.name
                              << ", memory=" << device.total_memory_bytes << " bytes\n";
                std::cout << "The C++ ComputeEngine API provides vector addition and short-message SHA-256 batch operations.\n"
                          << "CUDA quantum kernels are exposed through explicit simulator methods.\n"
                          << "This menu currently displays devices; it does not launch a compute workload.\n";
                break;
            }
            case 9: show_educational_quantum_attack(); break;
            case 10: show_integrated_educational_quantum_attack(); break;
            case 11: show_quantum_simulator_benchmark(); break;
            case 12: show_educate_analysis(); break;
            default:
                running = false;
                break;
            }
        }
        crypto::Logger::instance().info("CryptoProject stopped.");
        std::cout << "CryptoProject has been closed.\n";
        return 0;
    }
    catch (const crypto::CryptoException& exception)
    {
        std::cerr << "[CRYPTO ERROR] " << exception.what() << '\n';
        return 1;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FATAL ERROR] " << exception.what() << '\n';
        return 1;
    }
}
