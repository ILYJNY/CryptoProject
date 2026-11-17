#pragma once

// EducateAnalysis mode (CryptoProject 2.3.5): enter a sentence, encrypt it with the three
// educational toy composites, then REALLY crack each one with quantum algorithms and report
// the crack time, split by execution method (single CPU / multithreaded CPU / GPU parallel).
//
//   Toy-AES_Toy-SHA_Toy-ECDSA  -> Grover (AES, SHA) + Shor ECDLP (the toy elliptic curve)
//   Toy-AES_Toy-SHA_Toy-RSAPSS -> Grover (AES, SHA) + Shor factoring (the toy RSA modulus)
//   Toy-AES_Toy-SHA_Toy-MLDSA  -> Grover (AES, SHA) + a custom Grover secret search (Module-LWE)
//
// Every attack is executed on the state-vector simulator (not a resource estimate), the
// recovered values are verified against the real instances, and all intermediate values
// (keys, ciphertext, nonce, tag, digest, curve points, modulus, factors, order, secret, ...)
// are reported. Parameters are deliberately tiny teaching parameters; the measured crack
// times apply only to these toys, never to AES-128, SHA-256, real ECDSA, RSA or ML-DSA.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto::educational_quantum_attack
{
    inline constexpr std::string_view DefaultEducateOutputDirectory = "Output/EducateAnalysis";

    using NamedValue = std::pair<std::string, std::string>;
    using NamedValueList = std::vector<NamedValue>;

    enum class EducateSetId
    {
        AesShaEcdsa,
        AesShaRsaPss,
        AesShaMlDsa
    };

    // Timing of one decisive attack circuit under one execution backend.
    struct BackendTiming
    {
        std::string method;             // "Single CPU", "Multithreaded CPU", "GPU parallel"
        bool available = false;         // whether the backend can run in this build
        bool executed = false;          // whether the circuit actually ran on it
        double simulator_ms = 0.0;      // measured state-vector simulation wall time
        std::string note;               // e.g. the reason a GPU backend is unavailable
    };

    struct ComponentCrack
    {
        std::string component;          // "Toy AES", "Toy SHA preimage", "Toy ECC", ...
        std::string algorithm;          // "Grover", "Shor (factoring)", "Shor (ECDLP)", "Custom Grover"
        bool executed = false;
        bool cracked = false;
        std::string status;
        NamedValueList inputs;          // all intermediate input values of this component
        NamedValueList recovered;       // all recovered values
        NamedValueList resources;       // qubits, iterations, oracle calls, ...
        double real_crack_ms = 0.0;     // wall time of the executed real crack
        std::vector<BackendTiming> timings;  // single CPU / multithreaded CPU / GPU parallel
    };

    struct SetCrack
    {
        EducateSetId id = EducateSetId::AesShaEcdsa;
        std::string name;               // "Toy-AES_Toy-SHA_Toy-ECDSA"
        std::string disclaimer;
        NamedValueList encryption;      // plaintext, ciphertext, nonce, tag, digest, key (ground truth)
        std::vector<ComponentCrack> components;
        bool all_cracked = false;
        double wall_ms = 0.0;
    };

    struct EducateAnalysisReport
    {
        std::string plaintext;
        bool plaintext_empty = false;
        std::vector<SetCrack> sets;
        std::string report;
    };

    struct EducateAnalysisConfig
    {
        // Backend used for the real crack that recovers the values.
        quantum::QuantumExecutionOptions primary_execution{};
        SimulationBudget budget{};
        std::uint64_t seed = 0U;                    // 0 draws a fresh seed
        std::size_t rsa_modulus_bits = 16U;         // size of the toy RSA modulus Shor factors
        std::size_t toy_sha_bits = 16U;
        bool measure_gpu = true;                    // include the GPU-parallel timing row
        std::function<void(const std::string&)> progress;
    };

    [[nodiscard]] EducateAnalysisReport run_educate_analysis(
        const std::string& plaintext, const EducateAnalysisConfig& config = {});

    [[nodiscard]] std::string format_educate_analysis_report(const EducateAnalysisReport& report);

    // Writes educate_analysis_report.txt and educate_analysis_metrics.csv into `directory`
    // and sets the paths to the ABSOLUTE locations actually written, so the files can be found
    // regardless of the working directory the program was launched from.
    [[nodiscard]] bool export_educate_analysis_report(
        const EducateAnalysisReport& report, const std::string& directory,
        std::string& report_path, std::string& csv_path);

    // Resolves a possibly-relative path to an absolute path string (no existence requirement).
    [[nodiscard]] std::string absolute_output_path(const std::string& path);
}
