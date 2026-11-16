#include "IntegratedRunner.h"

#include "CryptoAnalyzer/Educational/EducationalAnalyzer.h"
#include "CryptoSystem/Educational/AES/ToyAESKeySearch.h"
#include "CryptoSystem/Educational/ECC/ToyECC.h"
#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"
#include "CryptoSystem/Educational/RSA/ToyRSA.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "Logger/Logger.h"
#include "QuantumAttack/Standard/Algorithms/QuantumAlgorithms.h"
#include "QuantumAttack/Reports/QuantumReport.h"
#include "PerformanceMonitor/PerformanceMonitor.h"

#include <filesystem>
#include <sstream>

namespace crypto::integrated
{
    IntegratedRunResult run_educational_integrated_demo()
    {
        PerformanceMonitor monitor;
        std::ostringstream report;
        bool allPassed = true;

        educational::ToyRsaSample rsaSample;
        monitor.measure("Educational.RSA.Generate", "CPU", [&]()
        {
            rsaSample = educational::generate_toy_rsa_sample();
        });
        educational::ToyRsaAnalysis rsaResult;
        monitor.measure("Educational.RSA.Analyze", "CPU", [&]()
        {
            rsaResult = analyzer::EducationalAnalyzer::analyze(rsaSample.public_instance);
        });
        const bool rsaPassed = rsaResult.success &&
            rsaResult.recovered_plaintext == rsaSample.ground_truth.plaintext &&
            ((rsaResult.recovered_p == rsaSample.ground_truth.p &&
              rsaResult.recovered_q == rsaSample.ground_truth.q) ||
             (rsaResult.recovered_p == rsaSample.ground_truth.q &&
              rsaResult.recovered_q == rsaSample.ground_truth.p));
        allPassed = allPassed && rsaPassed;
        report << "[" << (rsaPassed ? "PASS" : "FAIL") << "] Toy RSA: "
               << rsaResult.status << ", trial divisions=" << rsaResult.trial_divisions << '\n';

        educational::ToyEccSample eccSample;
        monitor.measure("Educational.ECC.Generate", "CPU", [&]()
        {
            eccSample = educational::generate_toy_ecc_sample();
        });
        educational::ToyEccAnalysis eccResult;
        monitor.measure("Educational.ECC.Analyze", "CPU", [&]()
        {
            eccResult = analyzer::EducationalAnalyzer::analyze(eccSample.public_instance);
        });
        const bool eccPassed = eccResult.success &&
            eccResult.recovered_scalar == eccSample.ground_truth.private_scalar;
        allPassed = allPassed && eccPassed;
        report << "[" << (eccPassed ? "PASS" : "FAIL") << "] Toy elliptic curve: "
               << eccResult.status << ", candidate scalars=" << eccResult.attempts << '\n';

        educational::ToyLweSample lweSample;
        monitor.measure("Educational.ModuleLWE.Generate", "CPU", [&]()
        {
            lweSample = educational::generate_toy_lwe_sample();
        });
        educational::ToyLweAnalysis lweResult;
        monitor.measure("Educational.ModuleLWE.Analyze", "CPU", [&]()
        {
            lweResult = analyzer::EducationalAnalyzer::analyze(lweSample.public_instance);
        });
        const bool lwePassed = lweResult.success &&
            lweResult.recovered_secret == lweSample.ground_truth.secret;
        allPassed = allPassed && lwePassed;
        report << "[" << (lwePassed ? "PASS" : "FAIL") << "] Toy Module-LWE (R_q with n=4, k=2): "
               << lweResult.status << ", candidates tested=" << lweResult.candidates_tested << '\n';

        educational::ToyAesSample aesSample;
        monitor.measure("Educational.AES.Generate", "CPU", [&]()
        {
            aesSample = educational::generate_toy_aes_sample();
        });
        educational::ToyAesAnalysis aesResult;
        monitor.measure("Educational.AES.Analyze", "CPU", [&]()
        {
            aesResult = analyzer::EducationalAnalyzer::analyze(aesSample.public_instance);
        });
        const bool aesPassed = aesResult.success &&
            aesResult.recovered_key == aesSample.ground_truth.key;
        allPassed = allPassed && aesPassed;
        report << "[" << (aesPassed ? "PASS" : "FAIL") << "] Toy AES keyspace: "
               << aesResult.status << ", candidates tested=" << aesResult.candidates_tested << '\n';

        quantum::ShorToyResult quantumResult;
        monitor.measure("QuantumAttack.Educational.ToyShor", "CPU-StateVector", [&]()
        {
            quantumResult = quantum::run_shor_toy_experiment(15U, 2U, 2048U);
        });
        const bool quantumPassed = quantumResult.factored &&
            quantumResult.factor_a * quantumResult.factor_b == 15U;
        allPassed = allPassed && quantumPassed;
        report << "[" << (quantumPassed ? "PASS" : "CHECK") << "] Tiny Shor simulation: "
               << quantumResult.status << ", qubits=" << quantumResult.qubits
               << ", shots=" << quantumResult.shots
               << ", CPU simulation ms=" << quantumResult.elapsed_ms << '\n';

        educational::TruncatedHashCollision collision;
        monitor.measure("Educational.SHA256.CollisionDemo", "CPU", [&]()
        {
            collision = educational::find_truncated_sha256_collision(16U, 200000U);
        });
        const bool shaPassed = collision.found &&
            educational::truncated_sha256(
                "CryptoProject truncated SHA-256 demo:" + std::to_string(collision.first_input), 16U) ==
            educational::truncated_sha256(
                "CryptoProject truncated SHA-256 demo:" + std::to_string(collision.second_input), 16U);
        allPassed = allPassed && shaPassed;
        report << "[" << (shaPassed ? "PASS" : "FAIL") << "] Truncated SHA-256 collision: "
               << (collision.found ? "COLLISION_FOUND" : "NOT_FOUND")
               << ", attempts=" << collision.attempts << '\n';

        std::filesystem::create_directories("Output");
        monitor.export_csv("Output/integrated_performance.csv");
        monitor.export_summary_csv("Output/integrated_performance_summary.csv");
        const std::vector<quantum::ExperimentResult> quantumExperiments{
            quantum::run_superposition_experiment(),
            quantum::run_entanglement_experiment(),
            quantum::run_interference_experiment(),
            quantum::run_grover_experiment(3U, 5U, 1024U),
            quantum::run_qft_experiment(3U)
        };
        const std::string quantumReportPath = quantum::export_quantum_report(
            quantumExperiments, "Output/integrated_quantum_report.csv");

        report << "Performance records: Output/integrated_performance.csv\n"
               << "Performance summary: Output/integrated_performance_summary.csv\n"
               << "Quantum experiment report: " << quantumReportPath << '\n'
               << "Overall result: " << (allPassed ? "PASS" : "FAIL");

        Logger::instance().info(allPassed
            ? "Integrated educational analysis completed successfully."
            : "Integrated educational analysis completed with a failed comparison.");

        return {allPassed, report.str()};
    }
}
