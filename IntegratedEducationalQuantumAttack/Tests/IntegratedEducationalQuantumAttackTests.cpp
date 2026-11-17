// Tests for the integrated educational quantum-attack analysis (CryptoProject 2.3.5).
//
// Covered: running the three sets, aggregating every result, comparing resources,
// generating the report, generating the CSV files, and propagating failure states.

#include "IntegratedEducationalQuantumAttack/IntegratedEducationalQuantumAttack.h"
#include "IntegratedEducationalQuantumAttack/QuantumAttackExport.h"

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"

#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    namespace integrated = crypto::integrated_educational_quantum_attack;
    namespace eqa = crypto::educational_quantum_attack;

    void require(const bool condition, const std::string& message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    [[nodiscard]] bool contains(const std::string& text, const std::string& part)
    {
        return text.find(part) != std::string::npos;
    }

    [[nodiscard]] std::size_t csv_columns(const std::string& line)
    {
        std::size_t columns = 1U;
        bool quoted = false;
        for (const char character : line)
        {
            if (character == '"') quoted = !quoted;
            else if (character == ',' && !quoted) ++columns;
        }
        return columns;
    }

    [[nodiscard]] std::string read_file(const std::string& path)
    {
        std::ifstream input(path);
        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

    [[nodiscard]] eqa::QuantumAttackConfig test_config()
    {
        eqa::QuantumAttackConfig config;
        config.seed = 20260516U;
        config.execution.backend = crypto::quantum::QuantumBackendType::CpuMultiThread;
        config.execution.cpu_threads = 2U;
        return config;
    }

    void test_run_and_aggregate(const integrated::IntegratedResult& result)
    {
        const integrated::Comparison& comparison = result.comparison;
        require(result.sets.size() == 3U, "The integrated analysis must run exactly three sets.");
        require(comparison.rows.size() == 12U && comparison.attacks_total == 12U,
                "Every analysis of every set must be aggregated.");
        require(comparison.attacks_executed == 9U && comparison.attacks_succeeded == 9U,
                "Nine circuits are executed and must succeed.");
        require(comparison.attacks_failed == 0U, "No analysis may fail in a normal run.");
        require(comparison.attacks_theory_only == 2U && comparison.attacks_not_modeled == 1U,
                "Two theory-only analyses and one NOT MODELED analysis are expected.");

        // Honest overall status: not everything was attacked by a circuit.
        require(result.status == eqa::SetStatus::Partial && !result.any_failure,
                "The integrated status must be PARTIAL, not a blanket success.");

        std::set<std::string> targets;
        for (const integrated::ComparisonRow& row : comparison.rows) targets.insert(row.target);
        for (const char* expected : {"Toy AES", "Toy SHA Preimage", "Toy SHA Collision", "Toy ECC", "Toy RSA", "Toy Module-LWE"})
            require(targets.contains(expected), std::string("The comparison is missing ") + expected + '.');

        for (const integrated::ComparisonRow& row : comparison.rows)
        {
            if (row.target == "Toy SHA Collision")
                require(row.algorithm == "BHT", "The collision row must be BHT.");
            if (row.target == "Toy SHA Preimage" || row.target == "Toy AES")
                require(row.algorithm == "Grover", "AES and preimage rows must be Grover.");
            if (row.target == "Toy Module-LWE")
            {
                require(row.algorithm == "NOT MODELED" && !row.model_qubits.has_value() &&
                        !row.estimated_quantum_seconds.has_value(),
                        "The Module-LWE row must carry no invented figure.");
            }
            if (row.target == "Toy ECC" || row.target == "Toy RSA")
            {
                require(!row.simulator_executed && !row.simulated_qubits.has_value() &&
                        row.model_qubits.kind == eqa::MetricKind::Estimated,
                        "Shor rows are theory only: estimated model, nothing measured.");
            }
            if (row.simulator_executed)
            {
                require(row.simulator_runtime_ms.kind == eqa::MetricKind::Measured &&
                        row.estimated_quantum_seconds.kind == eqa::MetricKind::Estimated,
                        "Simulator runtime is measured and quantum attack time is estimated.");
                require(!row.gpu_executed, "A CPU run must not be reported as a GPU run.");
            }
        }
    }

    void test_resource_comparison(const integrated::IntegratedResult& result)
    {
        const integrated::Comparison& comparison = result.comparison;
        require(comparison.fewest_simulated_qubits.available &&
                comparison.fewest_simulated_qubits.value.value == 12.0L &&
                comparison.fewest_simulated_qubits.target == "Toy AES",
                "The smallest executed circuit is the 12-qubit Toy AES search.");
        require(comparison.fewest_model_qubits.available && comparison.fewest_model_qubits.value.value == 21.0L,
                "The smallest resource model is the Toy AES Grover model.");
        require(comparison.shallowest_model_depth.available && comparison.shallowest_model_depth.value.has_value(),
                "A shallowest modeled circuit must be identified.");
        require(comparison.fastest_simulation.available &&
                comparison.fastest_simulation.value.kind == eqa::MetricKind::Measured,
                "The fastest simulator run must be a measured value.");
        require(!comparison.fewest_model_qubits.caveat.empty() && !comparison.fastest_simulation.caveat.empty(),
                "Every highlight must carry its caveat.");

        require(comparison.total_simulator_runtime_ms.kind == eqa::MetricKind::Measured &&
                comparison.total_simulator_runtime_ms.value > 0.0L,
                "The total simulator runtime must be a measured sum.");
        long double sum = 0.0L;
        for (const integrated::ComparisonRow& row : comparison.rows)
            if (row.simulator_runtime_ms.kind == eqa::MetricKind::Measured) sum += row.simulator_runtime_ms.value;
        require(std::abs(static_cast<double>(sum - comparison.total_simulator_runtime_ms.value)) < 1.0e-6,
                "The total simulator runtime must equal the sum of the rows.");
        require(comparison.total_classical_runtime_ms.kind == eqa::MetricKind::Measured,
                "The total classical runtime must be a measured sum.");

        require(comparison.applicability.size() == 12U, "Every attack model needs an applicability statement.");
        require(!comparison.not_modeled_items.empty() && !comparison.assumptions.empty(),
                "Unmodeled items and assumptions must be listed.");
        bool lwe_listed = false;
        bool oracle_listed = false;
        for (const std::string& item : comparison.not_modeled_items)
        {
            if (contains(item, "Toy Module-LWE") && contains(item, "NOT MODELED")) lwe_listed = true;
            if (contains(item, "inside one oracle call")) oracle_listed = true;
        }
        require(lwe_listed && oracle_listed, "Module-LWE and the oracle circuits must be listed as NOT MODELED.");
    }

    void test_report(const integrated::IntegratedResult& result)
    {
        const std::string& report = result.report;
        for (const char* section : {
                 "INTEGRATED EDUCATIONAL QUANTUM ATTACK ANALYSIS",
                 "[1] COMPARISON OF THE ATTACK MODELS",
                 "[2] COMPUTER RESOURCES OF THE CLASSICAL SIMULATIONS",
                 "[3] AGGREGATED MEASUREMENTS",
                 "[4] HIGHLIGHTS",
                 "[5] APPLICABILITY OF EACH ATTACK MODEL",
                 "[6] NOT EXECUTED AND NOT MODELED ITEMS",
                 "[7] ASSUMPTIONS BEHIND THE ESTIMATES",
                 "[8] LIMITS OF INTERPRETATION",
                 "[9] INDIVIDUAL SET REPORTS"})
        {
            require(contains(report, section), std::string("The integrated report is missing: ") + section);
        }
        require(contains(report, "NOT SUMMED"), "The estimated attack times must not be summed.");
        require(contains(report, "NOT\nmerged") || contains(report, "NOT merged"),
                "The report must say the sets are not merged.");
        require(contains(report, "Educational AES-SHA-ECDSA analogue") &&
                contains(report, "Educational AES-SHA-RSAPSS analogue") &&
                contains(report, "Educational SHA-AES-MLKEM analogue"),
                "The integrated report must contain all three set reports.");
        require(contains(report, "NOT quantum attack time"), "The report must separate simulator and attack time.");
        require(!contains(report, "time to break all"), "No total break time may be claimed.");
    }

    void test_csv_and_export(const integrated::IntegratedResult& result)
    {
        const std::string comparison = integrated::comparison_csv(result.comparison);
        std::istringstream lines(comparison);
        std::string line;
        std::size_t columns = 0U;
        std::size_t rows = 0U;
        while (std::getline(lines, line))
        {
            if (line.empty()) continue;
            if (columns == 0U) columns = csv_columns(line);
            else
            {
                require(csv_columns(line) == columns, "A comparison CSV row does not match the header.");
                ++rows;
            }
        }
        require(rows == 12U, "The comparison CSV must contain one row per analysis.");
        require(contains(comparison, "time_a_simulator_runtime_ms") &&
                contains(comparison, "time_b_estimated_quantum_attack_seconds") &&
                contains(comparison, "state_vector_bytes"), "Comparison CSV columns must carry units.");

        const std::string aggregates = integrated::aggregate_metrics_csv(result.comparison, result.status);
        require(contains(aggregates, "metric,value,unit,kind,scope"), "The aggregate CSV needs unit and scope columns.");
        require(contains(aggregates, "attacks_total,12,") && contains(aggregates, "NOT SUMMED"),
                "The aggregate CSV is incomplete.");

        const std::string directory = "IntegratedQuantumAttackTestOutput";
        std::filesystem::remove_all(directory);
        integrated::IntegratedExportedFiles files;
        require(integrated::export_integrated_result(result, directory, files), "The integrated export failed.");
        for (const std::string& path : {files.report, files.metrics_csv, files.comparison_csv, files.metrics_json})
            require(std::filesystem::exists(path) && std::filesystem::file_size(path) > 0U, "An export file is missing: " + path);
        require(contains(files.report, "integrated_quantum_report.txt") &&
                contains(files.metrics_csv, "integrated_quantum_metrics.csv") &&
                contains(files.comparison_csv, "quantum_attack_comparison.csv"), "Export file names are wrong.");
        require(read_file(files.report) == result.report, "The exported report differs from the in-memory report.");
        std::filesystem::remove_all(directory);
    }

    void test_failure_propagation(const integrated::IntegratedResult& baseline)
    {
        // One failed attack fails its set and the integrated result.
        std::vector<eqa::SetAttackReport> failed_sets = baseline.sets;
        failed_sets[1].attacks[0].outcome = eqa::AttackOutcome::Failed;
        failed_sets[1].status = eqa::SetStatus::Failed;
        const integrated::IntegratedResult failed = integrated::integrate(failed_sets);
        require(failed.status == eqa::SetStatus::Failed && failed.any_failure,
                "A failed set must make the integrated result FAILED.");
        require(failed.comparison.attacks_failed == 1U && failed.comparison.attacks_succeeded == 8U,
                "The failure must be counted.");
        require(contains(failed.report, "FAILED"), "The integrated report must show the failure.");

        // The failure is detected even if the set forgot to update its own status.
        std::vector<eqa::SetAttackReport> stale_sets = baseline.sets;
        stale_sets[2].attacks[1].outcome = eqa::AttackOutcome::Failed;
        const integrated::IntegratedResult stale = integrated::integrate(stale_sets);
        require(stale.status == eqa::SetStatus::Failed && stale.any_failure,
                "A failed attack must be detected even with a stale set status.");

        // An execution error is a failure too.
        std::vector<eqa::SetAttackReport> error_sets = baseline.sets;
        error_sets[0].attacks[2].execution = eqa::ExecutionStatus::Error;
        error_sets[0].attacks[2].outcome = eqa::AttackOutcome::Failed;
        error_sets[0].status = eqa::SetStatus::Failed;
        require(integrated::integrate(error_sets).status == eqa::SetStatus::Failed,
                "An execution error must make the integrated result FAILED.");

        // Only when every attack of every set succeeded is the result a full success.
        std::vector<eqa::SetAttackReport> success_sets = baseline.sets;
        for (eqa::SetAttackReport& set : success_sets)
        {
            for (eqa::AttackResult& attack : set.attacks)
            {
                attack.execution = eqa::ExecutionStatus::Simulated;
                attack.outcome = eqa::AttackOutcome::Succeeded;
            }
            set.status = eqa::SetStatus::AllSucceeded;
        }
        const integrated::IntegratedResult success = integrated::integrate(success_sets);
        require(success.status == eqa::SetStatus::AllSucceeded && !success.any_failure,
                "All-success aggregation is wrong.");

        // No sets at all is not a success.
        require(integrated::integrate({}).status == eqa::SetStatus::Partial, "An empty analysis is not a success.");
    }

    void test_nothing_executed()
    {
        // With a budget below every circuit nothing is executed: no measured time may appear
        // and no highlight may be invented.
        eqa::QuantumAttackConfig config = test_config();
        config.budget.max_qubits = 4U;
        config.run_validation_experiments = false;
        const integrated::IntegratedResult result = integrated::run("Hello", config);
        require(result.comparison.attacks_executed == 0U && result.comparison.attacks_succeeded == 0U,
                "Nothing fits a 4-qubit budget.");
        require(result.status == eqa::SetStatus::Partial && !result.any_failure,
                "Not executing is PARTIAL: neither a success nor a failure.");
        require(result.comparison.total_simulator_runtime_ms.kind == eqa::MetricKind::NotExecuted,
                "Without executed circuits there is no simulator runtime.");
        require(!result.comparison.fastest_simulation.available &&
                !result.comparison.fewest_simulated_qubits.available,
                "Highlights over executed circuits must be unavailable.");
        require(contains(result.report, "NOT AVAILABLE") && contains(result.report, "NOT EXECUTED"),
                "The report must say that nothing was executed.");
        require(result.comparison.fewest_model_qubits.available,
                "The logical resource models do not depend on execution.");
    }
}

int main()
{
    try
    {
        const integrated::IntegratedResult result = integrated::run("Hello", test_config());
        test_run_and_aggregate(result);
        test_resource_comparison(result);
        test_report(result);
        test_csv_and_export(result);
        test_failure_propagation(result);
        test_nothing_executed();
        std::cout << "[PASS] Integrated educational quantum attack tests completed successfully.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FAIL] " << exception.what() << '\n';
        return 1;
    }
}
