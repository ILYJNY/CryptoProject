#include "EducationalExperiments.h"

#include "../../Standard/Algorithms/QuantumAlgorithms.h"

#include <sstream>

namespace crypto::quantum::educational
{
    std::vector<ExperimentResult> run_all_experiments(const QuantumExecutionOptions& options)
    {
        std::vector<ExperimentResult> results;
        results.reserve(6U);
        results.push_back(run_superposition_experiment(options));
        results.push_back(run_entanglement_experiment(options));
        results.push_back(run_interference_experiment(options));
        results.push_back(run_measurement_experiment(1000U, options));
        results.push_back(run_grover_experiment(3U, 5U, 1024U, options));
        results.push_back(run_qft_experiment(3U, options));
        return results;
    }

    std::string run_all_experiments_text(const QuantumExecutionOptions& options)
    {
        std::ostringstream output;
        bool allPassed = true;
        for (const auto& result : run_all_experiments(options))
        {
            output << format_experiment(result) << '\n';
            allPassed = allPassed && result.passed;
        }
        const auto shor = run_shor_toy_experiment(15U, 2U, 2048U, options);
        output << format_shor_result(shor) << '\n';
        allPassed = allPassed && shor.factored;
        output << "Educational experiment suite: " << (allPassed ? "PASS" : "CHECK") << '\n'
               << "Note: state-vector simulation runs on classical CPU or GPU hardware; no quantum processor is used.\n";
        return output.str();
    }
}
