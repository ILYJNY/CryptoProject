#include "ToyModuleLweGroverAttack.h"

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "EducationalQuantumAttack/Engine/GroverEngine.h"

#include <exception>
#include <vector>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        // The oracle truth table: every candidate index the real toy-LWE predicate accepts.
        [[nodiscard]] std::vector<std::size_t> marked_candidates(
            const educational::ToyLwePublicInstance& instance)
        {
            std::vector<std::size_t> marked;
            for (std::uint64_t encoded = 0; encoded < educational::ToyModuleSecretCandidateCount; ++encoded)
            {
                if (educational::toy_lwe_candidate_matches(instance, educational::decode_toy_lwe_candidate(encoded)))
                    marked.push_back(static_cast<std::size_t>(encoded));
            }
            return marked;
        }

        [[nodiscard]] GroverSearchRequest build_request(
            const educational::ToyLwePublicInstance& instance,
            const std::vector<std::size_t>& marked,
            const quantum::QuantumExecutionOptions& execution,
            std::uint64_t seed, std::size_t qubit_budget)
        {
            GroverSearchRequest request;
            request.search_qubits = ceil_log2(educational::ToyModuleSecretCandidateCount);
            request.marked_indices = marked;
            request.classical_verifier = [&instance](const std::size_t candidate)
            {
                return candidate < educational::ToyModuleSecretCandidateCount &&
                    educational::toy_lwe_candidate_matches(
                        instance, educational::decode_toy_lwe_candidate(static_cast<std::uint64_t>(candidate)));
            };
            request.strategy = GroverStrategy::UnknownSolutionCount;
            request.seed = seed;
            request.execution = execution;
            request.simulator_qubit_limit = qubit_budget;
            return request;
        }
    }

    ToyModuleLweGroverAttack attack_toy_module_lwe_with_grover(
        const educational::ToyLwePublicInstance& instance,
        const QuantumAttackConfig& config,
        const std::uint64_t seed)
    {
        ToyModuleLweGroverAttack result;
        result.candidate_space = educational::ToyModuleSecretCandidateCount;
        result.search_qubits = ceil_log2(educational::ToyModuleSecretCandidateCount);
        result.total_qubits = result.search_qubits;

        const SimulationFeasibility feasibility =
            check_simulation_budget(result.search_qubits, GroverWorkingMemoryFactor, config.budget);
        if (!feasibility.feasible)
        {
            result.executed = false;
            result.status = "NOT EXECUTED (circuit exceeds the simulation budget)";
            result.failure_reason = feasibility.reason;
            return result;
        }

        try
        {
            const Stopwatch table_timer;
            const std::vector<std::size_t> marked = marked_candidates(instance);
            result.oracle_table_ms = table_timer.elapsed_ms();
            result.marked_candidates = marked.size();

            const GroverSearchRequest request =
                build_request(instance, marked, config.execution, seed, config.budget.max_qubits);
            const GroverSearchResult search = run_grover_search(request);

            result.executed = true;
            result.grover_iterations = search.total_grover_iterations;
            result.circuit_runs = search.circuit_runs;
            result.measurements = search.measurements;
            result.simulator_gate_operations = search.simulator_gate_count;
            result.total_qubits = search.qubits;
            result.state_vector_bytes = search.state_vector_bytes;
            result.simulator_ms = search.simulation_wall_ms;
            result.backend = search.backend;

            if (search.found)
            {
                result.secret_recovered = true;
                result.recovered_index = search.found_index;
                result.recovered_secret =
                    educational::decode_toy_lwe_candidate(static_cast<std::uint64_t>(search.found_index));
                result.status = "RECOVERED the toy Module-LWE secret by a custom Grover candidate search";
            }
            else
            {
                result.status = "NOT RECOVERED within the attempt budget";
                result.failure_reason = search.failure_reason;
            }
        }
        catch (const std::exception& exception)
        {
            result.executed = false;
            result.status = "ERROR during the simulation";
            result.failure_reason = exception.what();
        }
        return result;
    }

    ToyModuleLweSingleRun run_toy_module_lwe_single_circuit(
        const educational::ToyLwePublicInstance& instance,
        const quantum::QuantumExecutionOptions& execution,
        const std::uint64_t seed, const std::size_t qubit_budget)
    {
        const std::vector<std::size_t> marked = marked_candidates(instance);
        GroverSearchRequest request = build_request(instance, marked, execution, seed, qubit_budget);
        // A fixed iteration count makes the per-backend comparison run identical work.
        request.strategy = GroverStrategy::KnownSolutionCount;
        request.assumed_solution_count = marked.empty() ? 1.0 : static_cast<double>(marked.size());
        request.max_attempts = 1U;
        request.fall_back_to_unknown_count = false;

        const GroverSearchResult search = run_grover_search(request);
        ToyModuleLweSingleRun single;
        single.simulator_ms = search.simulation_wall_ms;
        single.total_qubits = search.qubits;
        single.backend = search.backend;
        return single;
    }
}
