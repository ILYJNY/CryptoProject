#include "ToyAesGroverAttack.h"

#include "AttackCommon.h"
#include "EducationalQuantumAttack/Engine/ResourceModel.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"

#include <algorithm>
#include <exception>
#include <sstream>
#include <vector>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        [[nodiscard]] std::string aes_oracle_cost(const educational::ToyAesPublicInstance& instance)
        {
            const std::size_t aad_blocks = (instance.associated_data.size() + 15U) / 16U;
            const std::size_t ciphertext_blocks = (instance.ciphertext.ciphertext.size() + 15U) / 16U;
            std::ostringstream text;
            text << "One oracle call is one reversible AES-128-GCM tag verification of the public record "
                    "under a superposed key: the AES-128 key schedule, 2 AES-128 block encryptions (the "
                    "GHASH key E_k(0) and the tag mask E_k(J0)), " << (aad_blocks + ciphertext_blocks + 1U)
                 << " multiplications in GF(2^128) for GHASH and a 128-bit tag comparison, computed and "
                    "then uncomputed. The elementary-gate count, depth and workspace qubits of that "
                    "circuit are NOT MODELED by this project.";
            return text.str();
        }

        void add_reference_scenario(AttackResult& report, const HardwareScenario& scenario)
        {
            const auto estimate = quantum::estimate_quantum_resources(quantum::CryptoTarget::AES, 128U);
            ReferenceScenario& reference = report.reference;
            reference.included = true;
            reference.title = "Full AES-128 key search (theory only; NOT simulated; NOT the toy instance above)";
            reference.lines.emplace_back("Key space", "2^128 keys");
            reference.lines.emplace_back(
                "Search register", std::to_string(estimate.estimated_register_qubits) + " logical qubits");
            reference.lines.emplace_back(
                "Ideal Grover iterations (pi/4 * 2^64)",
                format_number(static_cast<long double>(estimate.generic_search_iterations)));
            reference.lines.emplace_back(
                "Scenario time at the assumed rate",
                format_seconds(static_cast<long double>(estimate.generic_search_iterations) *
                               scenario.seconds_per_grover_iteration));
            reference.lines.emplace_back("Oracle circuit cost", "NOT MODELED");
            reference.lines.emplace_back("State-vector simulation", "impossible (2^128 amplitudes)");
            reference.disclaimer =
                "A closed-formula illustration from the existing QuantumResourceModel. It is shown only "
                "to contrast with the 12-bit toy key space and is not an attack result.";
        }
    }

    ToyAesGroverAttack attack_toy_aes_with_grover(
        const educational::ToyAesPublicInstance& instance,
        const QuantumAttackConfig& config,
        const std::uint64_t seed)
    {
        ToyAesGroverAttack result;
        AttackResult& report = result.report;
        report.kind = AttackKind::AesKeySearch;
        report.id = "toy_aes_grover";
        report.algorithm_family = "Grover";
        report.algorithm =
            "Grover search over the restricted key space, R = floor(pi / (4 * asin(sqrt(M/N)))) iterations";
        report.mathematical_problem =
            "Unstructured search: find the key k among N = 2^n candidates for which AES-128-GCM "
            "authenticates the public record.";
        report.applicability =
            "Valid for this toy only: the AES primitive is real AES-128-GCM, but all except n key bits "
            "are fixed to zero and publicly known. Grover gives a quadratic speed-up in oracle calls, "
            "about sqrt(N) instead of N; it does not break AES-128 with an unrestricted key.";
        report.circuit_implemented = true;

        const std::size_t unknown_bits = instance.unknown_bits;
        report.target = "Toy AES: AES-128-GCM with " + std::to_string(unknown_bits) + " unknown key bits";
        report.parameters.emplace_back("Unknown key bits n", std::to_string(unknown_bits));
        report.parameters.emplace_back("Ciphertext bytes", std::to_string(instance.ciphertext.ciphertext.size()));
        report.parameters.emplace_back("GCM nonce", hex_string(instance.ciphertext.nonce));
        report.parameters.emplace_back("GCM tag", hex_string(instance.ciphertext.tag));
        report.parameters.emplace_back(
            "Associated data (Toy SHA digest of the message)", hex_string(instance.associated_data));

        if (unknown_bits < 4U || unknown_bits > 16U)
        {
            report.execution = ExecutionStatus::Error;
            report.execution_note = "Invalid toy AES instance: the unknown key size must be 4 to 16 bits.";
            report.outcome = AttackOutcome::Failed;
            return result;
        }
        const std::size_t key_space = std::size_t{1} << unknown_bits;
        report.parameters.emplace_back("Key space N = 2^n", std::to_string(key_space));
        report.parameters.emplace_back(
            "Fixed key bits", std::to_string(128U - unknown_bits) + " bits fixed to zero (public in this toy)");

        report.assumptions.push_back(
            "Exactly one key authenticates the record (M = 1). With a 128-bit GCM tag the expected number "
            "of other authenticating keys is about (N - 1) * 2^-128.");
        report.assumptions.push_back(scenario_assumption_text(config.scenario));
        report.limitations.push_back(
            "The oracle is simulated through a classically built truth table. A real attack would need a "
            "reversible AES-128-GCM verification circuit, whose cost is NOT MODELED.");
        report.limitations.push_back(
            "The simulator runtime measures a classical computer simulating 2^n amplitudes; it is not the "
            "running time of a quantum computer.");

        const SimulationFeasibility feasibility =
            check_simulation_budget(unknown_bits, GroverWorkingMemoryFactor, config.budget);
        const ResolvedBackend backend = resolve_backend(config.execution);
        quantum::QuantumBackendStatistics statistics{};
        std::uint64_t model_iterations = optimal_grover_iterations(static_cast<double>(key_space), 1.0);
        std::uint64_t model_runs = 1U;
        std::uint64_t model_deepest = model_iterations;
        bool executed = false;

        if (!feasibility.feasible)
        {
            mark_not_executed(report, feasibility.reason);
        }
        else
        {
            const auto cpu_before = process_cpu_time_ms();
            try
            {
                // Simulation-only step: evaluate the real predicate on every candidate to obtain
                // the oracle's truth table.
                const Stopwatch table_timer;
                std::vector<std::size_t> marked;
                for (std::size_t candidate = 0U; candidate < key_space; ++candidate)
                {
                    if (educational::toy_aes_candidate_matches(instance, static_cast<std::uint32_t>(candidate)))
                        marked.push_back(candidate);
                }
                const double table_ms = table_timer.elapsed_ms();

                GroverSearchRequest request;
                request.search_qubits = unknown_bits;
                request.marked_indices = marked;
                request.classical_verifier = [&instance](const std::size_t candidate)
                {
                    return educational::toy_aes_candidate_matches(instance, static_cast<std::uint32_t>(candidate));
                };
                request.strategy = GroverStrategy::KnownSolutionCount;
                request.assumed_solution_count = 1.0;
                request.max_attempts = std::max<std::size_t>(1U, config.max_quantum_attempts);
                request.seed = seed;
                request.execution = backend.options;
                request.simulator_qubit_limit = config.budget.max_qubits;

                const GroverSearchResult search = run_grover_search(request);
                executed = true;
                statistics = search.backend;
                report.execution = ExecutionStatus::Simulated;
                report.simulator_executed = true;
                report.execution_note = feasibility.reason;

                std::ostringstream table_text;
                table_text << "Simulated oracle: truth table built classically with " << key_space
                           << " real AES-128-GCM verifications; " << marked.size()
                           << " candidate key(s) authenticate the record. " << aes_oracle_cost(instance);
                write_simulated_grover(report, search, table_ms, table_text.str());

                report.notes.push_back(search.strategy_description + ".");
                for (std::size_t index = 0U; index < search.attempts.size(); ++index)
                {
                    const GroverAttempt& attempt = search.attempts[index];
                    std::ostringstream line;
                    line << "Circuit run " << (index + 1U) << ": " << attempt.iterations
                         << " Grover iterations; probability of measuring a marked key (read from the "
                            "simulated state) = " << format_probability(attempt.success_probability)
                         << "; measured candidate " << attempt.measured_index << " -> "
                         << (attempt.verified ? "authenticates the record" : "rejected by AES-GCM");
                    report.notes.push_back(line.str());
                }
                report.notes.push_back(
                    "Marked keys in the simulated oracle: M = " + std::to_string(marked.size()) +
                    " (assumed M = 1).");

                model_iterations = search.total_grover_iterations;
                model_runs = search.circuit_runs;
                model_deepest = 0U;
                for (const GroverAttempt& attempt : search.attempts)
                    model_deepest = std::max(model_deepest, attempt.iterations);

                if (search.found)
                {
                    const auto candidate = static_cast<std::uint32_t>(search.found_index);
                    result.recovered_key = educational::toy_aes_candidate_key(candidate, unknown_bits);
                    const auto plaintext = standard::AES128GCM::decrypt(
                        result.recovered_key, instance.ciphertext, instance.associated_data);
                    result.recovered_plaintext.assign(plaintext.begin(), plaintext.end());
                    result.key_recovered = true;
                    report.outcome = AttackOutcome::Succeeded;
                    report.verified_against_public_instance = true;
                    report.recovered.emplace_back("Candidate index", std::to_string(search.found_index));
                    report.recovered.emplace_back("AES-128 key", hex_string(result.recovered_key));
                    report.recovered.emplace_back("Decrypted plaintext", printable(result.recovered_plaintext));
                }
                else
                {
                    report.outcome = AttackOutcome::Failed;
                    report.execution_note += " Attack failed: " + search.failure_reason;
                }
            }
            catch (const std::exception& exception)
            {
                mark_error(report, exception.what());
            }
            const auto cpu_after = process_cpu_time_ms();
            report.time.simulator_cpu_time_ms = (cpu_before.has_value() && cpu_after.has_value())
                ? Metric::measured(static_cast<long double>(*cpu_after - *cpu_before),
                                   "process CPU time, all threads, oracle table plus simulation")
                : Metric::unknown("process CPU time is not available on this platform");
        }

        // Logical resource model (computed, never executed).
        const GroverLogicalCost cost =
            grover_logical_cost(unknown_bits, model_iterations, model_runs, model_deepest);
        write_grover_logical_model(
            report.logical_model, cost, aes_oracle_cost(instance),
            Metric::not_applicable("Grover key search needs no quantum-accessible memory"));
        if (!executed)
        {
            report.logical_model.scope +=
                " Because the circuit was not executed, the counts assume one ideal run with M = 1.";
        }

        // B. Estimated quantum attack time.
        write_grover_time_estimate(
            report.time, model_iterations, config.scenario,
            executed ? "all circuit runs of this attack" : "one ideal run, M = 1");

        // C. Classical attack runtime: the existing exhaustive key search on the same record.
        if (config.run_classical_baselines)
        {
            const Stopwatch classical_timer;
            const educational::ToyAesAnalysis classical = educational::analyze_toy_aes(instance);
            report.time.classical_attack_runtime_ms = Metric::measured(
                static_cast<long double>(classical_timer.elapsed_ms()), "wall time on this CPU, single thread");
            report.time.classical_attack_work = Metric::measured(
                static_cast<long double>(classical.candidates_tested), "candidate keys tested");
            report.time.classical_attack_description =
                std::string("Existing educational::analyze_toy_aes on the same record: sequential AES-GCM "
                            "trial decryption that stops at the first authenticating key (status ") +
                classical.status + ").";
        }
        else
        {
            report.time.classical_attack_runtime_ms = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_work = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_description = "Classical baseline disabled in the configuration.";
        }

        fill_compute_resources(report.compute, backend, statistics, feasibility, executed);
        if (config.include_reference_scenarios) add_reference_scenario(report, config.scenario);
        return result;
    }
}
