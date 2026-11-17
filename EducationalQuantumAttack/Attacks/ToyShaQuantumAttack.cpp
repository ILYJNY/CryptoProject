#include "ToyShaQuantumAttack.h"

#include "AttackCommon.h"
#include "CryptoSystem/Educational/SHA/ToySha256.h"
#include "EducationalQuantumAttack/Engine/ResourceModel.h"
#include "QuantumAttack/Standard/Models/QuantumResourceModel.h"

#include <algorithm>
#include <cmath>
#include <exception>
#include <numbers>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace crypto::educational_quantum_attack
{
    namespace
    {
        constexpr std::size_t kMinimumToyShaBits = 4U;
        constexpr std::size_t kMaximumToyShaBits = 16U;
        // A preimage search over 2^(b + extra) messages contains 2^extra preimages on average.
        constexpr std::size_t kInitialExtraDomainBits = 2U;
        constexpr std::size_t kMaximumExtraDomainBits = 4U;

        [[nodiscard]] std::size_t decimal_digits(std::uint64_t value)
        {
            std::size_t digits = 1U;
            while (value >= 10U)
            {
                value /= 10U;
                ++digits;
            }
            return digits;
        }

        // Statement about the cost of one oracle call that hashes a family message.
        [[nodiscard]] std::string sha_oracle_cost(
            const std::string_view prefix, const std::uint64_t largest_counter,
            const std::size_t output_bits, const std::string& after_hash)
        {
            const std::size_t longest_message = prefix.size() + decimal_digits(largest_counter);
            // SHA-256 pads with one 0x80 byte and an 8-byte length, so 55 bytes fit one block.
            const std::size_t blocks = (longest_message + 9U + 63U) / 64U;
            std::ostringstream text;
            text << "One oracle call is one reversible Toy SHA evaluation on a superposed message counter: "
                    "writing the counter in decimal into the message block, " << blocks
                 << " SHA-256 compression call(s) of 64 rounds each (messages of this family are at most "
                 << longest_message << " bytes), truncation to the leading " << output_bits << " bits, "
                 << after_hash << ", and uncomputation. The elementary-gate count, depth and workspace "
                    "qubits of that circuit are NOT MODELED by this project.";
            return text.str();
        }

        void merge(GroverSearchResult& total, const GroverSearchResult& run)
        {
            total.found = run.found;
            total.found_index = run.found_index;
            total.attempts.insert(total.attempts.end(), run.attempts.begin(), run.attempts.end());
            total.strategy_description = run.strategy_description;
            total.failure_reason = run.failure_reason;
            total.planned_iterations = run.planned_iterations;
            total.total_grover_iterations += run.total_grover_iterations;
            total.classical_verifications += run.classical_verifications;
            total.circuit_runs += run.circuit_runs;
            total.hadamard_gates += run.hadamard_gates;
            total.phase_flip_operations += run.phase_flip_operations;
            total.diffusion_operations += run.diffusion_operations;
            total.measurements += run.measurements;
            total.simulator_gate_count += run.simulator_gate_count;
            total.deepest_run_operation_depth =
                std::max(total.deepest_run_operation_depth, run.deepest_run_operation_depth);
            total.qubits = run.qubits;
            total.state_vector_bytes = run.state_vector_bytes;
            total.simulation_wall_ms += run.simulation_wall_ms;
            total.backend.cpu_operations += run.backend.cpu_operations;
            total.backend.gpu_operations += run.backend.gpu_operations;
            total.backend.cpu_fallback_operations += run.backend.cpu_fallback_operations;
            total.backend.cpu_wall_time_ms += run.backend.cpu_wall_time_ms;
            total.backend.gpu_kernel_time_ms += run.backend.gpu_kernel_time_ms;
            total.backend.gpu_transfer_time_ms += run.backend.gpu_transfer_time_ms;
            total.backend.gpu_initialization_time_ms += run.backend.gpu_initialization_time_ms;
            total.backend.cpu_threads_used = run.backend.cpu_threads_used;
            total.backend.gpu_device_used = run.backend.gpu_device_used;
            total.backend.gpu_devices_used = run.backend.gpu_devices_used;
        }

        [[nodiscard]] std::uint64_t deepest_iterations(const GroverSearchResult& search)
        {
            std::uint64_t deepest = 0U;
            for (const GroverAttempt& attempt : search.attempts) deepest = std::max(deepest, attempt.iterations);
            return deepest;
        }

        void measure_cpu_time(AttackResult& report, const std::optional<double>& before)
        {
            const auto after = process_cpu_time_ms();
            report.time.simulator_cpu_time_ms = (before.has_value() && after.has_value())
                ? Metric::measured(static_cast<long double>(*after - *before),
                                   "process CPU time, all threads, oracle table plus simulation")
                : Metric::unknown("process CPU time is not available on this platform");
        }
    }

    // =====================================================================================
    // Preimage: Grover
    // =====================================================================================

    ToyShaPreimageAttack attack_toy_sha_preimage_with_grover(
        const std::uint32_t target_digest,
        const std::size_t output_bits,
        const std::string_view family_prefix,
        const QuantumAttackConfig& config,
        const std::uint64_t seed)
    {
        ToyShaPreimageAttack result;
        AttackResult& report = result.report;
        report.kind = AttackKind::ShaPreimage;
        report.id = "toy_sha_preimage_grover";
        report.algorithm_family = "Grover";
        report.algorithm =
            "Grover preimage search with an unknown number of preimages "
            "(Boyer-Brassard-Hoyer-Tapp iteration schedule)";
        report.mathematical_problem =
            "Preimage search: given a digest d, find a message m with ToySHA(m) = d, where "
            "ToySHA(m) = the leading b bits of SHA-256(m).";
        report.applicability =
            "Valid for the b-bit truncated digest only. Grover needs about (pi/4) * 2^(b/2) oracle calls "
            "for one preimage; for the full 256-bit digest that is about 2^128. This is a PREIMAGE "
            "attack and is reported separately from the collision attack.";
        report.circuit_implemented = true;
        report.target = "Toy SHA: SHA-256 truncated to " + std::to_string(output_bits) + " bits (preimage)";
        report.parameters.emplace_back("Digest bits b", std::to_string(output_bits));
        report.parameters.emplace_back("Target digest d", hex_value(target_digest, 4U));
        report.parameters.emplace_back("Message family", std::string(family_prefix) + "<decimal counter>");

        if (output_bits < kMinimumToyShaBits || output_bits > kMaximumToyShaBits ||
            target_digest >= (std::uint32_t{1} << output_bits))
        {
            report.execution = ExecutionStatus::Error;
            report.execution_note =
                "Invalid Toy SHA preimage target: the digest must have 4 to 16 bits and fit in them.";
            report.outcome = AttackOutcome::Failed;
            return result;
        }

        report.assumptions.push_back(
            "SHA-256 behaves like a random function on the message family, so a domain of 2^(b+e) "
            "messages holds 2^e preimages on average; the true count is unknown to the attacker.");
        report.assumptions.push_back(scenario_assumption_text(config.scenario));
        report.limitations.push_back(
            "The oracle is simulated through a classically built truth table. A real attack would need a "
            "reversible SHA-256 circuit, whose cost is NOT MODELED.");
        report.limitations.push_back(
            "The found message is another message with the target digest; it need not be the original "
            "message, which is not uniquely determined by a b-bit digest.");

        const ResolvedBackend backend = resolve_backend(config.execution);
        quantum::QuantumBackendStatistics statistics{};
        std::size_t register_bits = output_bits + kInitialExtraDomainBits;
        SimulationFeasibility feasibility =
            check_simulation_budget(register_bits, GroverWorkingMemoryFactor, config.budget);
        const double expected_initial_solutions = std::ldexp(1.0, static_cast<int>(kInitialExtraDomainBits));
        std::uint64_t model_iterations = optimal_grover_iterations(
            std::ldexp(1.0, static_cast<int>(register_bits)), expected_initial_solutions);
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
                GroverSearchResult total;
                double table_ms = 0.0;
                std::size_t marked_in_final_domain = 0U;
                std::uint64_t domain_seed = seed;

                for (std::size_t extra = kInitialExtraDomainBits; extra <= kMaximumExtraDomainBits; ++extra)
                {
                    const std::size_t bits = output_bits + extra;
                    const SimulationFeasibility domain_budget =
                        check_simulation_budget(bits, GroverWorkingMemoryFactor, config.budget);
                    if (!domain_budget.feasible)
                    {
                        report.notes.push_back(
                            "A larger search domain was needed but is outside the simulation budget: " +
                            domain_budget.reason);
                        break;
                    }
                    register_bits = bits;
                    feasibility = domain_budget;
                    const std::size_t domain = std::size_t{1} << bits;

                    // Simulation-only step: the oracle's truth table over the whole domain.
                    const Stopwatch table_timer;
                    std::vector<std::size_t> marked;
                    for (std::size_t counter = 0U; counter < domain; ++counter)
                    {
                        if (educational::truncated_sha256(
                                educational::toy_sha_family_message(family_prefix, counter), output_bits) ==
                            target_digest)
                        {
                            marked.push_back(counter);
                        }
                    }
                    table_ms += table_timer.elapsed_ms();
                    marked_in_final_domain = marked.size();

                    GroverSearchRequest request;
                    request.search_qubits = bits;
                    request.marked_indices = marked;
                    request.classical_verifier = [&](const std::size_t counter)
                    {
                        return educational::truncated_sha256(
                                   educational::toy_sha_family_message(family_prefix, counter), output_bits) ==
                               target_digest;
                    };
                    request.strategy = GroverStrategy::UnknownSolutionCount;
                    request.seed = domain_seed;
                    request.execution = backend.options;
                    request.simulator_qubit_limit = config.budget.max_qubits;

                    const GroverSearchResult search = run_grover_search(request);
                    merge(total, search);
                    executed = true;

                    std::ostringstream line;
                    line << "Search domain of 2^" << bits << " messages (counters 0 to " << (domain - 1U)
                         << "): the simulated oracle marks " << marked.size() << " preimage(s); "
                         << search.attempts.size() << " circuit run(s), " << search.total_grover_iterations
                         << " Grover iterations -> " << (search.found ? "preimage found" : "no preimage found");
                    report.notes.push_back(line.str());
                    if (search.found) break;
                    domain_seed = derive_seed(domain_seed, "next preimage domain");
                }

                statistics = total.backend;
                report.execution = ExecutionStatus::Simulated;
                report.simulator_executed = true;
                report.execution_note = feasibility.reason;
                report.parameters.emplace_back(
                    "Search register", std::to_string(register_bits) + " qubits (2^" +
                    std::to_string(register_bits) + " candidate messages)");

                std::ostringstream table_text;
                table_text << "Simulated oracle: truth table built classically with real SHA-256 evaluations "
                              "over every searched domain; " << marked_in_final_domain
                           << " preimage(s) in the final domain. "
                           << sha_oracle_cost(family_prefix, (std::uint64_t{1} << register_bits) - 1U,
                                              output_bits, "comparison with the target digest");
                write_simulated_grover(report, total, table_ms, table_text.str());
                report.notes.push_back(total.strategy_description + ".");
                report.notes.push_back(
                    "For comparison, with a known preimage count M the ideal iteration count would be "
                    "floor(pi / (4 * asin(sqrt(M/N)))) = " +
                    std::to_string(optimal_grover_iterations(
                        std::ldexp(1.0, static_cast<int>(register_bits)),
                        static_cast<double>(std::max<std::size_t>(1U, marked_in_final_domain)))) +
                    " for the actual M in the final domain.");

                model_iterations = total.total_grover_iterations;
                model_runs = total.circuit_runs;
                model_deepest = deepest_iterations(total);

                if (total.found)
                {
                    result.preimage_found = true;
                    result.message_counter = total.found_index;
                    result.message = educational::toy_sha_family_message(family_prefix, total.found_index);
                    report.outcome = AttackOutcome::Succeeded;
                    report.verified_against_public_instance = true;
                    report.recovered.emplace_back("Preimage message", printable(result.message));
                    report.recovered.emplace_back(
                        "Toy SHA of the preimage",
                        hex_value(educational::truncated_sha256(result.message, output_bits), 4U));
                }
                else
                {
                    report.outcome = AttackOutcome::Failed;
                    report.execution_note += " Attack failed: " + total.failure_reason;
                }
            }
            catch (const std::exception& exception)
            {
                mark_error(report, exception.what());
            }
            measure_cpu_time(report, cpu_before);
        }

        const std::string oracle_cost = sha_oracle_cost(
            family_prefix, (std::uint64_t{1} << register_bits) - 1U, output_bits,
            "comparison with the target digest");
        const GroverLogicalCost cost =
            grover_logical_cost(register_bits, model_iterations, model_runs, model_deepest);
        write_grover_logical_model(
            report.logical_model, cost, oracle_cost,
            Metric::not_applicable("Grover preimage search needs no quantum-accessible memory"));
        if (!executed)
        {
            report.logical_model.scope +=
                " Because the circuit was not executed, the counts assume one ideal run on a 2^(b+2) domain "
                "with the expected 4 preimages.";
        }
        write_grover_time_estimate(
            report.time, model_iterations, config.scenario,
            executed ? "all circuit runs of this attack" : "one ideal run");

        if (config.run_classical_baselines)
        {
            const Stopwatch classical_timer;
            const educational::TruncatedHashPreimage classical = educational::find_truncated_sha256_preimage(
                target_digest, output_bits, std::uint64_t{1} << register_bits, family_prefix);
            report.time.classical_attack_runtime_ms = Metric::measured(
                static_cast<long double>(classical_timer.elapsed_ms()), "wall time on this CPU, single thread");
            report.time.classical_attack_work = Metric::measured(
                static_cast<long double>(classical.attempts), "hash evaluations");
            report.time.classical_attack_description =
                std::string("Classical exhaustive preimage search educational::find_truncated_sha256_preimage "
                            "over the same message family (") +
                (classical.found ? "preimage found" : "no preimage in the domain") + ").";
        }
        else
        {
            report.time.classical_attack_runtime_ms = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_work = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_description = "Classical baseline disabled in the configuration.";
        }

        fill_compute_resources(report.compute, backend, statistics, feasibility, executed);

        if (config.include_reference_scenarios)
        {
            const auto estimate = quantum::estimate_quantum_resources(quantum::CryptoTarget::SHA256, 256U);
            ReferenceScenario& reference = report.reference;
            reference.included = true;
            reference.title = "Full SHA-256 preimage search (theory only; NOT simulated; NOT the toy digest above)";
            reference.lines.emplace_back("Digest bits", "256");
            reference.lines.emplace_back(
                "Search register", std::to_string(estimate.estimated_register_qubits) + " logical qubits");
            reference.lines.emplace_back(
                "Ideal Grover iterations (pi/4 * 2^128)",
                format_number(static_cast<long double>(estimate.generic_search_iterations)));
            reference.lines.emplace_back(
                "Scenario time at the assumed rate",
                format_seconds(static_cast<long double>(estimate.generic_search_iterations) *
                               config.scenario.seconds_per_grover_iteration));
            reference.lines.emplace_back("Oracle circuit cost", "NOT MODELED");
            reference.disclaimer =
                "A closed-formula illustration from the existing QuantumResourceModel; not an attack result.";
        }
        return result;
    }

    // =====================================================================================
    // Collision: Brassard-Hoyer-Tapp
    // =====================================================================================

    ToyShaCollisionAttack attack_toy_sha_collision_with_bht(
        const std::size_t output_bits,
        const std::string_view family_prefix,
        const QuantumAttackConfig& config,
        const std::uint64_t seed)
    {
        ToyShaCollisionAttack result;
        AttackResult& report = result.report;
        report.kind = AttackKind::ShaCollision;
        report.id = "toy_sha_collision_bht";
        report.algorithm_family = "BHT";
        report.algorithm =
            "Brassard-Hoyer-Tapp quantum collision search: a classical table of k ~ 2^(b/3) digests, then "
            "Grover amplitude amplification of a table-membership oracle";
        report.mathematical_problem =
            "Collision search: find two different messages m1 != m2 with ToySHA(m1) = ToySHA(m2). No "
            "target digest is given.";
        report.applicability =
            "Valid for the b-bit truncated digest under the random-function model. BHT uses about "
            "2^(b/3) queries in total, against about 2^(b/2) for the classical birthday search, but only "
            "with a quantum-accessible table of about 2^(b/3) entries. This is a COLLISION attack; it is "
            "not Grover's preimage search and is reported separately from it.";
        report.circuit_implemented = true;
        report.target = "Toy SHA: SHA-256 truncated to " + std::to_string(output_bits) + " bits (collision)";
        report.parameters.emplace_back("Digest bits b", std::to_string(output_bits));
        report.parameters.emplace_back("Message family", std::string(family_prefix) + "<decimal counter>");

        if (output_bits < kMinimumToyShaBits || output_bits > kMaximumToyShaBits)
        {
            report.execution = ExecutionStatus::Error;
            report.execution_note = "Invalid Toy SHA collision target: the digest must have 4 to 16 bits.";
            report.outcome = AttackOutcome::Failed;
            return result;
        }

        const std::size_t register_bits = output_bits;
        const std::size_t domain = std::size_t{1} << register_bits;
        const double digest_space = std::ldexp(1.0, static_cast<int>(output_bits));
        const auto table_size = static_cast<std::size_t>(
            std::max(2.0, std::round(std::cbrt(digest_space))));
        report.parameters.emplace_back(
            "Table size k = round(2^(b/3))", std::to_string(table_size) + " messages (counters " +
            std::to_string(domain) + " to " + std::to_string(domain + table_size - 1U) + ")");
        report.parameters.emplace_back(
            "Search register", std::to_string(register_bits) + " qubits (counters 0 to " +
            std::to_string(domain - 1U) + ", disjoint from the table)");

        report.assumptions.push_back(
            "SHA-256 behaves like a random function on the message family, so the search domain of N "
            "messages holds about N * k / 2^b messages whose digest is in the table.");
        report.assumptions.push_back(
            "The digest table is available as quantum-accessible classical memory (QRAM); its hardware "
            "cost is NOT MODELED.");
        report.assumptions.push_back(scenario_assumption_text(config.scenario));
        report.limitations.push_back(
            "The membership oracle is simulated through a classically built truth table. A real attack "
            "would need a reversible SHA-256 circuit and a superposition table lookup; both are NOT MODELED.");
        report.limitations.push_back(
            "When the cost of the quantum-accessible table is charged, BHT is not known to beat classical "
            "parallel collision search; the 2^(b/3) figure counts queries only.");

        const SimulationFeasibility feasibility =
            check_simulation_budget(register_bits, GroverWorkingMemoryFactor, config.budget);
        const ResolvedBackend backend = resolve_backend(config.execution);
        quantum::QuantumBackendStatistics statistics{};
        std::size_t distinct_table_digests = table_size;
        std::uint64_t model_iterations = optimal_grover_iterations(
            static_cast<double>(domain), static_cast<double>(table_size));
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
                // Step 1 (classical, part of the algorithm): hash k messages into a table.
                std::unordered_map<std::uint32_t, std::uint64_t> table;
                table.reserve(table_size * 2U);
                bool table_collision = false;
                for (std::size_t offset = 0U; offset < table_size; ++offset)
                {
                    const std::uint64_t counter = static_cast<std::uint64_t>(domain) + offset;
                    const std::uint32_t digest = educational::truncated_sha256(
                        educational::toy_sha_family_message(family_prefix, counter), output_bits);
                    if (!table.emplace(digest, counter).second) table_collision = true;
                }
                distinct_table_digests = table.size();
                if (table_collision)
                {
                    report.notes.push_back(
                        "Two of the k table messages already collide. A faithful BHT run would stop here "
                        "with a purely classical collision; this analysis continues with the " +
                        std::to_string(distinct_table_digests) +
                        " distinct digests so that the quantum phase is still demonstrated.");
                }

                // Simulation-only step: truth table of the membership oracle over the domain.
                const Stopwatch table_timer;
                std::vector<std::size_t> marked;
                for (std::size_t counter = 0U; counter < domain; ++counter)
                {
                    const std::uint32_t digest = educational::truncated_sha256(
                        educational::toy_sha_family_message(family_prefix, counter), output_bits);
                    if (table.contains(digest)) marked.push_back(counter);
                }
                const double table_ms = table_timer.elapsed_ms();

                // Step 2 (quantum): Grover over the domain for a message whose digest is in the table.
                const double expected_marked = static_cast<double>(domain) *
                    static_cast<double>(distinct_table_digests) / digest_space;
                GroverSearchRequest request;
                request.search_qubits = register_bits;
                request.marked_indices = marked;
                request.classical_verifier = [&](const std::size_t counter)
                {
                    return table.contains(educational::truncated_sha256(
                        educational::toy_sha_family_message(family_prefix, counter), output_bits));
                };
                request.strategy = GroverStrategy::KnownSolutionCount;
                request.assumed_solution_count = std::max(1.0, expected_marked);
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
                table_text << "Simulated membership oracle: truth table built classically with " << domain
                           << " real SHA-256 evaluations; " << marked.size()
                           << " message(s) of the domain have a digest in the table (expected "
                           << format_number(expected_marked) << "). "
                           << sha_oracle_cost(family_prefix, static_cast<std::uint64_t>(domain) - 1U, output_bits,
                                              "a membership test against the k-entry digest table");
                write_simulated_grover(report, search, table_ms, table_text.str());
                report.simulated.quantum_memory_bits = Metric::computed(
                    static_cast<long double>(distinct_table_digests * output_bits),
                    "digest table the oracle reads in superposition: k distinct digests x b bits; in the "
                    "simulation the table is ordinary classical memory");

                report.notes.push_back(search.strategy_description + ".");
                for (std::size_t index = 0U; index < search.attempts.size(); ++index)
                {
                    const GroverAttempt& attempt = search.attempts[index];
                    std::ostringstream line;
                    line << "Circuit run " << (index + 1U) << ": " << attempt.iterations
                         << " Grover iterations; probability of measuring a marked message (read from the "
                            "simulated state) = " << format_probability(attempt.success_probability)
                         << "; measured counter " << attempt.measured_index << " -> "
                         << (attempt.verified ? "digest is in the table" : "digest is not in the table");
                    report.notes.push_back(line.str());
                }

                const long double classical_birthday =
                    std::sqrt(std::numbers::pi_v<long double> / 2.0L * static_cast<long double>(digest_space));
                std::ostringstream queries;
                queries << "Query count of this run: " << table_size << " classical table queries + "
                        << search.total_grover_iterations << " quantum oracle calls + "
                        << search.classical_verifications << " classical verification queries = "
                        << (table_size + search.total_grover_iterations + search.classical_verifications)
                        << ". Classical birthday search expects about sqrt(pi/2 * 2^b) = "
                        << format_number(classical_birthday) << " queries.";
                report.notes.push_back(queries.str());

                model_iterations = search.total_grover_iterations;
                model_runs = search.circuit_runs;
                model_deepest = deepest_iterations(search);

                if (search.found)
                {
                    result.first_counter = search.found_index;
                    result.first_message =
                        educational::toy_sha_family_message(family_prefix, search.found_index);
                    result.digest = educational::truncated_sha256(result.first_message, output_bits);
                    result.second_counter = table.at(result.digest);
                    result.second_message =
                        educational::toy_sha_family_message(family_prefix, result.second_counter);
                    // The two counters come from disjoint ranges, so the messages differ.
                    const bool verified = result.first_message != result.second_message &&
                        educational::truncated_sha256(result.second_message, output_bits) == result.digest;
                    result.collision_found = verified;
                    report.outcome = verified ? AttackOutcome::Succeeded : AttackOutcome::Failed;
                    report.verified_against_public_instance = verified;
                    report.recovered.emplace_back("Message 1", printable(result.first_message));
                    report.recovered.emplace_back("Message 2", printable(result.second_message));
                    report.recovered.emplace_back("Common Toy SHA digest", hex_value(result.digest, 4U));
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
            measure_cpu_time(report, cpu_before);
        }

        const std::string oracle_cost = sha_oracle_cost(
            family_prefix, static_cast<std::uint64_t>(domain) - 1U, output_bits,
            "a membership test against the k-entry digest table");
        const GroverLogicalCost cost =
            grover_logical_cost(register_bits, model_iterations, model_runs, model_deepest);
        write_grover_logical_model(
            report.logical_model, cost, oracle_cost,
            Metric::computed(static_cast<long double>(distinct_table_digests * output_bits),
                             "quantum-accessible classical memory for the digest table (k x b bits); "
                             "hardware cost NOT MODELED"));
        report.logical_model.scope +=
            " The classical table phase (k hash evaluations) is not a quantum resource and is listed in the notes.";
        if (!executed)
        {
            report.logical_model.scope +=
                " Because the circuit was not executed, the counts assume one ideal run with the expected "
                "number of marked messages.";
        }
        write_grover_time_estimate(
            report.time, model_iterations, config.scenario,
            executed ? "quantum phase only, all circuit runs; the classical table phase is excluded"
                     : "quantum phase only, one ideal run; the classical table phase is excluded");

        if (config.run_classical_baselines)
        {
            const Stopwatch classical_timer;
            const educational::TruncatedHashCollision classical =
                educational::find_truncated_sha256_collision(output_bits, 200000U, family_prefix);
            report.time.classical_attack_runtime_ms = Metric::measured(
                static_cast<long double>(classical_timer.elapsed_ms()), "wall time on this CPU, single thread");
            report.time.classical_attack_work = Metric::measured(
                static_cast<long double>(classical.attempts), "hash evaluations");
            report.time.classical_attack_description =
                std::string("Existing classical birthday search educational::find_truncated_sha256_collision "
                            "over the same message family (") +
                (classical.found ? "collision found" : "no collision found") + ").";
        }
        else
        {
            report.time.classical_attack_runtime_ms = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_work = Metric::not_executed("classical baseline disabled");
            report.time.classical_attack_description = "Classical baseline disabled in the configuration.";
        }

        fill_compute_resources(report.compute, backend, statistics, feasibility, executed);

        if (config.include_reference_scenarios)
        {
            ReferenceScenario& reference = report.reference;
            reference.included = true;
            reference.title = "Full SHA-256 collision search (theory only; NOT simulated; NOT the toy digest above)";
            reference.lines.emplace_back("Digest bits", "256");
            reference.lines.emplace_back("Classical birthday search", "about 2^128 hash evaluations");
            reference.lines.emplace_back("BHT query count", "about 2^(256/3) = 2^85.3 queries");
            reference.lines.emplace_back("BHT quantum-accessible table", "about 2^85.3 digests (hardware cost NOT MODELED)");
            reference.lines.emplace_back("Oracle circuit cost", "NOT MODELED");
            reference.lines.emplace_back("Attack time", "NOT MODELED (depends on the table's hardware cost)");
            reference.disclaimer =
                "Asymptotic query exponents only. They are not an attack-time estimate and not an attack result.";
        }
        return result;
    }
}
