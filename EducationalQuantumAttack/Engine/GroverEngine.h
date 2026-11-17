#pragma once

// Grover amplitude amplification driven on the existing QuantumAttack state-vector
// simulator (QuantumSimulator: Hadamard, basis-state phase flip, diffusion, measurement).
//
// What is simulated: the search register, the Grover iterations and one measurement per
// circuit run. What is NOT simulated: the reversible circuit inside the oracle. The oracle
// acts through its truth table, which the caller builds classically by evaluating the real
// predicate on every candidate. That table exists only because a classical simulator needs
// it; a quantum computer would evaluate the predicate in superposition instead.

#include "QuantumAttack/Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace crypto::educational_quantum_attack
{
    enum class GroverStrategy
    {
        // The number of solutions M is assumed known: run floor(pi / (4 * asin(sqrt(M/N))))
        // iterations, measure once, verify classically, and re-run on a failed verification.
        KnownSolutionCount,
        // M is unknown: Boyer-Brassard-Hoyer-Tapp schedule with randomly chosen iteration
        // counts below an exponentially growing bound.
        UnknownSolutionCount
    };

    struct GroverSearchRequest
    {
        std::size_t search_qubits = 0U;
        // Oracle truth table: the marked basis states of the search register.
        std::vector<std::size_t> marked_indices;
        // The real predicate, applied classically to each measured candidate.
        std::function<bool(std::size_t)> classical_verifier;

        GroverStrategy strategy = GroverStrategy::KnownSolutionCount;
        // Used by KnownSolutionCount. May be a model expectation rather than an integer.
        double assumed_solution_count = 1.0;
        std::size_t max_attempts = 4U;
        // When the known-count strategy exhausts its attempts, continue with the
        // unknown-count schedule instead of giving up.
        bool fall_back_to_unknown_count = true;
        // The unknown-count schedule stops after this multiple of sqrt(N) Grover iterations.
        double unknown_count_timeout_factor = 9.0;

        std::uint64_t seed = 1U;
        quantum::QuantumExecutionOptions execution{};
        std::size_t simulator_qubit_limit = 26U;
    };

    struct GroverAttempt
    {
        std::uint64_t iterations = 0U;
        std::size_t measured_index = 0U;
        // Exact probability, read from the simulated state, that a measurement yields a
        // marked state. A simulator diagnostic: real hardware would not reveal it.
        double success_probability = 0.0;
        bool verified = false;
    };

    struct GroverSearchResult
    {
        bool found = false;
        std::size_t found_index = 0U;
        std::vector<GroverAttempt> attempts;
        std::string strategy_description;
        std::string failure_reason;

        std::uint64_t planned_iterations = 0U;          // known-count strategy only
        std::uint64_t total_grover_iterations = 0U;     // equals the number of quantum oracle calls
        std::uint64_t classical_verifications = 0U;

        // Operations executed on the simulator, summed over every circuit run.
        std::uint64_t circuit_runs = 0U;
        std::uint64_t hadamard_gates = 0U;
        std::uint64_t phase_flip_operations = 0U;       // one per marked state per oracle call
        std::uint64_t diffusion_operations = 0U;
        std::uint64_t measurements = 0U;
        std::uint64_t simulator_gate_count = 0U;        // the simulator's own counter, summed
        std::uint64_t deepest_run_operation_depth = 0U; // sequential simulator operations, deepest run

        std::size_t qubits = 0U;
        std::size_t state_vector_bytes = 0U;
        double simulation_wall_ms = 0.0;
        quantum::QuantumBackendStatistics backend{};
    };

    [[nodiscard]] std::uint64_t optimal_grover_iterations(double search_space, double solutions);
    [[nodiscard]] double grover_success_probability(double search_space, double solutions, std::uint64_t iterations);

    // Throws std::invalid_argument for an invalid request and propagates simulator errors.
    [[nodiscard]] GroverSearchResult run_grover_search(const GroverSearchRequest& request);
}
