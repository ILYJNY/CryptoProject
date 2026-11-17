#pragma once

// Real custom quantum attack on the toy Module-LWE secret (CryptoProject 2.3.5).
//
// This is an ACTUAL executed attack, not a resource estimate, and it is NOT Shor: Module-LWE
// is not a factoring or discrete-logarithm problem, so Shor does not apply. Instead this is a
// bespoke Grover secret-candidate search over the finite candidate space of the toy scheme:
//
//   - the secret is a vector of n*k = 8 coefficients in {-1, 0, 1}, so there are 3^8 = 6561
//     candidates, encoded by a base-3 index in a ceil(log2 6561) = 13-qubit register;
//   - the oracle marks the candidate(s) s for which b - A*s has every centered coefficient in
//     {-1, 0, 1}, i.e. the real toy-LWE verification predicate;
//   - Grover amplifies the marked candidate(s); the measured candidate is verified classically.
//
// It runs on QuantumSimulator through GroverEngine. The oracle is applied through a truth
// table built by evaluating the real predicate on every candidate (a classical step the
// simulation needs); the oracle's internal reversible circuit is not modeled.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Educational/ModuleLWE/ToyModuleLWE.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto::educational_quantum_attack
{
    struct ToyModuleLweGroverAttack
    {
        bool executed = false;
        bool secret_recovered = false;
        std::string status;

        educational::ToyModuleSmallVector recovered_secret{};
        std::uint64_t recovered_index = 0U;

        std::uint64_t candidate_space = 0U;         // 3^(n*k) = 6561
        std::uint64_t marked_candidates = 0U;       // how many candidates the oracle marks
        std::size_t search_qubits = 0U;             // ceil(log2 candidate_space)
        std::uint64_t grover_iterations = 0U;       // = oracle calls, summed over circuit runs
        std::uint64_t circuit_runs = 0U;
        std::uint64_t measurements = 0U;
        std::uint64_t simulator_gate_operations = 0U;
        std::size_t total_qubits = 0U;
        std::size_t state_vector_bytes = 0U;

        double oracle_table_ms = 0.0;               // classical truth-table construction (simulation-only)
        double simulator_ms = 0.0;                  // state-vector simulation wall time
        quantum::QuantumBackendStatistics backend{};
        std::string failure_reason;
    };

    // Attacks the public toy Module-LWE instance. `seed` drives the Grover measurement sampling.
    [[nodiscard]] ToyModuleLweGroverAttack attack_toy_module_lwe_with_grover(
        const educational::ToyLwePublicInstance& instance,
        const QuantumAttackConfig& config,
        std::uint64_t seed);

    // One Grover circuit with a fixed iteration count, for the per-backend timing harness.
    struct ToyModuleLweSingleRun
    {
        double simulator_ms = 0.0;
        std::size_t total_qubits = 0U;
        quantum::QuantumBackendStatistics backend{};
    };

    [[nodiscard]] ToyModuleLweSingleRun run_toy_module_lwe_single_circuit(
        const educational::ToyLwePublicInstance& instance,
        const quantum::QuantumExecutionOptions& execution,
        std::uint64_t seed, std::size_t qubit_budget = 26U);
}
