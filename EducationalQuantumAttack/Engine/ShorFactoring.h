#pragma once

// Real Shor integer factoring on the state-vector simulator (CryptoProject 2.3.5).
//
// This is an ACTUAL executed attack, not a resource estimate. It factors the given modulus
// N by quantum order finding:
//
//   1. pick a base a coprime to N,
//   2. run iterative (one-control-qubit) quantum phase estimation of the modular-
//      multiplication operator U_a |y> = |a*y mod N> on an n-qubit work register, which
//      measures an integer y approximating s/r * 2^t for the order r of a modulo N,
//   3. recover a candidate order r from y by continued fractions,
//   4. if r is even and a^(r/2) != -1 (mod N), gcd(a^(r/2) +/- 1, N) is a non-trivial factor.
//
// Shor's algorithm is probabilistic: a measurement can fail to yield a useful order, so the
// driver tries several bases and a few measurement shots per base and combines the recovered
// order divisors by least common multiple, exactly as the textbook algorithm prescribes.
//
// The quantum part (phase estimation) runs on QuantumSimulator through PhaseEstimationEngine.
// The modular-multiplication operator is applied as one exact reversible permutation of the
// work-register basis states; its decomposition into elementary gates is not simulated (the
// register is small by design). n = number of bits of N, so the circuit uses n + 1 qubits.
//
// Feasible on a classical simulator only for small moduli: n + 1 qubits means a 2^(n+1)
// state vector. The caller's qubit budget bounds n.

#include "QuantumAttack/Backend/QuantumBackendTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto::educational_quantum_attack
{
    struct ShorFactoringAttempt
    {
        std::uint64_t base = 0U;                // a
        std::uint64_t measured_phase = 0U;      // y, the integer read from the phase register
        std::uint64_t candidate_order = 0U;     // order divisor recovered from this measurement
        std::uint64_t combined_order = 0U;      // lcm of divisors seen for this base so far
        bool yielded_factor = false;
        double simulator_ms = 0.0;              // wall time of this phase-estimation circuit
    };

    struct ShorFactoringResult
    {
        bool factored = false;
        bool executed = false;                  // false only if the circuit exceeded the budget
        std::string status;                     // human-readable outcome
        std::string failure_reason;

        std::uint64_t modulus = 0U;             // N
        std::size_t modulus_bits = 0U;          // n
        std::uint64_t factor_p = 0U;
        std::uint64_t factor_q = 0U;

        std::uint64_t winning_base = 0U;        // the a that produced the factor
        std::uint64_t recovered_order = 0U;     // the order r of the winning base

        std::size_t work_qubits = 0U;           // n
        std::size_t total_qubits = 0U;          // n + 1 (one reused control qubit)
        std::size_t phase_bits = 0U;            // t = 2n measured phase bits per run
        std::uint64_t controlled_modular_multiplications = 0U; // simulated controlled U^(2^j)
        std::uint64_t measurements = 0U;
        std::uint64_t simulator_gate_operations = 0U;

        std::vector<ShorFactoringAttempt> attempts;
        double total_simulator_ms = 0.0;        // classical simulation wall time (all attempts)
        double permutation_table_ms = 0.0;      // classical table construction (simulation-only)
        quantum::QuantumBackendStatistics backend{};
        std::size_t state_vector_bytes = 0U;
    };

    struct ShorFactoringOptions
    {
        quantum::QuantumExecutionOptions execution{};
        std::uint64_t seed = 1U;
        std::size_t max_bases = 20U;            // distinct bases a to try
        std::size_t shots_per_base = 2U;        // phase-estimation runs per base
        std::size_t qubit_budget = 26U;         // refuse if n + 1 exceeds this
    };

    // Factors `modulus` (which must be an odd composite that fits the budget). Throws
    // std::invalid_argument for a modulus that is trivially out of range.
    [[nodiscard]] ShorFactoringResult run_shor_factoring(
        std::uint64_t modulus, const ShorFactoringOptions& options);

    // Runs one phase-estimation circuit for a fixed base, for the per-backend timing harness.
    // Returns the measured phase and the circuit's measured simulation time. Does no
    // continued-fraction post-processing.
    struct ShorFactoringSingleRun
    {
        std::uint64_t measured_phase = 0U;
        double simulator_ms = 0.0;
        std::size_t total_qubits = 0U;
        quantum::QuantumBackendStatistics backend{};
    };

    [[nodiscard]] ShorFactoringSingleRun run_shor_factoring_single_circuit(
        std::uint64_t modulus, std::uint64_t base,
        const quantum::QuantumExecutionOptions& execution,
        std::uint64_t seed, std::size_t qubit_budget = 26U);
}
