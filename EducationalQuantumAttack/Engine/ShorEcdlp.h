#pragma once

// Real Shor elliptic-curve discrete-logarithm attack on the state-vector simulator
// (CryptoProject 2.3.5). This is an ACTUAL executed attack, not a resource estimate.
//
// Given the toy curve's base point G (of order r) and a public point Q = kG, it recovers
// the secret scalar k by quantum phase estimation of the point-translation operators:
//
//   - the work register holds one of the r points of <G>, each encoded by an index that is
//     assigned by enumerating the subgroup through real coordinate arithmetic;
//   - stage 1 estimates the phase of the "+G" translation, giving an integer y_G ~ s/r * 2^t;
//   - stage 2 estimates the phase of the "+Q" = "+kG" translation on the collapsed
//     eigenvector, giving y_Q ~ k*s/r * 2^t;
//   - k is the integer in [1, r) for which (k * y_G) mod 2^t best matches y_Q, and it is
//     verified honestly by checking k*G == Q with coordinate arithmetic.
//
// The translations are computed by elliptic-curve point addition on coordinates and a
// coordinate->index lookup, so the simulation never uses the secret k. The register needs
// ceil(log2 r) qubits plus one reused control qubit.

#include "QuantumAttack/Backend/QuantumBackendTypes.h"

#include "CryptoSystem/Educational/ECC/ToyECC.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto::educational_quantum_attack
{
    struct ShorEcdlpAttempt
    {
        std::uint64_t phase_generator = 0U;     // y_G
        std::uint64_t phase_public = 0U;        // y_Q
        std::uint32_t candidate_scalar = 0U;
        bool verified = false;                  // candidate_scalar * G == Q
        double simulator_ms = 0.0;
    };

    struct ShorEcdlpResult
    {
        bool recovered = false;
        bool executed = false;
        std::string status;
        std::string failure_reason;

        // Echoed curve and instance parameters (all intermediate inputs of the attack).
        std::uint32_t field_prime = 0U;
        std::uint32_t coefficient_a = 0U;
        std::uint32_t coefficient_b = 0U;
        std::uint32_t base_x = 0U;
        std::uint32_t base_y = 0U;
        std::uint32_t base_point_order = 0U;
        std::uint32_t public_x = 0U;
        std::uint32_t public_y = 0U;

        std::uint32_t recovered_scalar = 0U;

        std::size_t register_qubits = 0U;       // ceil(log2 r)
        std::size_t total_qubits = 0U;          // register + 1 control
        std::size_t phase_bits = 0U;            // t = 2 * register_qubits per stage
        std::size_t point_table_size = 0U;      // number of enumerated points of <G>
        std::uint64_t controlled_point_additions = 0U;
        std::uint64_t measurements = 0U;
        std::uint64_t simulator_gate_operations = 0U;

        std::vector<ShorEcdlpAttempt> attempts;
        double total_simulator_ms = 0.0;
        double permutation_table_ms = 0.0;      // classical point-table construction (simulation-only)
        quantum::QuantumBackendStatistics backend{};
        std::size_t state_vector_bytes = 0U;
    };

    struct ShorEcdlpOptions
    {
        quantum::QuantumExecutionOptions execution{};
        std::uint64_t seed = 1U;
        std::size_t max_shots = 8U;             // retry until a verified scalar is found
        std::size_t qubit_budget = 26U;
    };

    [[nodiscard]] ShorEcdlpResult run_shor_ecdlp(
        const educational::ToyEccPublicInstance& instance, const ShorEcdlpOptions& options);

    // One two-stage phase-estimation circuit, for the per-backend timing harness.
    struct ShorEcdlpSingleRun
    {
        std::uint64_t phase_generator = 0U;
        std::uint64_t phase_public = 0U;
        double simulator_ms = 0.0;
        std::size_t total_qubits = 0U;
        quantum::QuantumBackendStatistics backend{};
    };

    [[nodiscard]] ShorEcdlpSingleRun run_shor_ecdlp_single_circuit(
        const educational::ToyEccPublicInstance& instance,
        const quantum::QuantumExecutionOptions& execution,
        std::uint64_t seed, std::size_t qubit_budget = 26U);
}
