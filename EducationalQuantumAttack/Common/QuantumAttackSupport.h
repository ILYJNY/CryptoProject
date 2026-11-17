#pragma once

// Small utilities shared by the quantum attack engines: provenance-aware formatting,
// process measurements, backend resolution and the simulation budget check.

#include "QuantumAttackTypes.h"

#include "QuantumAttack/Backend/QuantumBackendTypes.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace crypto::educational_quantum_attack
{
    // ---- formatting ---------------------------------------------------------------------

    [[nodiscard]] std::string_view metric_kind_label(MetricKind kind) noexcept;
    // "1234 [computed]" or "NOT MODELED"; an absent value is never rendered as a number.
    [[nodiscard]] std::string format_metric(const Metric& metric, std::string_view unit = {});
    // The bare value for a CSV cell, or the status text when no value exists.
    [[nodiscard]] std::string metric_cell(const Metric& metric);
    [[nodiscard]] std::string format_number(long double value);
    [[nodiscard]] std::string format_bytes(long double bytes);
    // Probabilities need more digits than other numbers: 0.99995 must not print as 1.
    [[nodiscard]] std::string format_probability(double probability);
    [[nodiscard]] std::string format_seconds(long double seconds);

    [[nodiscard]] std::string_view attack_kind_label(AttackKind kind) noexcept;
    [[nodiscard]] std::string_view execution_status_label(ExecutionStatus status) noexcept;
    [[nodiscard]] std::string_view attack_outcome_label(AttackOutcome outcome) noexcept;
    [[nodiscard]] std::string_view set_status_label(SetStatus status) noexcept;
    [[nodiscard]] std::string_view set_file_stem(SetId id) noexcept;
    [[nodiscard]] std::string backend_label(quantum::QuantumBackendType backend);

    // ---- integer helpers ----------------------------------------------------------------

    [[nodiscard]] std::size_t ceil_log2(std::uint64_t value) noexcept;      // smallest n with 2^n >= value
    [[nodiscard]] std::size_t bit_length(std::uint64_t value) noexcept;     // number of significant bits
    [[nodiscard]] std::uint64_t gcd_u64(std::uint64_t left, std::uint64_t right) noexcept;
    [[nodiscard]] std::uint64_t mod_mul(std::uint64_t left, std::uint64_t right, std::uint64_t modulus) noexcept;
    [[nodiscard]] std::uint64_t mod_pow(std::uint64_t base, std::uint64_t exponent, std::uint64_t modulus) noexcept;
    // Modular inverse; returns std::nullopt when gcd(value, modulus) != 1.
    [[nodiscard]] std::optional<std::uint64_t> mod_inverse(std::uint64_t value, std::uint64_t modulus) noexcept;

    // ---- randomness ---------------------------------------------------------------------

    // Returns config_seed, or a fresh operating-system seed when config_seed is 0.
    [[nodiscard]] std::uint64_t resolve_seed(std::uint64_t config_seed);
    // Deterministically derives an independent stream seed for one attack.
    [[nodiscard]] std::uint64_t derive_seed(std::uint64_t root_seed, std::string_view label) noexcept;

    // ---- process measurements -----------------------------------------------------------

    // CPU time consumed by this process (all threads, user + kernel) in milliseconds.
    [[nodiscard]] std::optional<double> process_cpu_time_ms();
    // Peak resident memory of this process. This is a process-wide high-water mark: it can
    // only grow, so it bounds the memory of an attack from above rather than isolating it.
    [[nodiscard]] std::optional<std::uint64_t> process_peak_memory_bytes();

    class Stopwatch final
    {
    public:
        Stopwatch() : start_(std::chrono::steady_clock::now()) {}
        [[nodiscard]] double elapsed_ms() const
        {
            return std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - start_).count();
        }

    private:
        std::chrono::steady_clock::time_point start_;
    };

    // ---- backend resolution -------------------------------------------------------------

    struct ResolvedBackend
    {
        quantum::QuantumExecutionOptions options{};
        std::string requested;
        std::string used;
        bool gpu_requested = false;
        bool gpu_available = false;
        std::string gpu_status = "NOT USED (CPU backend selected)";
        std::string gpu_device;
    };

    // Maps the requested backend to one that can run in this build. When a CUDA backend is
    // requested but unavailable, the simulation runs on the CPU and is labeled as CPU; a
    // CPU run is never reported as a GPU run.
    [[nodiscard]] ResolvedBackend resolve_backend(const quantum::QuantumExecutionOptions& requested);

    // ---- simulation budget --------------------------------------------------------------

    struct SimulationFeasibility
    {
        bool feasible = false;
        std::size_t qubits = 0U;
        std::uint64_t state_vector_bytes = 0U;      // saturates at UINT64_MAX
        std::uint64_t working_memory_bytes = 0U;    // saturates at UINT64_MAX
        std::string reason;
    };

    // Working-set multipliers relative to the state vector, derived from what the existing
    // simulator allocates: Grover-type circuits need the state, the probability vector and
    // the cumulative distribution (2x); controlled-permutation circuits additionally need
    // the simulator's state snapshot, gather buffer and index tables (3x).
    inline constexpr unsigned GroverWorkingMemoryFactor = 2U;
    inline constexpr unsigned ControlledPermutationWorkingMemoryFactor = 3U;

    [[nodiscard]] SimulationFeasibility check_simulation_budget(
        std::size_t qubits, unsigned working_memory_factor, const SimulationBudget& budget);

    // Fills the compute-resource section shared by every executed attack.
    void fill_compute_resources(
        ComputeResources& compute,
        const ResolvedBackend& backend,
        const quantum::QuantumBackendStatistics& statistics,
        const SimulationFeasibility& feasibility,
        bool executed);

    void report_progress(const QuantumAttackConfig& config, const std::string& message);
}
