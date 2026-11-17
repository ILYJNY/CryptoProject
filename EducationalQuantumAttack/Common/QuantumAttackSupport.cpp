#include "QuantumAttackSupport.h"

#include "ComputeEngine/ComputeEngine.h"
#include "CryptoSetAnalysis/Detail/AttackTimeModel.h"
#include "QuantumAttack/Backend/CUDA/CUDAMultiGpuQuantumBackend.h"
#include "QuantumAttack/Backend/CUDA/CUDAQuantumBackend.h"
#include "Random/SecureRandom.h"

#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>

#if defined(_WIN32)
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <psapi.h>
#elif defined(__linux__) || defined(__APPLE__)
    #include <sys/resource.h>
#endif

namespace crypto::educational_quantum_attack
{
    // ---- formatting ---------------------------------------------------------------------

    std::string_view metric_kind_label(const MetricKind kind) noexcept
    {
        switch (kind)
        {
            case MetricKind::Measured: return "measured";
            case MetricKind::Computed: return "computed";
            case MetricKind::Estimated: return "estimated";
            case MetricKind::NotModeled: return "NOT MODELED";
            case MetricKind::NotApplicable: return "N/A";
            case MetricKind::NotExecuted: return "NOT EXECUTED";
            case MetricKind::Unknown: return "UNKNOWN";
        }
        return "UNKNOWN";
    }

    std::string format_number(const long double value)
    {
        if (!std::isfinite(value)) return "non-finite";
        std::ostringstream out;
        const long double magnitude = std::fabs(value);
        if (magnitude < 1.0e15L && std::floor(value) == value)
        {
            out << std::fixed << std::setprecision(0) << value;
        }
        else if (magnitude >= 1.0e15L || (magnitude > 0.0L && magnitude < 1.0e-3L))
        {
            out << std::scientific << std::setprecision(4) << value;
        }
        else
        {
            out << std::fixed << std::setprecision(3) << value;
        }
        return out.str();
    }

    std::string format_metric(const Metric& metric, const std::string_view unit)
    {
        std::ostringstream out;
        if (metric.has_value())
        {
            out << format_number(metric.value);
            if (!unit.empty()) out << ' ' << unit;
            out << " [" << metric_kind_label(metric.kind) << ']';
        }
        else
        {
            out << metric_kind_label(metric.kind);
        }
        if (!metric.note.empty()) out << " (" << metric.note << ')';
        return out.str();
    }

    std::string metric_cell(const Metric& metric)
    {
        if (!metric.has_value()) return std::string(metric_kind_label(metric.kind));
        std::ostringstream out;
        if (std::isfinite(metric.value) && std::fabs(metric.value) < 1.0e15L &&
            std::floor(metric.value) == metric.value)
        {
            out << std::fixed << std::setprecision(0) << metric.value;
        }
        else
        {
            out << std::setprecision(12) << metric.value;
        }
        return out.str();
    }

    std::string format_bytes(const long double bytes)
    {
        if (!std::isfinite(bytes) || bytes < 0.0L) return "N/A";
        constexpr long double kibibyte = 1024.0L;
        std::ostringstream out;
        if (bytes >= kibibyte * kibibyte * kibibyte * kibibyte * kibibyte)
        {
            // Beyond the pebibyte range a unit prefix no longer helps; print a power of two
            // when the value is one (state vectors are), otherwise scientific notation.
            int exponent = 0;
            const long double mantissa = std::frexp(bytes, &exponent);
            if (mantissa == 0.5L) out << "2^" << (exponent - 1) << " bytes";
            else out << std::scientific << std::setprecision(4) << bytes << " bytes";
            return out.str();
        }
        out << std::fixed << std::setprecision(2);
        if (bytes >= kibibyte * kibibyte * kibibyte * kibibyte)
            out << bytes / (kibibyte * kibibyte * kibibyte * kibibyte) << " TiB";
        else if (bytes >= kibibyte * kibibyte * kibibyte)
            out << bytes / (kibibyte * kibibyte * kibibyte) << " GiB";
        else if (bytes >= kibibyte * kibibyte)
            out << bytes / (kibibyte * kibibyte) << " MiB";
        else if (bytes >= kibibyte)
            out << bytes / kibibyte << " KiB";
        else
            out << std::setprecision(0) << bytes << " bytes";
        return out.str();
    }

    std::string format_probability(const double probability)
    {
        std::ostringstream out;
        out << std::fixed << std::setprecision(6) << probability;
        return out.str();
    }

    std::string format_seconds(const long double seconds)
    {
        // The standard set analysis already owns a duration formatter; reuse it so that
        // both analyses print scenario times in the same style.
        return set_analysis::detail::attack_time_model::format_duration(seconds);
    }

    std::string_view attack_kind_label(const AttackKind kind) noexcept
    {
        switch (kind)
        {
            case AttackKind::AesKeySearch: return "Toy AES";
            case AttackKind::ShaPreimage: return "Toy SHA Preimage";
            case AttackKind::ShaCollision: return "Toy SHA Collision";
            case AttackKind::EccDiscreteLog: return "Toy ECC";
            case AttackKind::RsaFactoring: return "Toy RSA";
            case AttackKind::ModuleLweSecretSearch: return "Toy Module-LWE";
        }
        return "Unknown";
    }

    std::string_view execution_status_label(const ExecutionStatus status) noexcept
    {
        switch (status)
        {
            case ExecutionStatus::Simulated: return "SIMULATED";
            case ExecutionStatus::TheoryOnly: return "THEORY ONLY (NOT EXECUTED)";
            case ExecutionStatus::NotModeled: return "NOT MODELED";
            case ExecutionStatus::Error: return "ERROR";
        }
        return "UNKNOWN";
    }

    std::string_view attack_outcome_label(const AttackOutcome outcome) noexcept
    {
        switch (outcome)
        {
            case AttackOutcome::Succeeded: return "SUCCEEDED";
            case AttackOutcome::Failed: return "FAILED";
            case AttackOutcome::NotAttempted: return "NOT ATTEMPTED";
        }
        return "UNKNOWN";
    }

    std::string_view set_status_label(const SetStatus status) noexcept
    {
        switch (status)
        {
            case SetStatus::AllSucceeded: return "ALL ATTACKS SUCCEEDED";
            case SetStatus::Partial: return "PARTIAL (some attacks not executed or not modeled; none failed)";
            case SetStatus::Failed: return "FAILED (at least one executed attack failed)";
        }
        return "UNKNOWN";
    }

    std::string_view set_file_stem(const SetId id) noexcept
    {
        switch (id)
        {
            case SetId::AesShaEcdsa: return "aes_sha_ecdsa";
            case SetId::AesShaRsaPss: return "aes_sha_rsapss";
            case SetId::ShaAesMlKem: return "sha_aes_mlkem";
        }
        return "unknown_set";
    }

    std::string backend_label(const quantum::QuantumBackendType backend)
    {
        switch (backend)
        {
            case quantum::QuantumBackendType::CpuSingleThread: return "CPU-SINGLE";
            case quantum::QuantumBackendType::CpuMultiThread: return "CPU-MULTI";
            case quantum::QuantumBackendType::CudaGpu: return "CUDA-GPU";
            case quantum::QuantumBackendType::CudaMultiGpu: return "CUDA-MULTI-GPU";
        }
        return "UNKNOWN";
    }

    // ---- integer helpers ----------------------------------------------------------------

    std::size_t ceil_log2(const std::uint64_t value) noexcept
    {
        std::size_t bits = 0U;
        std::uint64_t power = 1U;
        while (power < value && bits < 63U)
        {
            power <<= 1U;
            ++bits;
        }
        return bits;
    }

    std::size_t bit_length(std::uint64_t value) noexcept
    {
        std::size_t bits = 0U;
        while (value != 0U)
        {
            value >>= 1U;
            ++bits;
        }
        return bits;
    }

    std::uint64_t gcd_u64(std::uint64_t left, std::uint64_t right) noexcept
    {
        while (right != 0U)
        {
            const std::uint64_t remainder = left % right;
            left = right;
            right = remainder;
        }
        return left;
    }

    std::uint64_t mod_mul(std::uint64_t left, std::uint64_t right, const std::uint64_t modulus) noexcept
    {
        // Double-and-add keeps every intermediate value below 2 * modulus, so the result is
        // exact for any modulus below 2^63 without a 128-bit integer type.
        if (modulus == 0U) return 0U;
        left %= modulus;
        right %= modulus;
        if (left < (std::uint64_t{1} << 32U) && right < (std::uint64_t{1} << 32U))
            return (left * right) % modulus;
        std::uint64_t result = 0U;
        while (right != 0U)
        {
            if ((right & 1U) != 0U)
            {
                result += left;
                if (result >= modulus) result -= modulus;
            }
            left += left;
            if (left >= modulus) left -= modulus;
            right >>= 1U;
        }
        return result;
    }

    std::uint64_t mod_pow(std::uint64_t base, std::uint64_t exponent, const std::uint64_t modulus) noexcept
    {
        if (modulus == 0U) return 0U;
        if (modulus == 1U) return 0U;
        std::uint64_t result = 1U;
        base %= modulus;
        while (exponent != 0U)
        {
            if ((exponent & 1U) != 0U) result = mod_mul(result, base, modulus);
            exponent >>= 1U;
            base = mod_mul(base, base, modulus);
        }
        return result;
    }

    std::optional<std::uint64_t> mod_inverse(const std::uint64_t value, const std::uint64_t modulus) noexcept
    {
        if (modulus == 0U) return std::nullopt;
        if (modulus == 1U) return std::uint64_t{0};
        // Extended Euclid on signed 64-bit values; the callers use moduli far below 2^62.
        std::int64_t t = 0;
        std::int64_t new_t = 1;
        std::int64_t r = static_cast<std::int64_t>(modulus);
        std::int64_t new_r = static_cast<std::int64_t>(value % modulus);
        while (new_r != 0)
        {
            const std::int64_t quotient = r / new_r;
            const std::int64_t next_t = t - quotient * new_t;
            t = new_t;
            new_t = next_t;
            const std::int64_t next_r = r - quotient * new_r;
            r = new_r;
            new_r = next_r;
        }
        if (r != 1) return std::nullopt;
        if (t < 0) t += static_cast<std::int64_t>(modulus);
        return static_cast<std::uint64_t>(t);
    }

    // ---- randomness ---------------------------------------------------------------------

    std::uint64_t resolve_seed(const std::uint64_t config_seed)
    {
        if (config_seed != 0U) return config_seed;
        std::uint64_t seed = 0U;
        while (seed == 0U) seed = SecureRandom::u64();
        return seed;
    }

    std::uint64_t derive_seed(const std::uint64_t root_seed, const std::string_view label) noexcept
    {
        // FNV-1a over the label, then one SplitMix64 finalization round.
        std::uint64_t hash = 0xCBF29CE484222325ULL ^ root_seed;
        for (const char character : label)
        {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(character));
            hash *= 0x100000001B3ULL;
        }
        hash += 0x9E3779B97F4A7C15ULL;
        hash = (hash ^ (hash >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        hash = (hash ^ (hash >> 27U)) * 0x94D049BB133111EBULL;
        hash ^= hash >> 31U;
        return hash == 0U ? 0x9E3779B97F4A7C15ULL : hash;
    }

    // ---- process measurements -----------------------------------------------------------

    std::optional<double> process_cpu_time_ms()
    {
#if defined(_WIN32)
        FILETIME creation_time{};
        FILETIME exit_time{};
        FILETIME kernel_time{};
        FILETIME user_time{};
        if (GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time, &kernel_time, &user_time) == 0)
            return std::nullopt;
        ULARGE_INTEGER kernel{};
        kernel.LowPart = kernel_time.dwLowDateTime;
        kernel.HighPart = kernel_time.dwHighDateTime;
        ULARGE_INTEGER user{};
        user.LowPart = user_time.dwLowDateTime;
        user.HighPart = user_time.dwHighDateTime;
        // FILETIME counts 100-nanosecond intervals.
        return static_cast<double>(kernel.QuadPart + user.QuadPart) / 10000.0;
#elif defined(__linux__) || defined(__APPLE__)
        struct rusage usage{};
        if (getrusage(RUSAGE_SELF, &usage) != 0) return std::nullopt;
        const double user_ms = static_cast<double>(usage.ru_utime.tv_sec) * 1000.0 +
                               static_cast<double>(usage.ru_utime.tv_usec) / 1000.0;
        const double system_ms = static_cast<double>(usage.ru_stime.tv_sec) * 1000.0 +
                                 static_cast<double>(usage.ru_stime.tv_usec) / 1000.0;
        return user_ms + system_ms;
#else
        return std::nullopt;
#endif
    }

    std::optional<std::uint64_t> process_peak_memory_bytes()
    {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS counters{};
        counters.cb = sizeof(counters);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)) == 0)
            return std::nullopt;
        return static_cast<std::uint64_t>(counters.PeakWorkingSetSize);
#elif defined(__linux__)
        struct rusage usage{};
        if (getrusage(RUSAGE_SELF, &usage) != 0) return std::nullopt;
        // Linux reports ru_maxrss in kibibytes.
        return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024ULL;
#elif defined(__APPLE__)
        struct rusage usage{};
        if (getrusage(RUSAGE_SELF, &usage) != 0) return std::nullopt;
        // macOS reports ru_maxrss in bytes.
        return static_cast<std::uint64_t>(usage.ru_maxrss);
#else
        return std::nullopt;
#endif
    }

    // ---- backend resolution -------------------------------------------------------------

    ResolvedBackend resolve_backend(const quantum::QuantumExecutionOptions& requested)
    {
        ResolvedBackend resolved;
        resolved.options = requested;
        resolved.requested = backend_label(requested.backend);
        resolved.used = resolved.requested;

        const bool single_gpu = requested.backend == quantum::QuantumBackendType::CudaGpu;
        const bool multi_gpu = requested.backend == quantum::QuantumBackendType::CudaMultiGpu;
        if (!single_gpu && !multi_gpu) return resolved;

        resolved.gpu_requested = true;
        const bool available = single_gpu
            ? quantum::cuda_backend::CUDAQuantumBackend::is_available()
            : quantum::cuda_backend::CUDAMultiGpuQuantumBackend::is_available();
        if (!available)
        {
            // Never present a CPU run as a GPU run: switch the backend and say so.
            resolved.options.backend = quantum::QuantumBackendType::CpuMultiThread;
            resolved.used = backend_label(resolved.options.backend);
            resolved.gpu_available = false;
            resolved.gpu_status = ComputeEngine::cuda_compiled()
                ? "UNAVAILABLE (no usable CUDA device for the requested backend); executed on " + resolved.used
                : "UNAVAILABLE (project built without CUDA); executed on " + resolved.used;
            return resolved;
        }

        resolved.gpu_available = true;
        resolved.gpu_status = "AVAILABLE";
        try
        {
            const auto devices = ComputeEngine::discover_gpus();
            std::ostringstream names;
            if (single_gpu)
            {
                for (const auto& device : devices)
                {
                    if (device.index == requested.gpu_device)
                        names << "GPU " << device.index << ": " << device.name
                              << " (" << format_bytes(static_cast<long double>(device.total_memory_bytes)) << ')';
                }
            }
            else
            {
                bool first = true;
                for (const auto& device : devices)
                {
                    if (!first) names << "; ";
                    first = false;
                    names << "GPU " << device.index << ": " << device.name
                          << " (" << format_bytes(static_cast<long double>(device.total_memory_bytes)) << ')';
                }
            }
            resolved.gpu_device = names.str();
        }
        catch (const std::exception&)
        {
            resolved.gpu_device.clear();
        }
        if (resolved.gpu_device.empty()) resolved.gpu_device = "UNKNOWN (device properties could not be read)";
        return resolved;
    }

    // ---- simulation budget --------------------------------------------------------------

    SimulationFeasibility check_simulation_budget(
        const std::size_t qubits, const unsigned working_memory_factor, const SimulationBudget& budget)
    {
        constexpr std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
        constexpr std::uint64_t bytes_per_amplitude = 16U; // two IEEE-754 doubles

        SimulationFeasibility result;
        result.qubits = qubits;
        if (qubits >= 59U)
        {
            result.state_vector_bytes = maximum;
            result.working_memory_bytes = maximum;
        }
        else
        {
            result.state_vector_bytes = bytes_per_amplitude << qubits;
            const std::uint64_t factor = working_memory_factor == 0U ? 1U : working_memory_factor;
            result.working_memory_bytes = result.state_vector_bytes > maximum / factor
                ? maximum : result.state_vector_bytes * factor;
        }

        std::ostringstream reason;
        if (qubits == 0U)
        {
            reason << "The circuit has no qubits.";
        }
        else if (qubits > budget.max_qubits)
        {
            reason << "The circuit needs " << qubits << " simulated qubits, above the configured limit of "
                   << budget.max_qubits << " qubits (state vector alone: "
                   << (result.state_vector_bytes == maximum
                           ? std::string("more than 2^64 bytes")
                           : format_bytes(static_cast<long double>(result.state_vector_bytes)))
                   << ").";
        }
        else if (result.working_memory_bytes > budget.max_working_memory_bytes)
        {
            reason << "The simulation needs about "
                   << format_bytes(static_cast<long double>(result.working_memory_bytes))
                   << " of working memory (state vector "
                   << format_bytes(static_cast<long double>(result.state_vector_bytes))
                   << "), above the configured limit of "
                   << format_bytes(static_cast<long double>(budget.max_working_memory_bytes)) << '.';
        }
        else
        {
            result.feasible = true;
            reason << "Within budget: " << qubits << " qubits, state vector "
                   << format_bytes(static_cast<long double>(result.state_vector_bytes))
                   << ", modeled working memory "
                   << format_bytes(static_cast<long double>(result.working_memory_bytes)) << '.';
        }
        result.reason = reason.str();
        return result;
    }

    void fill_compute_resources(
        ComputeResources& compute,
        const ResolvedBackend& backend,
        const quantum::QuantumBackendStatistics& statistics,
        const SimulationFeasibility& feasibility,
        const bool executed)
    {
        constexpr std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
        compute.backend_requested = backend.requested;
        compute.gpu_requested = backend.gpu_requested;
        compute.gpu_status = backend.gpu_status;
        compute.gpu_device = backend.gpu_device;

        compute.state_vector_bytes = feasibility.state_vector_bytes == maximum
            ? Metric::computed(std::ldexp(16.0L, static_cast<int>(feasibility.qubits)),
                               "16 bytes x 2^qubits; exceeds 64-bit byte counts")
            : Metric::computed(static_cast<long double>(feasibility.state_vector_bytes), "16 bytes x 2^qubits");
        compute.working_memory_bytes = feasibility.working_memory_bytes == maximum
            ? Metric::not_modeled("exceeds 64-bit byte counts")
            : Metric::estimated(static_cast<long double>(feasibility.working_memory_bytes),
                                "state vector plus the simulator's temporary buffers");

        if (!executed)
        {
            compute.backend_used = "NONE (circuit not executed)";
            compute.cpu_threads = Metric::not_executed();
            compute.process_peak_memory_bytes = Metric::not_executed();
            compute.gpu_executed = false;
            // Nothing ran, so nothing "executed on" any backend; say only whether the
            // requested CUDA backend would have been available.
            if (!backend.gpu_requested)
                compute.gpu_status = "NOT USED (circuit not executed)";
            else if (backend.gpu_available)
                compute.gpu_status = "NOT USED (circuit not executed; the requested CUDA backend is available)";
            else
                compute.gpu_status = "NOT USED (circuit not executed; the requested CUDA backend is unavailable)";
            compute.gpu_operations = Metric::not_executed();
            compute.gpu_kernel_ms = Metric::not_executed();
            compute.gpu_transfer_ms = Metric::not_executed();
            compute.cpu_fallback_operations = Metric::not_executed();
            return;
        }

        compute.backend_used = backend.used;
        compute.cpu_threads = Metric::measured(static_cast<long double>(statistics.cpu_threads_used),
                                               "size of the simulator worker pool");
        const auto peak = process_peak_memory_bytes();
        compute.process_peak_memory_bytes = peak.has_value()
            ? Metric::measured(static_cast<long double>(*peak),
                               "process-wide high-water mark; includes everything run earlier in this process")
            : Metric::unknown("peak memory is not available on this platform");

        const bool gpu_backend_active = backend.gpu_requested && backend.gpu_available;
        if (gpu_backend_active)
        {
            compute.gpu_executed = statistics.gpu_operations > 0U;
            compute.gpu_status = compute.gpu_executed
                ? "USED (GPU kernels executed)"
                : "AVAILABLE BUT NOT USED (every operation of this circuit ran on the CPU path)";
            compute.gpu_operations = Metric::measured(static_cast<long double>(statistics.gpu_operations));
            compute.gpu_kernel_ms = Metric::measured(static_cast<long double>(statistics.gpu_kernel_time_ms));
            compute.gpu_transfer_ms = Metric::measured(static_cast<long double>(statistics.gpu_transfer_time_ms));
            compute.cpu_fallback_operations = Metric::measured(
                static_cast<long double>(statistics.cpu_fallback_operations),
                "operations that have no CUDA kernel and ran on the CPU");
        }
        else
        {
            compute.gpu_executed = false;
            compute.gpu_operations = Metric::not_applicable("no GPU execution");
            compute.gpu_kernel_ms = Metric::not_applicable("no GPU execution");
            compute.gpu_transfer_ms = Metric::not_applicable("no GPU execution");
            compute.cpu_fallback_operations = Metric::not_applicable("no GPU backend active");
        }
    }

    void report_progress(const QuantumAttackConfig& config, const std::string& message)
    {
        if (config.progress) config.progress(message);
    }
}
