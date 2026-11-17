#include "QuantumSimulator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>

namespace crypto::quantum
{
    namespace
    {
        using Clock = std::chrono::steady_clock;

        [[nodiscard]] double elapsed_ms(const Clock::time_point start)
        {
            return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        }

        [[nodiscard]] std::size_t checked_state_count(const std::size_t qubits)
        {
            if (qubits >= std::numeric_limits<std::size_t>::digits)
            {
                throw std::length_error("The requested state vector cannot be represented by size_t.");
            }
            return std::size_t{1} << qubits;
        }
    }

    QuantumSimulator::QuantumSimulator(
        const std::size_t qubits,
        const std::size_t maximum_qubits,
        QuantumExecutionOptions options)
        : qubits_(qubits), execution_options_(options)
    {
        if (qubits == 0U)
        {
            throw std::invalid_argument("A quantum register must contain at least one qubit.");
        }
        if (qubits > maximum_qubits)
        {
            throw std::length_error("The requested qubit count exceeds the configured simulator limit.");
        }
        amplitudes_.assign(checked_state_count(qubits), Complex{});
        amplitudes_[0] = Complex{1.0, 0.0};
        set_execution_options(options);
    }

    QuantumSimulator::~QuantumSimulator() = default;

    void QuantumSimulator::set_execution_options(QuantumExecutionOptions options)
    {
        // Synchronize before changing or destroying a backend that may own the newest state.
        sync_host_from_cuda();
        cuda_backend_.reset();
        multi_gpu_backend_.reset();
        cuda_state_valid_ = false;
        cuda_state_newer_ = false;
        multi_gpu_state_valid_ = false;
        multi_gpu_state_newer_ = false;
        accounted_cuda_timing_ = {};
        accounted_multi_gpu_timing_ = {};

        execution_options_ = options;
        std::size_t requested_threads = options.cpu_threads;
        if (options.backend == QuantumBackendType::CpuSingleThread) requested_threads = 1U;
        cpu_backend_ = std::make_unique<cpu::CPUQuantumBackend>(requested_threads);
        backend_statistics_.cpu_threads_used = cpu_backend_->thread_count();
        backend_statistics_.gpu_device_used = -1;

        backend_statistics_.gpu_devices_used.clear();
        if (options.backend == QuantumBackendType::CudaGpu)
        {
            cuda_backend_ = std::make_unique<cuda_backend::CUDAQuantumBackend>(options.gpu_device);
            cuda_backend_->upload(amplitudes_);
            cuda_state_valid_ = true;
            backend_statistics_.gpu_device_used = options.gpu_device;
            backend_statistics_.gpu_devices_used = {options.gpu_device};
            record_cuda_operation();
        }
        else if (options.backend == QuantumBackendType::CudaMultiGpu)
        {
            multi_gpu_backend_ = std::make_unique<cuda_backend::CUDAMultiGpuQuantumBackend>(
                qubits_, options.gpu_devices);
            multi_gpu_backend_->upload(amplitudes_);
            multi_gpu_state_valid_ = true;
            backend_statistics_.gpu_devices_used = multi_gpu_backend_->device_indices();
            backend_statistics_.gpu_device_used = backend_statistics_.gpu_devices_used.empty()
                ? -1 : backend_statistics_.gpu_devices_used.front();
            record_multi_gpu_operation();
        }
    }

    const QuantumExecutionOptions& QuantumSimulator::execution_options() const noexcept
    {
        return execution_options_;
    }

    const QuantumBackendStatistics& QuantumSimulator::backend_statistics() const noexcept
    {
        return backend_statistics_;
    }

    std::size_t QuantumSimulator::qubit_count() const noexcept { return qubits_; }
    std::size_t QuantumSimulator::basis_state_count() const noexcept { return amplitudes_.size(); }
    std::size_t QuantumSimulator::state_vector_bytes() const noexcept { return amplitudes_.size() * sizeof(Complex); }
    std::size_t QuantumSimulator::gate_count() const noexcept { return gate_count_; }
    std::size_t QuantumSimulator::operation_depth() const noexcept { return operation_depth_; }
    std::size_t QuantumSimulator::measurement_count() const noexcept { return measurement_count_; }

    const std::vector<Complex>& QuantumSimulator::state() const
    {
        sync_host_from_cuda();
        return amplitudes_;
    }

    void QuantumSimulator::ensure_cuda_state() const
    {
        if (!cuda_backend_)
        {
            throw std::runtime_error("The CUDA quantum backend is not selected.");
        }
        if (!cuda_state_valid_)
        {
            cuda_backend_->upload(amplitudes_);
            cuda_state_valid_ = true;
            cuda_state_newer_ = false;
            record_cuda_operation();
        }
    }

    void QuantumSimulator::ensure_multi_gpu_state() const
    {
        if (!multi_gpu_backend_)
        {
            throw std::runtime_error("The multi-GPU quantum backend is not selected.");
        }
        if (!multi_gpu_state_valid_)
        {
            multi_gpu_backend_->upload(amplitudes_);
            multi_gpu_state_valid_ = true;
            multi_gpu_state_newer_ = false;
            record_multi_gpu_operation();
        }
    }

    void QuantumSimulator::sync_host_from_cuda() const
    {
        if (cuda_backend_ && cuda_state_newer_)
        {
            cuda_backend_->download(amplitudes_);
            cuda_state_newer_ = false;
            cuda_state_valid_ = true;
            record_cuda_operation();
        }
        if (multi_gpu_backend_ && multi_gpu_state_newer_)
        {
            multi_gpu_backend_->download(amplitudes_);
            multi_gpu_state_newer_ = false;
            multi_gpu_state_valid_ = true;
            record_multi_gpu_operation();
        }
    }

    void QuantumSimulator::mark_host_state_modified() noexcept
    {
        cuda_state_valid_ = false;
        cuda_state_newer_ = false;
        multi_gpu_state_valid_ = false;
        multi_gpu_state_newer_ = false;
    }

    void QuantumSimulator::record_cpu_operation(const double elapsed) noexcept
    {
        ++backend_statistics_.cpu_operations;
        backend_statistics_.cpu_wall_time_ms += elapsed;
    }

    void QuantumSimulator::record_cuda_operation() const noexcept
    {
        if (!cuda_backend_) return;
        const cuda_backend::CudaQuantumTiming& current = cuda_backend_->timing();
        backend_statistics_.gpu_kernel_time_ms += current.kernel_time_ms - accounted_cuda_timing_.kernel_time_ms;
        backend_statistics_.gpu_transfer_time_ms += current.transfer_time_ms - accounted_cuda_timing_.transfer_time_ms;
        backend_statistics_.gpu_initialization_time_ms += current.initialization_time_ms - accounted_cuda_timing_.initialization_time_ms;
        backend_statistics_.gpu_qft_fused_stage_count += current.qft_fused_stage_count - accounted_cuda_timing_.qft_fused_stage_count;
        backend_statistics_.gpu_qft_swap_count += current.qft_swap_kernel_count - accounted_cuda_timing_.qft_swap_kernel_count;
        backend_statistics_.gpu_pinned_host_memory_used = backend_statistics_.gpu_pinned_host_memory_used || current.used_pinned_host_memory;
        accounted_cuda_timing_.kernel_time_ms = current.kernel_time_ms;
        accounted_cuda_timing_.transfer_time_ms = current.transfer_time_ms;
        accounted_cuda_timing_.initialization_time_ms = current.initialization_time_ms;
        accounted_cuda_timing_.qft_fused_stage_count = current.qft_fused_stage_count;
        accounted_cuda_timing_.qft_swap_kernel_count = current.qft_swap_kernel_count;
        accounted_cuda_timing_.used_pinned_host_memory = current.used_pinned_host_memory;
        backend_statistics_.gpu_device_used = cuda_backend_->device_index();
    }

    void QuantumSimulator::record_multi_gpu_operation() const noexcept
    {
        if (!multi_gpu_backend_) return;
        const auto& current = multi_gpu_backend_->timing();
        backend_statistics_.gpu_kernel_time_ms += current.kernel_time_ms - accounted_multi_gpu_timing_.kernel_time_ms;
        backend_statistics_.gpu_transfer_time_ms += current.transfer_time_ms - accounted_multi_gpu_timing_.transfer_time_ms;
        backend_statistics_.gpu_initialization_time_ms += current.initialization_time_ms - accounted_multi_gpu_timing_.initialization_time_ms;
        backend_statistics_.gpu_inter_gpu_transfer_time_ms += current.inter_gpu_transfer_time_ms - accounted_multi_gpu_timing_.inter_gpu_transfer_time_ms;
        backend_statistics_.gpu_parallel_kernel_wall_time_ms += current.parallel_kernel_wall_time_ms - accounted_multi_gpu_timing_.parallel_kernel_wall_time_ms;
        backend_statistics_.gpu_peer_copy_count += current.peer_copy_count - accounted_multi_gpu_timing_.peer_copy_count;
        backend_statistics_.gpu_host_staged_copy_count += current.host_staged_copy_count - accounted_multi_gpu_timing_.host_staged_copy_count;
        backend_statistics_.gpu_qft_fused_stage_count += current.qft_fused_stage_count - accounted_multi_gpu_timing_.qft_fused_stage_count;
        backend_statistics_.gpu_qft_swap_count += current.qft_swap_operation_count - accounted_multi_gpu_timing_.qft_swap_operation_count;
        backend_statistics_.gpu_pinned_host_memory_used = backend_statistics_.gpu_pinned_host_memory_used || current.used_pinned_host_memory;
        accounted_multi_gpu_timing_ = current;
    }

    void QuantumSimulator::reset_zero()
    {
        std::fill(amplitudes_.begin(), amplitudes_.end(), Complex{});
        amplitudes_[0] = Complex{1.0, 0.0};
        mark_host_state_modified();
        gate_count_ = 0U;
        operation_depth_ = 0U;
        measurement_count_ = 0U;
    }

    void QuantumSimulator::set_basis_state(const std::size_t basis_index)
    {
        if (basis_index >= amplitudes_.size())
        {
            throw std::out_of_range("The basis-state index is outside the register.");
        }
        std::fill(amplitudes_.begin(), amplitudes_.end(), Complex{});
        amplitudes_[basis_index] = Complex{1.0, 0.0};
        mark_host_state_modified();
        gate_count_ = 0U;
        operation_depth_ = 0U;
        measurement_count_ = 0U;
    }

    void QuantumSimulator::validate_qubit(const std::size_t qubit) const
    {
        if (qubit >= qubits_) throw std::out_of_range("The qubit index is outside the register.");
    }

    void QuantumSimulator::apply_x(const std::size_t target)
    {
        validate_qubit(target);
        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_x(target);
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_x(target);
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_x(amplitudes_, target);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_z(const std::size_t target)
    {
        validate_qubit(target);
        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_z(target);
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_z(target);
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_z(amplitudes_, target);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_hadamard(const std::size_t target)
    {
        validate_qubit(target);
        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_hadamard(target);
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_hadamard(target);
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_hadamard(amplitudes_, target);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_cnot(const std::size_t control, const std::size_t target)
    {
        validate_qubit(control);
        validate_qubit(target);
        if (control == target) throw std::invalid_argument("CNOT control and target must be different qubits.");
        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_cnot(control, target);
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_cnot(control, target);
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_cnot(amplitudes_, control, target);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_phase_flip(const std::size_t basis_index)
    {
        if (basis_index >= amplitudes_.size()) throw std::out_of_range("The phase-flip basis index is outside the register.");
        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_phase_flip(basis_index);
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_phase_flip(basis_index);
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_phase_flip(amplitudes_, basis_index);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_controlled_permutation(
        const std::size_t control_qubit,
        const std::vector<std::size_t>& target_qubits,
        const std::vector<std::size_t>& permutation)
    {
        sync_host_from_cuda();
        const auto start = Clock::now();
        cpu_backend_->apply_controlled_permutation(
            amplitudes_, qubits_, control_qubit, target_qubits, permutation);
        record_cpu_operation(elapsed_ms(start));
        mark_host_state_modified();
        ++gate_count_;
        ++operation_depth_;
        if (execution_options_.backend == QuantumBackendType::CudaGpu ||
            execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ++backend_statistics_.cpu_fallback_operations;
        }
    }

    void QuantumSimulator::apply_diffusion()
    {
        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_diffusion();
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_diffusion();
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_diffusion(amplitudes_);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_hadamard_gpu(
        const std::size_t target, const int device_index, QuantumGpuTiming& timing)
    {
        validate_qubit(target);
        sync_host_from_cuda();
        cuda_backend::CUDAQuantumBackend temporary(device_index);
        temporary.upload(amplitudes_);
        temporary.apply_hadamard(target);
        temporary.download(amplitudes_);
        const auto& gpu_timing = temporary.timing();
        timing = {gpu_timing.kernel_time_ms, gpu_timing.transfer_time_ms, gpu_timing.initialization_time_ms};
        backend_statistics_.gpu_kernel_time_ms += timing.kernel_time_ms;
        backend_statistics_.gpu_transfer_time_ms += timing.transfer_time_ms;
        backend_statistics_.gpu_initialization_time_ms += timing.initialization_time_ms;
        backend_statistics_.gpu_device_used = device_index;
        ++backend_statistics_.gpu_operations;
        mark_host_state_modified();
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_phase_flip_gpu(
        const std::size_t basis_index, const int device_index, QuantumGpuTiming& timing)
    {
        if (basis_index >= amplitudes_.size()) throw std::out_of_range("The phase-flip basis index is outside the register.");
        sync_host_from_cuda();
        cuda_backend::CUDAQuantumBackend temporary(device_index);
        temporary.upload(amplitudes_);
        temporary.apply_phase_flip(basis_index);
        temporary.download(amplitudes_);
        const auto& gpu_timing = temporary.timing();
        timing = {gpu_timing.kernel_time_ms, gpu_timing.transfer_time_ms, gpu_timing.initialization_time_ms};
        backend_statistics_.gpu_kernel_time_ms += timing.kernel_time_ms;
        backend_statistics_.gpu_transfer_time_ms += timing.transfer_time_ms;
        backend_statistics_.gpu_initialization_time_ms += timing.initialization_time_ms;
        backend_statistics_.gpu_device_used = device_index;
        ++backend_statistics_.gpu_operations;
        mark_host_state_modified();
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_diffusion_gpu(const int device_index, QuantumGpuTiming& timing)
    {
        sync_host_from_cuda();
        cuda_backend::CUDAQuantumBackend temporary(device_index);
        temporary.upload(amplitudes_);
        temporary.apply_diffusion();
        temporary.download(amplitudes_);
        const auto& gpu_timing = temporary.timing();
        timing = {gpu_timing.kernel_time_ms, gpu_timing.transfer_time_ms, gpu_timing.initialization_time_ms};
        backend_statistics_.gpu_kernel_time_ms += timing.kernel_time_ms;
        backend_statistics_.gpu_transfer_time_ms += timing.transfer_time_ms;
        backend_statistics_.gpu_initialization_time_ms += timing.initialization_time_ms;
        backend_statistics_.gpu_device_used = device_index;
        ++backend_statistics_.gpu_operations;
        mark_host_state_modified();
        ++gate_count_;
        ++operation_depth_;
    }

    void QuantumSimulator::apply_qft(const std::vector<std::size_t>& target_qubits)
    {
        if (target_qubits.empty()) throw std::invalid_argument("QFT requires at least one target qubit.");
        std::vector<bool> seen(qubits_, false);
        for (const std::size_t q : target_qubits)
        {
            validate_qubit(q);
            if (seen[q]) throw std::invalid_argument("QFT target qubits must be unique.");
            seen[q] = true;
        }

        if (execution_options_.backend == QuantumBackendType::CudaGpu)
        {
            ensure_cuda_state();
            cuda_backend_->apply_qft(target_qubits);
            cuda_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_cuda_operation();
        }
        else if (execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ensure_multi_gpu_state();
            multi_gpu_backend_->apply_qft(target_qubits);
            multi_gpu_state_newer_ = true;
            ++backend_statistics_.gpu_operations;
            record_multi_gpu_operation();
        }
        else
        {
            const auto start = Clock::now();
            cpu_backend_->apply_qft(amplitudes_, qubits_, target_qubits);
            record_cpu_operation(elapsed_ms(start));
            mark_host_state_modified();
        }

        const std::size_t n = target_qubits.size();
        gate_count_ += n + (n * (n - 1U)) / 2U + 3U * (n / 2U);
        ++operation_depth_;
    }

    void QuantumSimulator::apply_phase_shift(const std::size_t target, const double angle_radians)
    {
        validate_qubit(target);
        if (!std::isfinite(angle_radians))
            throw std::invalid_argument("The phase-shift angle must be finite.");
        // The CUDA backends expose a controlled-phase kernel but no single-qubit phase
        // kernel, so this gate uses the CPU reference path, as controlled permutations do.
        sync_host_from_cuda();
        const auto start = Clock::now();
        cpu_backend_->apply_phase_shift(amplitudes_, target, angle_radians);
        record_cpu_operation(elapsed_ms(start));
        mark_host_state_modified();
        ++gate_count_;
        ++operation_depth_;
        if (execution_options_.backend == QuantumBackendType::CudaGpu ||
            execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ++backend_statistics_.cpu_fallback_operations;
        }
    }

    QubitMeasurement QuantumSimulator::measure_qubit(const std::size_t target, const double uniform_sample)
    {
        validate_qubit(target);
        if (!(uniform_sample >= 0.0 && uniform_sample < 1.0))
            throw std::invalid_argument("The measurement sample must lie in the interval [0, 1).");
        sync_host_from_cuda();
        const auto start = Clock::now();

        QubitMeasurement result;
        result.probability_of_one = std::clamp(
            cpu_backend_->probability_of_one(amplitudes_, target), 0.0, 1.0);
        result.outcome = uniform_sample < result.probability_of_one;
        result.outcome_probability = result.outcome
            ? result.probability_of_one : 1.0 - result.probability_of_one;
        if (!(result.outcome_probability > 0.0))
            throw std::runtime_error("The sampled measurement outcome has zero probability.");
        cpu_backend_->collapse_qubit(amplitudes_, target, result.outcome, result.outcome_probability);

        record_cpu_operation(elapsed_ms(start));
        mark_host_state_modified();
        ++measurement_count_;
        ++operation_depth_;
        if (execution_options_.backend == QuantumBackendType::CudaGpu ||
            execution_options_.backend == QuantumBackendType::CudaMultiGpu)
        {
            ++backend_statistics_.cpu_fallback_operations;
        }
        return result;
    }

    std::vector<double> QuantumSimulator::probabilities() const
    {
        sync_host_from_cuda();
        std::vector<double> result;
        result.reserve(amplitudes_.size());
        for (const Complex& amplitude : amplitudes_) result.push_back(std::norm(amplitude));
        return result;
    }

    std::string QuantumSimulator::basis_label(const std::size_t index) const
    {
        std::string label(qubits_, '0');
        for (std::size_t bit = 0; bit < qubits_; ++bit)
            if ((index & (std::size_t{1} << bit)) != 0U) label[qubits_ - bit - 1U] = '1';
        return label;
    }

    MeasurementResult QuantumSimulator::measure_all(const std::size_t shots, const std::uint64_t seed) const
    {
        if (shots == 0U) throw std::invalid_argument("Measurement shots must be greater than zero.");
        const auto probability = probabilities();
        std::vector<double> cumulative(probability.size(), 0.0);
        std::partial_sum(probability.begin(), probability.end(), cumulative.begin());
        if (cumulative.empty() || cumulative.back() <= 0.0)
            throw std::runtime_error("The quantum state has zero total probability.");
        cumulative.back() = 1.0;

        std::mt19937_64 generator(seed);
        std::uniform_real_distribution<double> distribution(0.0, 1.0);
        MeasurementResult result;
        result.shots = shots;
        for (std::size_t shot = 0; shot < shots; ++shot)
        {
            const double sample = distribution(generator);
            const auto found = std::lower_bound(cumulative.begin(), cumulative.end(), sample);
            const std::size_t index = static_cast<std::size_t>(std::distance(cumulative.begin(), found));
            ++result.counts[basis_label(std::min(index, amplitudes_.size() - 1U))];
        }
        return result;
    }
}
