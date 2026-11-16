#include "CUDAMultiGpuQuantumBackend.h"

#include <stdexcept>
#include <string>
#include <utility>

namespace crypto::quantum::cuda_backend
{
    struct CUDAMultiGpuQuantumBackend::Impl
    {
        std::vector<int> devices;
        std::size_t count = 0U;
        std::size_t local_count = 0U;
        std::size_t distributed_bits = 0U;
        CudaMultiGpuTiming timing{};
    };

    namespace
    {
        [[noreturn]] void unavailable()
        {
            throw std::runtime_error(
                "Multi-GPU quantum backend is unavailable. Enable QUANTUM_ENABLE_CUDA and configure a CUDA compiler.");
        }
    }

    CUDAMultiGpuQuantumBackend::CUDAMultiGpuQuantumBackend(
        const std::size_t, std::vector<int> device_indices)
        : impl_(std::make_unique<Impl>())
    {
        impl_->devices = std::move(device_indices);
        unavailable();
    }

    CUDAMultiGpuQuantumBackend::~CUDAMultiGpuQuantumBackend() = default;
    bool CUDAMultiGpuQuantumBackend::is_available() noexcept { return false; }
    std::vector<int> CUDAMultiGpuQuantumBackend::available_devices() { return {}; }
    const std::vector<int>& CUDAMultiGpuQuantumBackend::device_indices() const noexcept { return impl_->devices; }
    std::size_t CUDAMultiGpuQuantumBackend::state_size() const noexcept { return impl_->count; }
    std::size_t CUDAMultiGpuQuantumBackend::local_state_size() const noexcept { return impl_->local_count; }
    std::size_t CUDAMultiGpuQuantumBackend::distributed_qubit_count() const noexcept { return impl_->distributed_bits; }
    const CudaMultiGpuTiming& CUDAMultiGpuQuantumBackend::timing() const noexcept { return impl_->timing; }
    void CUDAMultiGpuQuantumBackend::upload(const std::vector<Complex>&) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::download(std::vector<Complex>&) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_x(std::size_t) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_z(std::size_t) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_hadamard(std::size_t) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_cnot(std::size_t, std::size_t) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_controlled_phase(std::size_t, std::size_t, double) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_qft(const std::vector<std::size_t>&) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_phase_flip(std::size_t) { unavailable(); }
    void CUDAMultiGpuQuantumBackend::apply_diffusion() { unavailable(); }
}
