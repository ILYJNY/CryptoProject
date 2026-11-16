#include "CUDAQuantumBackend.h"

#include <stdexcept>
#include <string>

namespace crypto::quantum::cuda_backend
{
    struct CUDAQuantumBackend::Impl
    {
        int device = 0;
        std::size_t count = 0U;
        CudaQuantumTiming timing{};
    };

    namespace
    {
        [[noreturn]] void unavailable()
        {
            throw std::runtime_error("CUDA quantum backend is not available in this build. Enable QUANTUM_ENABLE_CUDA and configure a CUDA compiler.");
        }
    }

    CUDAQuantumBackend::CUDAQuantumBackend(const int device_index)
        : impl_(std::make_unique<Impl>())
    {
        impl_->device = device_index;
        unavailable();
    }

    CUDAQuantumBackend::~CUDAQuantumBackend() = default;
    bool CUDAQuantumBackend::is_available() noexcept { return false; }
    int CUDAQuantumBackend::device_index() const noexcept { return impl_->device; }
    std::size_t CUDAQuantumBackend::state_size() const noexcept { return impl_->count; }
    const CudaQuantumTiming& CUDAQuantumBackend::timing() const noexcept { return impl_->timing; }
    void CUDAQuantumBackend::upload(const std::vector<Complex>&) { unavailable(); }
    void CUDAQuantumBackend::download(std::vector<Complex>&) { unavailable(); }
    void CUDAQuantumBackend::apply_x(std::size_t) { unavailable(); }
    void CUDAQuantumBackend::apply_z(std::size_t) { unavailable(); }
    void CUDAQuantumBackend::apply_hadamard(std::size_t) { unavailable(); }
    void CUDAQuantumBackend::apply_cnot(std::size_t, std::size_t) { unavailable(); }
    void CUDAQuantumBackend::apply_controlled_phase(std::size_t, std::size_t, double) { unavailable(); }
    void CUDAQuantumBackend::apply_qft(const std::vector<std::size_t>&) { unavailable(); }
    void CUDAQuantumBackend::apply_phase_flip(std::size_t) { unavailable(); }
    void CUDAQuantumBackend::apply_diffusion() { unavailable(); }
}
