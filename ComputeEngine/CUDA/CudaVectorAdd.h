#pragma once

#include <cstddef>
#include <cstdint>

namespace crypto::cuda_backend
{
    struct CudaVectorAddTiming
    {
        double kernel_time_ms = 0.0;
        double transfer_time_ms = 0.0;
        double initialization_time_ms = 0.0;
    };

    void vector_add_u32(
        int device_index,
        const std::uint32_t* left,
        const std::uint32_t* right,
        std::uint32_t* output,
        std::size_t count,
        CudaVectorAddTiming& timing);
}
