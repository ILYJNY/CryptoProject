#pragma once

#include <cstddef>
#include <cstdint>

namespace crypto::cuda_backend
{
    struct CudaCryptoTiming
    {
        double kernel_time_ms = 0.0;
        double transfer_time_ms = 0.0;
        double initialization_time_ms = 0.0;
    };

    // One SHA-256 work item per message. Each message must be <= 55 bytes so
    // it fits in one padded SHA-256 block. Messages use a fixed 55-byte stride.
    void sha256_short_batch(
        int device_index,
        const std::uint8_t* messages,
        const std::uint8_t* lengths,
        std::uint8_t* digests,
        std::size_t message_count,
        CudaCryptoTiming& timing);
}
