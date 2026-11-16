#include "CudaCrypto.h"

#include <cuda_runtime.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace crypto::cuda_backend
{
    namespace
    {
        constexpr std::size_t message_stride = 55U;
        constexpr std::size_t digest_size = 32U;

        __device__ __constant__ std::uint32_t sha256_k[64] = {
            0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
            0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
            0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
            0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
            0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
            0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
            0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
            0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
            0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
            0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
            0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
            0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
            0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
            0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
            0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
            0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
        };

        __device__ __forceinline__ std::uint32_t rotr(const std::uint32_t value, const unsigned int shift)
        {
            return (value >> shift) | (value << (32U - shift));
        }

        __global__ void sha256_short_kernel(
            const std::uint8_t* messages,
            const std::uint8_t* lengths,
            std::uint8_t* digests,
            const std::size_t count)
        {
            const std::size_t message_index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
            if (message_index >= count) return;

            const unsigned int length = lengths[message_index];
            if (length > message_stride) return;

            std::uint8_t block[64];
            for (unsigned int i = 0U; i < 64U; ++i) block[i] = 0U;
            const std::size_t offset = message_index * message_stride;
            for (unsigned int i = 0U; i < length; ++i) block[i] = messages[offset + i];
            block[length] = 0x80U;
            const std::uint64_t bit_length = static_cast<std::uint64_t>(length) * 8ULL;
            for (unsigned int i = 0U; i < 8U; ++i)
            {
                block[63U - i] = static_cast<std::uint8_t>(bit_length >> (8U * i));
            }

            std::uint32_t words[64];
            for (unsigned int i = 0U; i < 16U; ++i)
            {
                const unsigned int j = i * 4U;
                words[i] = (static_cast<std::uint32_t>(block[j]) << 24U) |
                           (static_cast<std::uint32_t>(block[j + 1U]) << 16U) |
                           (static_cast<std::uint32_t>(block[j + 2U]) << 8U) |
                           static_cast<std::uint32_t>(block[j + 3U]);
            }
            for (unsigned int i = 16U; i < 64U; ++i)
            {
                const std::uint32_t x = words[i - 15U];
                const std::uint32_t y = words[i - 2U];
                const std::uint32_t s0 = rotr(x, 7U) ^ rotr(x, 18U) ^ (x >> 3U);
                const std::uint32_t s1 = rotr(y, 17U) ^ rotr(y, 19U) ^ (y >> 10U);
                words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
            }

            std::uint32_t a = 0x6A09E667U, b = 0xBB67AE85U;
            std::uint32_t c = 0x3C6EF372U, d = 0xA54FF53AU;
            std::uint32_t e = 0x510E527FU, f = 0x9B05688CU;
            std::uint32_t g = 0x1F83D9ABU, h = 0x5BE0CD19U;
            for (unsigned int i = 0U; i < 64U; ++i)
            {
                const std::uint32_t sum1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
                const std::uint32_t choose = (e & f) ^ (~e & g);
                const std::uint32_t temp1 = h + sum1 + choose + sha256_k[i] + words[i];
                const std::uint32_t sum0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
                const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
                const std::uint32_t temp2 = sum0 + majority;
                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }

            const std::uint32_t final_state[8] = {
                a + 0x6A09E667U, b + 0xBB67AE85U,
                c + 0x3C6EF372U, d + 0xA54FF53AU,
                e + 0x510E527FU, f + 0x9B05688CU,
                g + 0x1F83D9ABU, h + 0x5BE0CD19U
            };
            for (unsigned int i = 0U; i < 8U; ++i)
            {
                digests[message_index * digest_size + i * 4U] = static_cast<std::uint8_t>(final_state[i] >> 24U);
                digests[message_index * digest_size + i * 4U + 1U] = static_cast<std::uint8_t>(final_state[i] >> 16U);
                digests[message_index * digest_size + i * 4U + 2U] = static_cast<std::uint8_t>(final_state[i] >> 8U);
                digests[message_index * digest_size + i * 4U + 3U] = static_cast<std::uint8_t>(final_state[i]);
            }
        }

        void check_cuda(const cudaError_t result, const char* operation)
        {
            if (result != cudaSuccess)
                throw std::runtime_error(std::string(operation) + " failed: " + cudaGetErrorString(result));
        }

        class Buffer final
        {
        public:
            explicit Buffer(const std::size_t bytes) { if (bytes != 0U) check_cuda(cudaMalloc(&pointer_, bytes), "cudaMalloc"); }
            Buffer(const Buffer&) = delete;
            Buffer& operator=(const Buffer&) = delete;
            ~Buffer() { if (pointer_ != nullptr) (void)cudaFree(pointer_); }
            [[nodiscard]] void* get() const noexcept { return pointer_; }
        private:
            void* pointer_ = nullptr;
        };

        class Event final
        {
        public:
            Event() { check_cuda(cudaEventCreate(&event_), "cudaEventCreate"); }
            Event(const Event&) = delete;
            Event& operator=(const Event&) = delete;
            ~Event() { if (event_ != nullptr) (void)cudaEventDestroy(event_); }
            [[nodiscard]] cudaEvent_t get() const noexcept { return event_; }
        private:
            cudaEvent_t event_ = nullptr;
        };
    }

    void sha256_short_batch(
        const int device_index, const std::uint8_t* messages,
        const std::uint8_t* lengths, std::uint8_t* digests,
        const std::size_t message_count, CudaCryptoTiming& timing)
    {
        timing = {};
        if (message_count == 0U) return;
        if (messages == nullptr || lengths == nullptr || digests == nullptr)
            throw std::invalid_argument("CUDA SHA-256 batch received a null pointer.");
        for (std::size_t i = 0; i < message_count; ++i)
            if (lengths[i] > message_stride)
                throw std::invalid_argument("CUDA SHA-256 batch supports messages of at most 55 bytes.");

        const auto init_start = std::chrono::steady_clock::now();
        check_cuda(cudaSetDevice(device_index), "cudaSetDevice");
        check_cuda(cudaFree(nullptr), "CUDA context initialization");
        timing.initialization_time_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - init_start).count();

        const std::size_t input_bytes = message_count * message_stride;
        const std::size_t length_bytes = message_count;
        const std::size_t output_bytes = message_count * digest_size;
        Buffer device_messages(input_bytes), device_lengths(length_bytes), device_digests(output_bytes);
        Event transfer_start, transfer_end;
        check_cuda(cudaEventRecord(transfer_start.get()), "cudaEventRecord H2D start");
        check_cuda(cudaMemcpy(device_messages.get(), messages, input_bytes, cudaMemcpyHostToDevice), "cudaMemcpy messages");
        check_cuda(cudaMemcpy(device_lengths.get(), lengths, length_bytes, cudaMemcpyHostToDevice), "cudaMemcpy lengths");
        check_cuda(cudaEventRecord(transfer_end.get()), "cudaEventRecord H2D end");
        check_cuda(cudaEventSynchronize(transfer_end.get()), "cudaEventSynchronize H2D");
        float h2d_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&h2d_ms, transfer_start.get(), transfer_end.get()), "cudaEventElapsedTime H2D");

        constexpr unsigned int threads = 128U;
        const std::size_t requested_blocks = (message_count + threads - 1U) / threads;
        const unsigned int blocks = static_cast<unsigned int>(requested_blocks > 65535U ? 65535U : requested_blocks);
        Event kernel_start, kernel_end;
        check_cuda(cudaEventRecord(kernel_start.get()), "cudaEventRecord kernel start");
        sha256_short_kernel<<<blocks, threads>>>(
            static_cast<const std::uint8_t*>(device_messages.get()),
            static_cast<const std::uint8_t*>(device_lengths.get()),
            static_cast<std::uint8_t*>(device_digests.get()), message_count);
        check_cuda(cudaGetLastError(), "SHA-256 kernel launch");
        check_cuda(cudaEventRecord(kernel_end.get()), "cudaEventRecord kernel end");
        check_cuda(cudaEventSynchronize(kernel_end.get()), "cudaEventSynchronize kernel");
        float kernel_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&kernel_ms, kernel_start.get(), kernel_end.get()), "cudaEventElapsedTime kernel");

        check_cuda(cudaEventRecord(transfer_start.get()), "cudaEventRecord D2H start");
        check_cuda(cudaMemcpy(digests, device_digests.get(), output_bytes, cudaMemcpyDeviceToHost), "cudaMemcpy digests");
        check_cuda(cudaEventRecord(transfer_end.get()), "cudaEventRecord D2H end");
        check_cuda(cudaEventSynchronize(transfer_end.get()), "cudaEventSynchronize D2H");
        float d2h_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&d2h_ms, transfer_start.get(), transfer_end.get()), "cudaEventElapsedTime D2H");
        timing.kernel_time_ms = static_cast<double>(kernel_ms);
        timing.transfer_time_ms = static_cast<double>(h2d_ms) + static_cast<double>(d2h_ms);
    }
}
