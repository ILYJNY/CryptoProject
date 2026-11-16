#include "CudaVectorAdd.h"

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace crypto::cuda_backend
{
    namespace
    {
        void check_cuda(const cudaError_t result, const char* operation)
        {
            if (result != cudaSuccess)
            {
                throw std::runtime_error(
                    std::string(operation) + " failed: " + cudaGetErrorString(result));
            }
        }

        class DeviceBuffer final
        {
        public:
            explicit DeviceBuffer(const std::size_t bytes)
            {
                if (bytes > 0)
                {
                    check_cuda(cudaMalloc(&pointer_, bytes), "cudaMalloc");
                }
            }

            DeviceBuffer(const DeviceBuffer&) = delete;
            DeviceBuffer& operator=(const DeviceBuffer&) = delete;

            ~DeviceBuffer()
            {
                if (pointer_ != nullptr)
                {
                    (void)cudaFree(pointer_);
                }
            }

            [[nodiscard]] void* get() const noexcept { return pointer_; }

        private:
            void* pointer_ = nullptr;
        };

        class Event final
        {
        public:
            Event()
            {
                check_cuda(cudaEventCreate(&event_), "cudaEventCreate");
            }

            Event(const Event&) = delete;
            Event& operator=(const Event&) = delete;

            ~Event()
            {
                if (event_ != nullptr)
                {
                    (void)cudaEventDestroy(event_);
                }
            }

            [[nodiscard]] cudaEvent_t get() const noexcept { return event_; }

        private:
            cudaEvent_t event_ = nullptr;
        };

        __global__ void vector_add_kernel(
            const std::uint32_t* left,
            const std::uint32_t* right,
            std::uint32_t* output,
            const std::size_t count)
        {
            const std::size_t first =
                static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
            const std::size_t stride =
                static_cast<std::size_t>(gridDim.x) * blockDim.x;

            for (std::size_t index = first; index < count; index += stride)
            {
                output[index] = left[index] + right[index];
            }
        }

        std::mutex initialization_mutex;
        std::unordered_set<int> initialized_devices;
    }

    void vector_add_u32(
        const int device_index,
        const std::uint32_t* left,
        const std::uint32_t* right,
        std::uint32_t* output,
        const std::size_t count,
        CudaVectorAddTiming& timing)
    {
        timing = {};
        if (count == 0)
        {
            return;
        }
        if (left == nullptr || right == nullptr || output == nullptr)
        {
            throw std::invalid_argument("CUDA vector addition received a null data pointer.");
        }

        const auto initialization_start = std::chrono::steady_clock::now();
        check_cuda(cudaSetDevice(device_index), "cudaSetDevice");

        {
            std::scoped_lock lock(initialization_mutex);
            if (initialized_devices.find(device_index) == initialized_devices.end())
            {
                check_cuda(cudaFree(nullptr), "CUDA context initialization");
                initialized_devices.insert(device_index);
            }
        }

        timing.initialization_time_ms =
            std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - initialization_start).count();

        int device = 0;
        check_cuda(cudaGetDevice(&device), "cudaGetDevice");

        cudaDeviceProp properties{};
        check_cuda(cudaGetDeviceProperties(&properties, device), "cudaGetDeviceProperties");

        const std::size_t byte_count = count * sizeof(std::uint32_t);
        DeviceBuffer device_left(byte_count);
        DeviceBuffer device_right(byte_count);
        DeviceBuffer device_output(byte_count);

        Event transfer_start;
        Event transfer_end;
        Event kernel_start;
        Event kernel_end;

        check_cuda(cudaEventRecord(transfer_start.get()), "cudaEventRecord transfer start");
        check_cuda(cudaMemcpy(device_left.get(), left, byte_count, cudaMemcpyHostToDevice),
                   "cudaMemcpy left to device");
        check_cuda(cudaMemcpy(device_right.get(), right, byte_count, cudaMemcpyHostToDevice),
                   "cudaMemcpy right to device");
        check_cuda(cudaEventRecord(transfer_end.get()), "cudaEventRecord transfer end");
        check_cuda(cudaEventSynchronize(transfer_end.get()), "cudaEventSynchronize transfer");

        float host_to_device_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(
                       &host_to_device_ms,
                       transfer_start.get(),
                       transfer_end.get()),
                   "cudaEventElapsedTime host-to-device");

        constexpr unsigned int threads_per_block = 256U;
        const std::size_t required_blocks =
            (count + static_cast<std::size_t>(threads_per_block) - 1U) /
            static_cast<std::size_t>(threads_per_block);
        const std::size_t maximum_blocks =
            static_cast<std::size_t>(properties.maxGridSize[0]);
        const std::size_t block_count = std::min(required_blocks, maximum_blocks);

        if (block_count == 0)
        {
            throw std::runtime_error("The selected CUDA device reported an invalid grid limit.");
        }

        check_cuda(cudaEventRecord(kernel_start.get()), "cudaEventRecord kernel start");
        vector_add_kernel<<<static_cast<unsigned int>(block_count), threads_per_block>>>(
            static_cast<const std::uint32_t*>(device_left.get()),
            static_cast<const std::uint32_t*>(device_right.get()),
            static_cast<std::uint32_t*>(device_output.get()),
            count
        );
        check_cuda(cudaGetLastError(), "vector_add_kernel launch");
        check_cuda(cudaEventRecord(kernel_end.get()), "cudaEventRecord kernel end");
        check_cuda(cudaEventSynchronize(kernel_end.get()), "cudaEventSynchronize kernel");

        float kernel_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(&kernel_ms, kernel_start.get(), kernel_end.get()),
                   "cudaEventElapsedTime kernel");

        check_cuda(cudaEventRecord(transfer_start.get()), "cudaEventRecord device-to-host start");
        check_cuda(cudaMemcpy(output, device_output.get(), byte_count, cudaMemcpyDeviceToHost),
                   "cudaMemcpy result to host");
        check_cuda(cudaEventRecord(transfer_end.get()), "cudaEventRecord device-to-host end");
        check_cuda(cudaEventSynchronize(transfer_end.get()), "cudaEventSynchronize device-to-host");

        float device_to_host_ms = 0.0F;
        check_cuda(cudaEventElapsedTime(
                       &device_to_host_ms,
                       transfer_start.get(),
                       transfer_end.get()),
                   "cudaEventElapsedTime device-to-host");

        timing.kernel_time_ms = static_cast<double>(kernel_ms);
        timing.transfer_time_ms =
            static_cast<double>(host_to_device_ms) + static_cast<double>(device_to_host_ms);
    }
}
