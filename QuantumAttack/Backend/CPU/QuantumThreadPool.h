#pragma once

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto::quantum::cpu
{
    class QuantumThreadPool final
    {
    public:
        explicit QuantumThreadPool(std::size_t thread_count = 0U);
        ~QuantumThreadPool();

        QuantumThreadPool(const QuantumThreadPool&) = delete;
        QuantumThreadPool& operator=(const QuantumThreadPool&) = delete;

        [[nodiscard]] std::size_t thread_count() const noexcept;

        template <typename Function>
        void parallel_for(
            const std::size_t begin,
            const std::size_t end,
            Function&& function,
            const std::size_t grain_size = 1024U)
        {
            if (end <= begin)
            {
                return;
            }

            const std::size_t count = end - begin;
            const std::size_t safe_grain = std::max<std::size_t>(1U, grain_size);
            const std::size_t desired_blocks = (count + safe_grain - 1U) / safe_grain;
            const std::size_t blocks = std::min(worker_count_, desired_blocks);

            if (blocks <= 1U || worker_count_ <= 1U)
            {
                for (std::size_t index = begin; index < end; ++index)
                {
                    function(index);
                }
                return;
            }

            ensure_workers();
            using FunctionType = std::decay_t<Function>;
            FunctionType callable(std::forward<Function>(function));
            std::vector<std::future<void>> futures;
            futures.reserve(blocks);

            const std::size_t base_block_size = count / blocks;
            const std::size_t remainder = count % blocks;
            std::size_t block_begin = begin;

            for (std::size_t block = 0U; block < blocks; ++block)
            {
                const std::size_t block_size = base_block_size + (block < remainder ? 1U : 0U);
                const std::size_t block_end = block_begin + block_size;

                auto task = std::make_shared<std::packaged_task<void()>>(
                    [block_begin, block_end, &callable]()
                    {
                        for (std::size_t index = block_begin; index < block_end; ++index)
                        {
                            callable(index);
                        }
                    });

                futures.push_back(task->get_future());
                enqueue([task]() { (*task)(); });
                block_begin = block_end;
            }

            // Calling get() propagates worker exceptions to the caller.
            for (auto& future : futures)
            {
                future.get();
            }
        }

    private:
        void ensure_workers();
        void enqueue(std::function<void()> task);
        void worker_loop();

        std::vector<std::thread> workers_;
        std::queue<std::function<void()>> tasks_;
        mutable std::mutex mutex_;
        std::condition_variable condition_;
        bool stopping_ = false;
        std::size_t worker_count_ = 1U;
        std::once_flag startup_once_;
    };
}
