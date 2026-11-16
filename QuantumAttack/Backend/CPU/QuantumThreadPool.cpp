#include "QuantumThreadPool.h"

namespace crypto::quantum::cpu
{
    QuantumThreadPool::QuantumThreadPool(const std::size_t thread_count)
    {
        const std::size_t detected = static_cast<std::size_t>(std::thread::hardware_concurrency());
        // Use up to 16 workers by default to avoid excessive thread creation on
        // high-core-count workstations. Users can request an explicit count.
        worker_count_ = thread_count == 0U
            ? std::min<std::size_t>(16U, std::max<std::size_t>(1U, detected))
            : std::max<std::size_t>(1U, thread_count);
    }

    QuantumThreadPool::~QuantumThreadPool()
    {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        condition_.notify_all();
        for (std::thread& worker : workers_)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
    }

    std::size_t QuantumThreadPool::thread_count() const noexcept
    {
        return worker_count_;
    }

    void QuantumThreadPool::ensure_workers()
    {
        std::call_once(startup_once_, [this]()
        {
            workers_.reserve(worker_count_);
            for (std::size_t index = 0U; index < worker_count_; ++index)
            {
                workers_.emplace_back([this]() { worker_loop(); });
            }
        });
    }

    void QuantumThreadPool::enqueue(std::function<void()> task)
    {
        {
            std::lock_guard lock(mutex_);
            if (stopping_)
            {
                throw std::runtime_error("The quantum worker pool is stopping.");
            }
            tasks_.push(std::move(task));
        }
        condition_.notify_one();
    }

    void QuantumThreadPool::worker_loop()
    {
        for (;;)
        {
            std::function<void()> task;
            {
                std::unique_lock lock(mutex_);
                condition_.wait(lock, [this]() { return stopping_ || !tasks_.empty(); });
                if (stopping_ && tasks_.empty())
                {
                    return;
                }
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            task();
        }
    }
}
