#include "ComputeEngine.h"
#include "CryptoSystem/Standard/SHA/SHA256.h"
#include "ErrorHandling/CryptoException.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    void expect(const bool condition, const std::string& message)
    {
        if (!condition)
        {
            throw std::runtime_error(message);
        }
    }

    void test_cpu_vector_add()
    {
        constexpr std::size_t count = 100003U;

        std::vector<std::uint32_t> left(count);
        std::vector<std::uint32_t> right(count);
        std::vector<std::uint32_t> output(count, 0U);

        for (std::size_t index = 0; index < count; ++index)
        {
            left[index] = static_cast<std::uint32_t>(index * 3U);
            right[index] = static_cast<std::uint32_t>(index * 7U + 11U);
        }

        crypto::PerformanceMonitor monitor;
        crypto::ComputeOptions options;
        options.backend = crypto::ComputeBackend::Cpu;
        options.cpu_thread_count = 4U;

        const crypto::ComputeEngine engine(options, &monitor);
        const auto report = engine.vector_add_u32(left, right, output);

        expect(report.actual_backend == crypto::ComputeBackend::Cpu,
               "CPU backend was not selected.");
        expect(report.items_processed == count,
               "The execution report contains an incorrect item count.");
        expect(!report.used_cpu_fallback,
               "Explicit CPU execution must not be reported as a fallback.");

        for (std::size_t index = 0; index < count; ++index)
        {
            const std::uint32_t expected = left[index] + right[index];
            expect(output[index] == expected, "CPU vector addition produced an incorrect value.");
        }

        expect(monitor.records().size() == 1U,
               "ComputeEngine did not record its execution in PerformanceMonitor.");
        expect(monitor.records().front().stage == "ComputeEngine.VectorAddU32",
               "Unexpected performance stage name.");
    }

    void test_sha256_short_batch_cpu()
    {
        crypto::PerformanceMonitor monitor;
        crypto::ComputeOptions options;
        options.backend = crypto::ComputeBackend::Cpu;
        const crypto::ComputeEngine engine(options, &monitor);
        const std::vector<std::string> messages{"", "abc", "hello from CryptoProject v2"};
        crypto::Sha256BatchReport report;
        const auto digests = engine.sha256_short_batch(messages, &report);
        expect(digests.size() == messages.size(), "SHA-256 batch returned an incorrect result count.");
        for (std::size_t i = 0; i < messages.size(); ++i)
            expect(digests[i] == crypto::standard::sha256(messages[i]),
                   "SHA-256 batch result did not match the standard CPU implementation.");
        expect(report.execution.actual_backend == crypto::ComputeBackend::Cpu,
               "The explicit CPU SHA-256 batch did not use the CPU backend.");
        expect(report.messages_processed == messages.size(),
               "The SHA-256 batch report contains an incorrect message count.");
        expect(!monitor.records().empty(), "SHA-256 batch was not recorded in PerformanceMonitor.");

        bool rejected_long_input = false;
        try
        {
            (void)engine.sha256_short_batch(std::vector<std::string>{std::string(56U, 'x')});
        }
        catch (const crypto::CryptoException&)
        {
            rejected_long_input = true;
        }
        expect(rejected_long_input, "The short-message SHA-256 API did not reject a 56-byte input.");
    }

    void test_invalid_lengths()
    {
        crypto::ComputeOptions options;
        options.backend = crypto::ComputeBackend::Cpu;
        const crypto::ComputeEngine engine(options);

        const std::vector<std::uint32_t> left{1U, 2U};
        const std::vector<std::uint32_t> right{3U};
        std::vector<std::uint32_t> output(2U);

        bool exception_seen = false;
        try
        {
            (void)engine.vector_add_u32(left, right, output);
        }
        catch (const crypto::CryptoException&)
        {
            exception_seen = true;
        }

        expect(exception_seen, "Mismatched vector lengths did not raise CryptoException.");
    }
}

int main()
{
    try
    {
        const auto devices = crypto::ComputeEngine::discover_gpus();
        std::cout << "[INFO] CUDA compiled: "
                  << (crypto::ComputeEngine::cuda_compiled() ? "yes" : "no") << '\n';
        std::cout << "[INFO] Available CUDA devices: " << devices.size() << '\n';

        for (const auto& device : devices)
        {
            std::cout << "[GPU " << device.index << "] " << device.name
                      << " | SMs: " << device.multiprocessor_count << '\n';
        }

        test_cpu_vector_add();
        test_sha256_short_batch_cpu();
        test_invalid_lengths();

        std::cout << "[PASS] ComputeEngine smoke tests completed successfully.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FAIL] " << exception.what() << '\n';
        return 1;
    }
}
