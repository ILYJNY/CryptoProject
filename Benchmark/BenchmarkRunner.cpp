#include "BenchmarkRunner.h"

#include "Encoding/Encoding.h"
#include "PerformanceMonitor/PerformanceMonitor.h"
#include "SHA/SHA256.h"

#include <array>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace crypto::benchmark
{
    std::string run_basic_benchmark()
    {
        PerformanceMonitor monitor;
        const std::string payload(1024U * 1024U, 'C');
        const auto bytes = utf8_to_bytes(payload);
        standard::Sha256Digest digest{};

        for (int repetition = 0; repetition < 5; ++repetition)
        {
            monitor.measure("SHA256.1MiB", "CPU", [&]()
            {
                digest = standard::sha256(bytes);
            }, "1 MiB input; 5 repetitions");
        }

        std::filesystem::create_directories("Output");
        monitor.export_csv("Output/benchmark_records.csv");
        monitor.export_summary_csv("Output/benchmark_summary.csv");

        std::ostringstream output;
        output << "SHA-256 benchmark completed.\n"
               << "Input size: " << bytes.size() << " bytes\n"
               << "Repetitions: 5\n"
               << "Final digest: " << hex_encode(digest) << '\n'
               << "Detailed results: Output/benchmark_records.csv\n"
               << "Summary results: Output/benchmark_summary.csv";
        return output.str();
    }
}
