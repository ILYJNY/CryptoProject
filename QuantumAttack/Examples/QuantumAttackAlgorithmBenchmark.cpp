#include "../Benchmark/AlgorithmBenchmark.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    std::vector<std::size_t> parse_sizes(const std::string& value)
    {
        std::vector<std::size_t> result;
        std::stringstream stream(value);
        std::string token;
        while (std::getline(stream, token, ','))
        {
            if (token.empty()) throw std::invalid_argument("--qubits contains an empty value.");
            const auto parsed = std::stoull(token);
            if (parsed == 0ULL) throw std::invalid_argument("Qubit counts must be positive.");
            result.push_back(static_cast<std::size_t>(parsed));
        }
        if (result.empty()) throw std::invalid_argument("--qubits requires at least one value.");
        return result;
    }

    crypto::quantum::AlgorithmBenchmarkOptions parse_args(int argc, char** argv, std::string& csv)
    {
        crypto::quantum::AlgorithmBenchmarkOptions options;
        csv = "Output/algorithm_benchmark.csv";
        for (int i = 1; i < argc; ++i)
        {
            const std::string arg = argv[i];
            if (arg.rfind("--qubits=", 0U) == 0U) options.qubit_counts = parse_sizes(arg.substr(9U));
            else if (arg.rfind("--repeats=", 0U) == 0U) options.repeats = std::stoull(arg.substr(10U));
            else if (arg.rfind("--warmup=", 0U) == 0U) options.warmup_runs = std::stoull(arg.substr(9U));
            else if (arg.rfind("--shots=", 0U) == 0U) options.shots = std::stoull(arg.substr(8U));
            else if (arg.rfind("--threads=", 0U) == 0U) options.cpu_threads = std::stoull(arg.substr(10U));
            else if (arg.rfind("--max-memory-mib=", 0U) == 0U)
            {
                const std::size_t mib = std::stoull(arg.substr(17U));
                if (mib > std::numeric_limits<std::size_t>::max() / (1024U * 1024U))
                    throw std::overflow_error("--max-memory-mib is too large.");
                options.max_state_vector_bytes = mib * 1024U * 1024U;
            }
            else if (arg.rfind("--device=", 0U) == 0U) options.gpu_device = std::stoi(arg.substr(9U));
            else if (arg.rfind("--devices=", 0U) == 0U)
            {
                options.gpu_devices.clear();
                std::stringstream stream(arg.substr(10U));
                std::string token;
                while (std::getline(stream, token, ',')) options.gpu_devices.push_back(std::stoi(token));
            }
            else if (arg.rfind("--shor-number=", 0U) == 0U) options.shor_number = static_cast<std::uint32_t>(std::stoul(arg.substr(14U)));
            else if (arg.rfind("--shor-base=", 0U) == 0U) options.shor_base = static_cast<std::uint32_t>(std::stoul(arg.substr(12U)));
            else if (arg == "--cpu-only") options.include_cuda_backends = false;
            else if (arg == "--cuda-only") options.include_cpu_backends = false;
            else if (arg.rfind("--csv=", 0U) == 0U) csv = arg.substr(6U);
            else if (arg == "--help")
            {
                std::cout << "QuantumAttackAlgorithmBenchmark [--qubits=3,4,5] [--repeats=3] [--warmup=1] "
                             "[--shots=512] [--threads=N] [--max-memory-mib=64] [--device=N] [--devices=0,1] "
                             "[--shor-number=15] [--shor-base=2] [--cpu-only|--cuda-only] [--csv=PATH]\n";
                std::exit(EXIT_SUCCESS);
            }
            else throw std::invalid_argument("Unknown argument: " + arg);
        }
        return options;
    }
}

int main(int argc, char** argv)
{
    try
    {
        std::string csv;
        const auto options = parse_args(argc, argv, csv);
        const auto results = crypto::quantum::run_algorithm_benchmark(options);
        for (const auto& result : results)
            std::cout << crypto::quantum::format_algorithm_benchmark_result(result) << '\n';
        std::cout << "CSV report: " << crypto::quantum::export_algorithm_benchmark_csv(results, csv) << '\n';
        std::cout << "Note: these are classical state-vector simulation timings, not quantum-hardware timings.\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "Algorithm benchmark error: " << exception.what() << '\n';
        return EXIT_FAILURE;
    }
}
