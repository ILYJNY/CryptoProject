#include "../Benchmark/QftBenchmark.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    [[nodiscard]] std::vector<std::size_t> parse_size_list(
        const std::string& value, const char* option_name, const bool allow_zero = false)
    {
        std::vector<std::size_t> values;
        std::stringstream stream(value);
        std::string token;
        while (std::getline(stream, token, ','))
        {
            if (token.empty()) throw std::invalid_argument(std::string(option_name) + " contains an empty item.");
            const unsigned long long parsed = std::stoull(token);
            if (parsed == 0ULL && !allow_zero)
                throw std::invalid_argument(std::string(option_name) + " values must be positive.");
            values.push_back(static_cast<std::size_t>(parsed));
        }
        if (values.empty()) throw std::invalid_argument(std::string(option_name) + " requires at least one value.");
        return values;
    }

    [[nodiscard]] crypto::quantum::QftBenchmarkOptions parse_options(int argc, char** argv, std::string& csv_path)
    {
        crypto::quantum::QftBenchmarkOptions options;
        csv_path = "Output/qft_benchmark.csv";
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument = argv[index];
            if (argument.rfind("--qubits=", 0U) == 0U)
            {
                options.qubit_counts = parse_size_list(argument.substr(9U), "--qubits");
            }
            else if (argument.rfind("--repeats=", 0U) == 0U)
            {
                options.repeats = static_cast<std::size_t>(std::stoull(argument.substr(10U)));
            }
            else if (argument.rfind("--warmup=", 0U) == 0U)
            {
                options.warmup_runs = static_cast<std::size_t>(std::stoull(argument.substr(9U)));
            }
            else if (argument.rfind("--threads=", 0U) == 0U)
            {
                options.cpu_threads = static_cast<std::size_t>(std::stoull(argument.substr(10U)));
            }
            else if (argument.rfind("--max-memory-mib=", 0U) == 0U)
            {
                const std::size_t memory_mib = static_cast<std::size_t>(std::stoull(argument.substr(17U)));
                if (memory_mib > static_cast<std::size_t>(-1) / (1024U * 1024U))
                    throw std::overflow_error("--max-memory-mib is too large.");
                options.max_state_vector_bytes = memory_mib * 1024U * 1024U;
            }
            else if (argument.rfind("--device=", 0U) == 0U)
            {
                options.gpu_device = std::stoi(argument.substr(9U));
            }
            else if (argument.rfind("--devices=", 0U) == 0U)
            {
                const std::vector<std::size_t> parsed = parse_size_list(argument.substr(10U), "--devices", true);
                options.gpu_devices.clear();
                for (const std::size_t device : parsed)
                {
                    if (device > static_cast<std::size_t>(std::numeric_limits<int>::max()))
                        throw std::out_of_range("A CUDA device index exceeds the supported integer range.");
                    options.gpu_devices.push_back(static_cast<int>(device));
                }
            }
            else if (argument == "--cpu-only")
            {
                options.include_cuda_backends = false;
            }
            else if (argument == "--cuda-only")
            {
                options.include_cpu_backends = false;
            }
            else if (argument.rfind("--csv=", 0U) == 0U)
            {
                csv_path = argument.substr(6U);
                if (csv_path.empty()) throw std::invalid_argument("--csv requires a file path.");
            }
            else if (argument == "--help")
            {
                std::cout << "QuantumAttackBenchmark [--qubits=8,10,12,14,16] [--repeats=5] [--warmup=1] "
                             "[--threads=N] [--max-memory-mib=256] [--device=N] [--devices=0,1] "
                             "[--cpu-only|--cuda-only] [--csv=PATH]\n";
                std::cout << "Default behavior benchmarks CPU and any detected CUDA backends.\n";
                std::exit(EXIT_SUCCESS);
            }
            else
            {
                throw std::invalid_argument("Unknown argument: " + argument);
            }
        }
        return options;
    }
}

int main(int argc, char** argv)
{
    try
    {
        std::string csv_path;
        const auto options = parse_options(argc, argv, csv_path);
        const auto results = crypto::quantum::run_qft_benchmark(options);
        for (const auto& result : results)
        {
            std::cout << crypto::quantum::format_qft_benchmark_result(result) << '\n';
        }
        const std::string report_path = crypto::quantum::export_qft_benchmark_csv(results, csv_path);
        std::cout << "CSV report: " << report_path << '\n';
        std::cout << "Note: timings describe a classical state-vector simulator, not a quantum processor.\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "QuantumAttack benchmark error: " << exception.what() << '\n';
        return EXIT_FAILURE;
    }
}
