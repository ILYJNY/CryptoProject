#include "../Educational/Experiments/EducationalExperiments.h"
#include "../Reports/QuantumReport.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

namespace
{
    [[nodiscard]] crypto::quantum::QuantumExecutionOptions parse_options(int argc, char** argv)
    {
        crypto::quantum::QuantumExecutionOptions options;
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument = argv[index];
            if (argument == "--backend=cpu")
            {
                options.backend = crypto::quantum::QuantumBackendType::CpuSingleThread;
            }
            else if (argument == "--backend=cpu-multi")
            {
                options.backend = crypto::quantum::QuantumBackendType::CpuMultiThread;
            }
            else if (argument == "--backend=gpu")
            {
                options.backend = crypto::quantum::QuantumBackendType::CudaGpu;
            }
            else if (argument == "--backend=multi-gpu")
            {
                options.backend = crypto::quantum::QuantumBackendType::CudaMultiGpu;
            }
            else if (argument.rfind("--threads=", 0U) == 0U)
            {
                options.cpu_threads = static_cast<std::size_t>(std::stoull(argument.substr(10U)));
            }
            else if (argument.rfind("--device=", 0U) == 0U)
            {
                options.gpu_device = std::stoi(argument.substr(9U));
            }
            else if (argument.rfind("--devices=", 0U) == 0U)
            {
                std::stringstream devices(argument.substr(10U));
                std::string token;
                while (std::getline(devices, token, ','))
                {
                    if (token.empty()) throw std::invalid_argument("The --devices list contains an empty item.");
                    options.gpu_devices.push_back(std::stoi(token));
                }
            }
            else if (argument == "--help")
            {
                std::cout << "QuantumAttackDemo [--backend=cpu|cpu-multi|gpu|multi-gpu] "
                             "[--threads=N] [--device=N] [--devices=0,1,...]\n";
                std::cout << "For multi-GPU, --devices is optional; an empty list selects the largest available power-of-two set.\n";
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
        const auto options = parse_options(argc, argv);
        const auto experiments = crypto::quantum::educational::run_all_experiments(options);
        for (const auto& experiment : experiments)
        {
            std::cout << crypto::quantum::format_experiment(experiment) << '\n';
        }
        const std::string report = crypto::quantum::export_quantum_report(
            experiments, "Output/quantum_backend_report.csv");
        std::cout << "CSV report: " << report << '\n';
        std::cout << "Note: this is a classical state-vector simulator, not a quantum computer.\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "QuantumAttack error: " << exception.what() << '\n';
        return EXIT_FAILURE;
    }
}
