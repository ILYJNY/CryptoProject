#include "QuantumReport.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace crypto::quantum
{
    std::string export_quantum_report(
        const std::vector<ExperimentResult>& experiments,
        const std::string& file_path)
    {
        const std::filesystem::path path(file_path);
        if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("Unable to open the quantum report output file.");
        output << "name,passed,backend,qubits,gate_count,operation_depth,state_vector_bytes,"
                  "cpu_threads,cpu_operations,gpu_operations,cpu_fallback_operations,"
                  "elapsed_ms,cpu_wall_time_ms,gpu_kernel_time_ms,gpu_transfer_time_ms,"
                  "gpu_initialization_time_ms,gpu_device,gpu_devices,gpu_inter_gpu_transfer_time_ms,"
                  "gpu_parallel_kernel_wall_time_ms,gpu_peer_copy_count,gpu_host_staged_copy_count,"
                  "gpu_qft_fused_stage_count,gpu_qft_swap_count,gpu_pinned_host_memory_used,summary\n";
        for (const auto& experiment : experiments)
        {
            std::string summary = experiment.summary;
            for (char& character : summary)
            {
                if (character == '"') character = '\'';
                if (character == '\r' || character == '\n') character = ' ';
            }
            output << '"' << experiment.name << "\"," << (experiment.passed ? "true" : "false")
                   << ",\"" << experiment.backend << "\""
                   << ',' << experiment.qubits
                   << ',' << experiment.gate_count
                   << ',' << experiment.operation_depth
                   << ',' << experiment.state_vector_bytes
                   << ',' << experiment.cpu_threads
                   << ',' << experiment.cpu_operations
                   << ',' << experiment.gpu_operations
                   << ',' << experiment.cpu_fallback_operations
                   << ',' << experiment.elapsed_ms
                   << ',' << experiment.cpu_wall_time_ms
                   << ',' << experiment.gpu_kernel_time_ms
                   << ',' << experiment.gpu_transfer_time_ms
                   << ',' << experiment.gpu_initialization_time_ms
                   << ',' << experiment.gpu_device
                   << ",\"";
            for (std::size_t device_index = 0U; device_index < experiment.gpu_devices.size(); ++device_index)
            {
                if (device_index != 0U) output << ';';
                output << experiment.gpu_devices[device_index];
            }
            output << '\"' << ',' << experiment.gpu_inter_gpu_transfer_time_ms
                   << ',' << experiment.gpu_parallel_kernel_wall_time_ms
                   << ',' << experiment.gpu_peer_copy_count
                   << ',' << experiment.gpu_host_staged_copy_count
                   << ',' << experiment.gpu_qft_fused_stage_count
                   << ',' << experiment.gpu_qft_swap_count
                   << ',' << (experiment.gpu_pinned_host_memory_used ? "true" : "false")
                   << ",\"" << summary << "\"\n";
        }
        if (!output) throw std::runtime_error("Writing the quantum report failed.");
        return path.string();
    }
}
