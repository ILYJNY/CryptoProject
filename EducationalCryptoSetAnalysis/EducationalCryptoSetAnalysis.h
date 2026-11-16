#pragma once
#include <string>
#include <cstdint>
#include <vector>
namespace crypto::educational_set_analysis {
struct BackendBenchmark {
    bool gpu_available = false;
    bool verified = false;
    std::size_t output_bits = 16;
    std::uint64_t maximum_attempts = 200000;
    std::uint64_t single_attempts = 0, multi_attempts = 0, gpu_attempts = 0;
    std::uint32_t single_digest = 0, multi_digest = 0, gpu_digest = 0;
    double single_cpu_ms = 0.0, multi_thread_cpu_ms = 0.0;
    double gpu_wall_ms = 0.0, gpu_kernel_ms = 0.0, gpu_transfer_ms = 0.0;
    std::size_t cpu_threads = 0;
    std::string single_first, single_second, multi_first, multi_second, gpu_first, gpu_second;
    std::string gpu_device, gpu_status = "UNAVAILABLE";
};
struct SetResult {
    std::string name, key_exchange;
    bool passed = false;
    double generation_ms = 0.0, classical_attack_ms = 0.0;
    double grover_simulator_ms = 0.0, shor_simulator_ms = 0.0;
    double estimated_grover_seconds = 0.0, estimated_shor_seconds = 0.0, estimated_classical_seconds = 0.0;
    std::uint64_t candidates = 0;
    std::string attack_note;
    BackendBenchmark backend_benchmark;
};
[[nodiscard]] SetResult run_toy_aes_sha_ecdsa();
[[nodiscard]] SetResult run_toy_aes_sha_rsapss();
[[nodiscard]] SetResult run_toy_sha_aes_mlkem();
[[nodiscard]] std::vector<SetResult> run_all_toy_sets();
// Encrypts the user-provided UTF-8 message with the educational restricted-keyspace AES
// in each independent toy set, then demonstrates recovery of the toy key and plaintext.
[[nodiscard]] std::string run_custom_message_simulation(const std::string& plaintext);
[[nodiscard]] std::string format_set(const SetResult& result);
[[nodiscard]] std::string format_comparison(const std::vector<SetResult>& results);
[[nodiscard]] bool export_results(const std::vector<SetResult>& results, const std::string& directory, std::string& report_path, std::string& csv_path);
}
