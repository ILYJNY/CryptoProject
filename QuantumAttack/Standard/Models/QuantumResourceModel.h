#pragma once

#include <cstddef>
#include <string>

namespace crypto::quantum
{
    enum class CryptoTarget
    {
        RSA,
        ECC,
        AES,
        SHA256,
        MLKEM
    };

    struct QuantumResourceEstimate
    {
        std::string target;
        std::size_t input_bits = 0;
        std::size_t estimated_register_qubits = 0;
        std::size_t state_vector_bytes = 0;
        double generic_search_iterations = 0.0;
        bool state_vector_feasible = false;
        std::string qualification;
    };

    [[nodiscard]] QuantumResourceEstimate estimate_quantum_resources(
        CryptoTarget target,
        std::size_t parameter_bits,
        std::size_t simulator_qubit_limit = 22U);
    [[nodiscard]] std::string format_resource_estimate(const QuantumResourceEstimate& estimate);
}
