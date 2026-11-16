#include "QuantumResourceModel.h"

#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace crypto::quantum
{
    namespace
    {
        [[nodiscard]] std::size_t saturating_state_bytes(const std::size_t qubits)
        {
            constexpr std::size_t bytes_per_amplitude = 2U * sizeof(double);
            if (qubits >= std::numeric_limits<std::size_t>::digits ||
                qubits > (std::numeric_limits<std::size_t>::max() / bytes_per_amplitude) - 1U)
                return std::numeric_limits<std::size_t>::max();
            const std::size_t count = std::size_t{1} << qubits;
            if (count > std::numeric_limits<std::size_t>::max() / bytes_per_amplitude)
                return std::numeric_limits<std::size_t>::max();
            return count * bytes_per_amplitude;
        }
    }

    QuantumResourceEstimate estimate_quantum_resources(
        const CryptoTarget target,
        const std::size_t parameter_bits,
        const std::size_t simulator_qubit_limit)
    {
        if (parameter_bits == 0U || parameter_bits > 4096U)
            throw std::invalid_argument("The parameter size must be between 1 and 4096 bits.");

        QuantumResourceEstimate result;
        result.input_bits = parameter_bits;
        switch (target)
        {
        case CryptoTarget::RSA:
            result.target = "RSA";
            result.estimated_register_qubits = 3U * parameter_bits + 1U;
            result.qualification = "Register-size illustration for order finding only. It excludes work ancillas, error correction, fault tolerance, and circuit overhead; it is not a hardware resource estimate.";
            break;
        case CryptoTarget::ECC:
            result.target = "ECC";
            result.estimated_register_qubits = 3U * parameter_bits + 1U;
            result.qualification = "Register-size illustration for discrete-log order finding only. It excludes work ancillas, error correction, fault tolerance, and circuit overhead.";
            break;
        case CryptoTarget::AES:
            result.target = "AES search-space model";
            result.estimated_register_qubits = parameter_bits;
            result.generic_search_iterations = 0.7853981633974483 * std::pow(2.0, static_cast<double>(parameter_bits) / 2.0);
            result.qualification = "Only a generic Grover search-register estimate. Oracle workspace and reversible AES circuit costs are omitted; these are not measured AES attack results.";
            break;
        case CryptoTarget::SHA256:
            result.target = "Truncated SHA-256 output-space model";
            result.estimated_register_qubits = parameter_bits;
            result.generic_search_iterations = 0.7853981633974483 * std::pow(2.0, static_cast<double>(parameter_bits) / 2.0);
            result.qualification = "A generic search-space illustration for a deliberately truncated output model, not a full SHA-256 attack estimate.";
            break;
        case CryptoTarget::MLKEM:
            result.target = "ML-KEM";
            result.estimated_register_qubits = 0U;
            result.qualification = "No Shor-style factoring or discrete-log model is provided for ML-KEM. This project does not claim a practical quantum break of ML-KEM.";
            break;
        }
        result.state_vector_bytes = result.estimated_register_qubits == 0U
            ? 0U : saturating_state_bytes(result.estimated_register_qubits);
        result.state_vector_feasible = result.estimated_register_qubits > 0U &&
            result.estimated_register_qubits <= simulator_qubit_limit;
        return result;
    }

    std::string format_resource_estimate(const QuantumResourceEstimate& estimate)
    {
        std::ostringstream output;
        output << "Target: " << estimate.target << '\n'
               << "Input parameter: " << estimate.input_bits << " bits\n";
        if (estimate.estimated_register_qubits == 0U)
        {
            output << "State-vector qubits: N/A\n";
        }
        else
        {
            output << "Illustrative register qubits: " << estimate.estimated_register_qubits << '\n'
                   << "State-vector memory lower bound: ";
            if (estimate.state_vector_bytes == std::numeric_limits<std::size_t>::max())
                output << "exceeds size_t representation\n";
            else
                output << estimate.state_vector_bytes << " bytes\n";
            output << "Fits configured state-vector limit: "
                   << (estimate.state_vector_feasible ? "YES" : "NO") << '\n';
        }
        if (estimate.generic_search_iterations > 0.0)
        {
            output << std::fixed << std::setprecision(0)
                   << "Idealized Grover iterations: " << estimate.generic_search_iterations << '\n';
        }
        output << "Qualification: " << estimate.qualification << '\n';
        return output.str();
    }
}
