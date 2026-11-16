#include "Standard/Algorithms/QuantumAlgorithms.h"
#include "Standard/Core/QuantumSimulator.h"
#include "Standard/Models/QuantumResourceModel.h"
#include "Educational/Experiments/EducationalExperiments.h"

#include <cmath>
#include <iostream>
#include <stdexcept>

namespace
{
    void require(const bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
    }
}

int main()
{
    try
    {
        const auto superposition = crypto::quantum::run_superposition_experiment();
        require(superposition.passed, "Superposition experiment failed.");

        const auto entanglement = crypto::quantum::run_entanglement_experiment();
        require(entanglement.passed, "Entanglement experiment failed.");

        const auto interference = crypto::quantum::run_interference_experiment();
        require(interference.passed, "Interference experiment failed.");

        const auto grover = crypto::quantum::run_grover_experiment(3U, 5U, 1024U);
        require(grover.passed, "Grover experiment failed to amplify its target.");

        const auto qft = crypto::quantum::run_qft_experiment(3U);
        require(qft.passed, "QFT experiment did not produce a uniform measurement distribution.");

        const auto shor = crypto::quantum::run_shor_toy_experiment(15U, 2U, 2048U);
        require(shor.factored && shor.factor_a * shor.factor_b == 15U,
                "Tiny Shor simulation did not produce the expected factorization.");

        const auto educational = crypto::quantum::educational::run_all_experiments();
        require(educational.size() == 6U, "Educational experiment suite has an unexpected size.");
        for (const auto& experiment : educational)
            require(experiment.passed, "An educational experiment did not pass.");

        const auto rsaEstimate = crypto::quantum::estimate_quantum_resources(
            crypto::quantum::CryptoTarget::RSA, 4096U, 22U);
        require(!rsaEstimate.state_vector_feasible,
                "The RSA-4096 resource illustration should exceed the small simulator limit.");

        bool limitCaught = false;
        try { crypto::quantum::QuantumSimulator tooLarge(23U, 22U); }
        catch (const std::length_error&) { limitCaught = true; }
        require(limitCaught, "The simulator did not enforce its qubit limit.");

        std::cout << "QuantumSmokeTests passed.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "QuantumSmokeTests failed: " << exception.what() << '\n';
        return 1;
    }
}
