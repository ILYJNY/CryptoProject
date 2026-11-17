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

        // QuantumAttack 2.8: single-qubit phase shift and mid-circuit measurement.
        {
            crypto::quantum::QuantumSimulator phase(1U);
            phase.apply_hadamard(0U);
            phase.apply_phase_shift(0U, 3.14159265358979323846);
            phase.apply_hadamard(0U);
            const auto phase_probabilities = phase.probabilities();
            require(phase_probabilities[0] < 1e-9 && std::abs(phase_probabilities[1] - 1.0) < 1e-9,
                    "A phase shift of pi must act like a Z gate.");
            require(phase.gate_count() == 3U && phase.measurement_count() == 0U,
                    "The phase shift must be counted as a gate.");

            crypto::quantum::QuantumSimulator bell(2U);
            bell.apply_hadamard(0U);
            bell.apply_cnot(0U, 1U);
            const auto first = bell.measure_qubit(0U, 0.25);
            require(first.outcome && std::abs(first.probability_of_one - 0.5) < 1e-9 &&
                    std::abs(first.outcome_probability - 0.5) < 1e-9,
                    "A Bell-pair qubit must be measured as 1 with probability one half.");
            require(std::abs(bell.probabilities()[3] - 1.0) < 1e-9,
                    "Measuring one half of a Bell pair must collapse the state onto |11>.");
            const auto partner = bell.measure_qubit(1U, 0.999);
            require(partner.outcome && std::abs(partner.probability_of_one - 1.0) < 1e-9,
                    "After the collapse the partner qubit must be 1 with certainty.");
            require(bell.measurement_count() == 2U && bell.gate_count() == 2U,
                    "Measurements must be counted separately from gates.");

            crypto::quantum::QuantumSimulator bell_zero(2U);
            bell_zero.apply_hadamard(0U);
            bell_zero.apply_cnot(0U, 1U);
            const auto zero = bell_zero.measure_qubit(0U, 0.75);
            require(!zero.outcome && std::abs(bell_zero.probabilities()[0] - 1.0) < 1e-9,
                    "The 0 outcome must collapse the Bell pair onto |00>.");

            bool sampleRejected = false;
            try { (void)bell_zero.measure_qubit(0U, 1.0); }
            catch (const std::invalid_argument&) { sampleRejected = true; }
            require(sampleRejected, "A measurement sample outside [0, 1) must be rejected.");
        }

        std::cout << "QuantumSmokeTests passed.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "QuantumSmokeTests failed: " << exception.what() << '\n';
        return 1;
    }
}
