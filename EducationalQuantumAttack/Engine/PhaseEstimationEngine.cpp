#include "PhaseEstimationEngine.h"

#include "EducationalQuantumAttack/Common/QuantumAttackSupport.h"
#include "QuantumAttack/Standard/Core/QuantumSimulator.h"

#include <numbers>
#include <numeric>
#include <random>
#include <stdexcept>

namespace crypto::educational_quantum_attack
{
    PhaseEstimationResult run_iterative_phase_estimation(const PhaseEstimationRequest& request)
    {
        if (request.work_qubits == 0U || request.work_qubits >= 62U)
            throw std::invalid_argument("The phase-estimation work register must have between 1 and 61 qubits.");
        if (request.stages.empty())
            throw std::invalid_argument("Phase estimation needs at least one stage.");
        const std::size_t work_dimension = std::size_t{1} << request.work_qubits;
        if (request.initial_work_state >= work_dimension)
            throw std::invalid_argument("The initial work-register state is outside the register.");
        for (const PhaseEstimationStage& stage : request.stages)
        {
            if (stage.bits == 0U || stage.bits > 62U)
                throw std::invalid_argument("Each phase-estimation stage must measure between 1 and 62 bits.");
            if (!stage.controlled_power)
                throw std::invalid_argument("Each phase-estimation stage needs a controlled-power provider.");
        }

        // Work register: qubits [0, work_qubits). Control qubit: the next qubit up.
        const std::size_t control = request.work_qubits;
        quantum::QuantumSimulator simulator(
            request.work_qubits + 1U, request.simulator_qubit_limit, request.execution);
        simulator.set_basis_state(request.initial_work_state);

        std::vector<std::size_t> work_register(request.work_qubits);
        std::iota(work_register.begin(), work_register.end(), std::size_t{0});
        std::vector<std::size_t> permutation(work_dimension);

        std::mt19937_64 generator(request.seed);
        std::uniform_real_distribution<double> uniform(0.0, 1.0);

        PhaseEstimationResult result;
        result.phase_integers.reserve(request.stages.size());

        for (const PhaseEstimationStage& stage : request.stages)
        {
            // With the phase written in binary as 0.b1 b2 ... bt, the rounds measure bt
            // first and b1 last. The round that measures bk applies U^(2^(k-1)), which
            // leaves the control qubit with the phase 2*pi * 0.bk b(k+1) ... bt. Removing
            // 2*pi * `correction`, where `correction` = 0.0 b(k+1) b(k+2) ... bt is built
            // from the outcomes already observed, leaves exactly pi * bk, so the final
            // Hadamard maps the control qubit onto |bk>. Moving from bk to b(k-1) shifts
            // the known bits one place to the right and inserts bk at weight 1/4.
            double correction = 0.0;
            std::uint64_t measured = 0U;
            for (std::size_t round = 0U; round < stage.bits; ++round)
            {
                const std::size_t power = stage.bits - 1U - round;
                {
                    const Stopwatch table_timer;
                    stage.controlled_power(power, permutation);
                    result.permutation_table_ms += table_timer.elapsed_ms();
                }

                const Stopwatch round_timer;
                simulator.apply_hadamard(control);
                simulator.apply_controlled_permutation(control, work_register, permutation);
                if (correction != 0.0)
                {
                    simulator.apply_phase_shift(control, -2.0 * std::numbers::pi * correction);
                    ++result.phase_shift_gates;
                }
                simulator.apply_hadamard(control);

                double sample = uniform(generator);
                if (!(sample < 1.0)) sample = 0.0; // guard against a rounded-up 1.0
                const quantum::QubitMeasurement measurement = simulator.measure_qubit(control, sample);
                if (measurement.outcome)
                {
                    measured |= std::uint64_t{1} << round;
                    simulator.apply_x(control); // reset the control qubit to |0>
                    ++result.reset_x_gates;
                }
                correction = correction / 2.0 + (measurement.outcome ? 0.25 : 0.0);

                result.hadamard_gates += 2U;
                ++result.controlled_permutations;
                ++result.measurements;
                result.simulation_wall_ms += round_timer.elapsed_ms();
            }
            result.phase_integers.push_back(measured);
        }

        result.simulator_gate_count = simulator.gate_count();
        result.simulator_operation_depth = simulator.operation_depth();
        result.qubits = simulator.qubit_count();
        result.state_vector_bytes = simulator.state_vector_bytes();
        result.backend = simulator.backend_statistics();
        return result;
    }
}
