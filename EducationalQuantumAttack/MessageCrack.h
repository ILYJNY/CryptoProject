#pragma once

// Message crack-timing feature (CryptoProject 2.3.5).
//
// A focused, interactive workflow on the educational toy composite sets:
//
//   1. receive a plaintext sentence,
//   2. encrypt it with the set's Toy AES-128-GCM (restricted 12-bit key space),
//   3. crack it (recover the key and decrypt the sentence),
//   4. report how long the crack took.
//
// It is a thin presentation layer over the existing Toy AES Grover attack, which already
// measures all three crack times, so the numbers here are the same ones the full attack
// report shows. Two crack times are reported for each set and kept apart:
//
//   - classical crack runtime: the existing restricted-key-space search, measured on this CPU;
//   - quantum Grover crack: the state-vector simulation runtime (A) and the scenario estimate (B).
//
// All parameters are deliberately tiny teaching parameters. The 12-bit Toy AES key space is
// an educational keyspace reduction, not AES-128; a crack time here says nothing about AES-128.

#include "EducationalQuantumAttack/Common/QuantumAttackTypes.h"

#include "CryptoSystem/Standard/AES/AES128GCM.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::educational_quantum_attack
{
    inline constexpr std::string_view DefaultCrackOutputDirectory = "Output/EducationalQuantumAttack";

    struct MessageCrackSetResult
    {
        std::string set_name;

        // Encryption of the entered sentence.
        std::size_t unknown_key_bits = 0U;
        std::size_t key_space = 0U;             // 2^unknown_key_bits
        std::size_t ciphertext_bytes = 0U;

        // Classical crack (measured): the existing restricted-key-space search.
        bool classical_recovered = false;
        bool classical_plaintext_matches = false;
        std::string classical_decrypted;
        Metric classical_crack_ms;
        Metric classical_keys_tried;

        // Quantum Grover crack.
        bool quantum_executed = false;
        bool quantum_recovered = false;
        Metric quantum_simulator_ms;            // time A: classical simulation of the circuit
        Metric quantum_estimated_seconds;       // time B: scenario estimate
        Metric grover_iterations;
        Metric simulated_qubits;

        // The full attack report for this set's Toy AES, if the caller wants every detail.
        AttackResult attack;
    };

    struct MessageCrackReport
    {
        std::string plaintext;
        bool plaintext_empty = false;
        std::vector<MessageCrackSetResult> sets;
        std::string report;
    };

    // Encrypts `plaintext` and measures the crack time in each of the three independent toy
    // sets. An empty plaintext is reported as such and nothing is cracked.
    [[nodiscard]] MessageCrackReport run_message_crack_timing(
        const std::string& plaintext, const QuantumAttackConfig& config = {});

    [[nodiscard]] std::string format_message_crack_report(const MessageCrackReport& report);

    // Writes <plaintext-independent> message_crack_report.txt / .csv into `directory`.
    [[nodiscard]] bool export_message_crack_report(
        const MessageCrackReport& report, const std::string& directory,
        std::string& report_path, std::string& csv_path);
}
