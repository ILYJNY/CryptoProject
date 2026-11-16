#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace crypto::standard
{
    inline constexpr std::size_t MLKEM768_ENCAPSULATION_KEY_BYTES = 1184U;
    inline constexpr std::size_t MLKEM768_DECAPSULATION_KEY_BYTES = 2400U;
    inline constexpr std::size_t MLKEM768_CIPHERTEXT_BYTES = 1088U;
    inline constexpr std::size_t MLKEM768_SHARED_SECRET_BYTES = 32U;

    struct MlKem768KeyPair final
    {
        std::vector<std::uint8_t> encapsulation_key;
        std::vector<std::uint8_t> decapsulation_key;

        MlKem768KeyPair() = default;
        ~MlKem768KeyPair();
        MlKem768KeyPair(const MlKem768KeyPair&) = delete;
        MlKem768KeyPair& operator=(const MlKem768KeyPair&) = delete;
        MlKem768KeyPair(MlKem768KeyPair&&) noexcept = default;
        MlKem768KeyPair& operator=(MlKem768KeyPair&&) noexcept = delete;
    };

    struct MlKem768Encapsulation final
    {
        std::vector<std::uint8_t> ciphertext;
        std::array<std::uint8_t, MLKEM768_SHARED_SECRET_BYTES> shared_secret{};

        MlKem768Encapsulation() = default;
        ~MlKem768Encapsulation();
        MlKem768Encapsulation(const MlKem768Encapsulation&) = delete;
        MlKem768Encapsulation& operator=(const MlKem768Encapsulation&) = delete;
        MlKem768Encapsulation(MlKem768Encapsulation&&) noexcept = default;
        MlKem768Encapsulation& operator=(MlKem768Encapsulation&&) noexcept = delete;
    };

    struct MlKem768DemoResult
    {
        bool available = false;
        bool passed = false;
        std::size_t encapsulation_key_bytes = 0;
        std::size_t ciphertext_bytes = 0;
        std::size_t shared_secret_bytes = 0;
        std::string detail;
    };

    // Portable in-tree C++ implementation. It does not depend on Windows CNG ML-KEM APIs.
    [[nodiscard]] bool mlkem768_available() noexcept;
    [[nodiscard]] MlKem768KeyPair mlkem768_generate_keypair();
    [[nodiscard]] MlKem768Encapsulation mlkem768_encapsulate(
        std::span<const std::uint8_t> encapsulation_key);
    [[nodiscard]] std::array<std::uint8_t, MLKEM768_SHARED_SECRET_BYTES> mlkem768_decapsulate(
        std::span<const std::uint8_t> decapsulation_key,
        std::span<const std::uint8_t> ciphertext);
    [[nodiscard]] MlKem768DemoResult run_mlkem768_demo();
    [[nodiscard]] std::string mlkem768_status_message();
}
