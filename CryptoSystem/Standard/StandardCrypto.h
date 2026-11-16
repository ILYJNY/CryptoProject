#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace crypto::standard
{
    [[nodiscard]] std::string run_sha256_demo(std::string_view message);
    [[nodiscard]] std::string run_aes_gcm_demo(std::string_view message);
    [[nodiscard]] std::string run_p256_demo(std::string_view message);
    [[nodiscard]] std::string run_rsa_demo(std::string_view message, std::size_t modulus_bits = 4096U);
}
