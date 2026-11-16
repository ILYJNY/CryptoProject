#include "CryptoSystem/Standard/ModuleLWE/MLKEM768.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

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
        require(crypto::standard::mlkem768_available(), "Portable ML-KEM-768 must be available.");

        auto key_pair = crypto::standard::mlkem768_generate_keypair();
        require(key_pair.encapsulation_key.size() == crypto::standard::MLKEM768_ENCAPSULATION_KEY_BYTES,
                "Incorrect ML-KEM-768 encapsulation key size.");
        require(key_pair.decapsulation_key.size() == crypto::standard::MLKEM768_DECAPSULATION_KEY_BYTES,
                "Incorrect ML-KEM-768 decapsulation key size.");

        auto encapsulation = crypto::standard::mlkem768_encapsulate(key_pair.encapsulation_key);
        require(encapsulation.ciphertext.size() == crypto::standard::MLKEM768_CIPHERTEXT_BYTES,
                "Incorrect ML-KEM-768 ciphertext size.");
        const auto recovered = crypto::standard::mlkem768_decapsulate(
            key_pair.decapsulation_key, encapsulation.ciphertext);
        require(std::equal(recovered.begin(), recovered.end(), encapsulation.shared_secret.begin()),
                "ML-KEM-768 valid ciphertext round-trip failed.");

        std::vector<std::uint8_t> modified_ciphertext = encapsulation.ciphertext;
        modified_ciphertext.back() ^= 0x01U;
        const auto rejected_secret = crypto::standard::mlkem768_decapsulate(
            key_pair.decapsulation_key, modified_ciphertext);
        require(!std::equal(rejected_secret.begin(), rejected_secret.end(), encapsulation.shared_secret.begin()),
                "ML-KEM-768 implicit rejection did not derive a distinct fallback secret.");

        bool rejected_bad_key = false;
        std::vector<std::uint8_t> modified_key = key_pair.decapsulation_key;
        modified_key[crypto::standard::MLKEM768_DECAPSULATION_KEY_BYTES - 33U] ^= 0x01U;
        try
        {
            (void)crypto::standard::mlkem768_decapsulate(modified_key, encapsulation.ciphertext);
        }
        catch (const std::invalid_argument&)
        {
            rejected_bad_key = true;
        }
        require(rejected_bad_key, "ML-KEM-768 accepted a decapsulation key with a corrupted public-key hash.");

        const auto demo = crypto::standard::run_mlkem768_demo();
        require(demo.available && demo.passed, "ML-KEM-768 integrated self-test failed.");

        std::cout << "[PASS] ML-KEM-768 smoke tests completed.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FAIL] " << exception.what() << '\n';
        return 1;
    }
}
