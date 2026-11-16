#include "ToyAESKeySearch.h"

#include "Random/SecureRandom.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <stdexcept>

namespace crypto::educational
{
    ToyAesSample generate_toy_aes_sample(const std::size_t unknown_bits)
    {
        if (unknown_bits < 4U || unknown_bits > 16U)
            throw std::invalid_argument("Toy AES unknown key size must be between 4 and 16 bits.");
        ToyAesSample sample;
        const std::uint64_t candidateCount = std::uint64_t{1} << unknown_bits;
        const std::uint16_t unknownPart = static_cast<std::uint16_t>(
            crypto::SecureRandom::uniform_u64(0U, candidateCount - 1U));
        for (std::size_t bit = 0; bit < unknown_bits; ++bit)
        {
            if ((unknownPart & (std::uint16_t{1} << bit)) != 0U)
                sample.ground_truth.key[15U - bit / 8U] |= static_cast<std::uint8_t>(1U << (bit % 8U));
        }
        sample.ground_truth.plaintext = "Educational AES keyspace demonstration.";

        const auto* text = reinterpret_cast<const std::uint8_t*>(sample.ground_truth.plaintext.data());
        const std::span<const std::uint8_t> plaintext(text, sample.ground_truth.plaintext.size());
        sample.public_instance.ciphertext = standard::AES128GCM::encrypt(
            sample.ground_truth.key, plaintext);
        sample.public_instance.unknown_bits = unknown_bits;
        return sample;
    }

    ToyAesAnalysis analyze_toy_aes(const ToyAesPublicInstance& instance)
    {
        ToyAesAnalysis result;

        if (instance.unknown_bits < 4U || instance.unknown_bits > 16U)
        {
            result.status = "INVALID_KEYSPACE_SIZE";
            return result;
        }
        const std::uint32_t candidateCount = std::uint32_t{1} << instance.unknown_bits;
        for (std::uint32_t candidate = 0; candidate < candidateCount; ++candidate)
        {
            standard::Aes128Key key{};
            for (std::size_t bit = 0; bit < instance.unknown_bits; ++bit)
            {
                if ((candidate & (std::uint32_t{1} << bit)) != 0U)
                    key[15U - bit / 8U] |= static_cast<std::uint8_t>(1U << (bit % 8U));
            }
            ++result.candidates_tested;

            try
            {
                (void)standard::AES128GCM::decrypt(key, instance.ciphertext);
                result.success = true;
                result.recovered_key = key;
                result.status = "AES_KEY_RECOVERED";
                return result;
            }
            catch (const std::exception&)
            {
                // An authentication failure means this trial key did not match the generated record.
            }
        }

        result.status = "INCONCLUSIVE";
        return result;
    }
}
