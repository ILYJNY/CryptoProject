#include "RSA.h"

#include "BigInteger/BigInteger.h"
#include "ErrorHandling/CryptoException.h"
#include "Random/SecureRandom.h"
#include "SHA/SHA256.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <utility>

namespace crypto::standard
{
    namespace
    {
        using Bytes = std::vector<std::uint8_t>;
        constexpr std::size_t HashLength = 32U;

        [[nodiscard]] BigInt os2ip(const std::span<const std::uint8_t> bytes)
        {
            BigInt value = 0;
            for (const std::uint8_t byte : bytes)
            {
                value <<= 8;
                value += byte;
            }
            return value;
        }

        [[nodiscard]] Bytes i2osp(const BigInt& value, const std::size_t length)
        {
            if (value < 0 || bit_length(value) > length * 8U)
            {
                raise_error(ErrorCode::OutOfRange, "Integer does not fit in the requested byte length.");
            }

            Bytes result(length, 0U);
            BigInt remaining = value;
            for (std::size_t i = 0; i < length; ++i)
            {
                result[length - 1U - i] = static_cast<std::uint8_t>((remaining & 0xFF).convert_to<unsigned int>());
                remaining >>= 8;
            }
            if (remaining != 0)
            {
                raise_error(ErrorCode::OutOfRange, "Integer does not fit in the requested byte length.");
            }
            return result;
        }

        [[nodiscard]] BigInt inverse_mod(BigInt a, BigInt modulus)
        {
            a = normalize_mod(a, modulus);
            BigInt oldR = a;
            BigInt r = modulus;
            BigInt oldS = 1;
            BigInt s = 0;

            while (r != 0)
            {
                const BigInt quotient = oldR / r;
                BigInt nextR = oldR - quotient * r;
                oldR = std::move(r);
                r = std::move(nextR);
                BigInt nextS = oldS - quotient * s;
                oldS = std::move(s);
                s = std::move(nextS);
            }

            if (oldR != 1)
            {
                raise_error(ErrorCode::ArithmeticError, "Modular inverse does not exist.");
            }
            return normalize_mod(oldS, modulus);
        }

        [[nodiscard]] bool probable_prime(const BigInt& candidate, const std::size_t rounds = 32U)
        {
            constexpr std::array<unsigned int, 16> smallPrimes{
                2U, 3U, 5U, 7U, 11U, 13U, 17U, 19U,
                23U, 29U, 31U, 37U, 41U, 43U, 47U, 53U
            };

            if (candidate < 2)
            {
                return false;
            }
            for (const unsigned int prime : smallPrimes)
            {
                if (candidate == prime)
                {
                    return true;
                }
                if ((candidate % prime) == 0)
                {
                    return false;
                }
            }

            BigInt d = candidate - 1;
            std::size_t s = 0;
            while ((d & 1) == 0)
            {
                d >>= 1;
                ++s;
            }

            for (std::size_t round = 0; round < rounds; ++round)
            {
                const BigInt a = BigInt(2) + SecureRandom::below(candidate - 3);
                BigInt x = mod_pow(a, d, candidate);
                if (x == 1 || x == candidate - 1)
                {
                    continue;
                }

                bool passed = false;
                for (std::size_t r = 1; r < s; ++r)
                {
                    x = (x * x) % candidate;
                    if (x == candidate - 1)
                    {
                        passed = true;
                        break;
                    }
                }
                if (!passed)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] BigInt generate_prime(const std::size_t bits, const BigInt& exponent)
        {
            if (bits < 512U)
            {
                raise_error(ErrorCode::InvalidArgument, "RSA prime size must be at least 512 bits.");
            }

            const std::size_t byteCount = (bits + 7U) / 8U;
            const unsigned int excessBits = static_cast<unsigned int>(byteCount * 8U - bits);

            while (true)
            {
                Bytes bytes(byteCount);
                SecureRandom::fill(bytes);
                bytes.front() &= static_cast<std::uint8_t>(0xFFU >> excessBits);
                bytes.front() |= static_cast<std::uint8_t>(1U << (7U - excessBits));
                bytes.back() |= 1U;
                BigInt candidate = os2ip(bytes);

                if (gcd(exponent, candidate - 1) != 1)
                {
                    continue;
                }
                if (probable_prime(candidate))
                {
                    return candidate;
                }
            }
        }

        [[nodiscard]] Bytes xor_bytes(const std::span<const std::uint8_t> a,
                                      const std::span<const std::uint8_t> b)
        {
            if (a.size() != b.size())
            {
                raise_error(ErrorCode::InvalidLength, "Mask and input lengths differ.");
            }
            Bytes result(a.size());
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                result[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
            }
            return result;
        }

        [[nodiscard]] Bytes oaep_encode(const std::span<const std::uint8_t> message,
                                        const std::size_t encoded_length,
                                        const std::span<const std::uint8_t> label)
        {
            if (encoded_length < 2U * HashLength + 2U ||
                message.size() > encoded_length - 2U * HashLength - 2U)
            {
                raise_error(ErrorCode::InvalidLength, "Message is too long for RSA-OAEP with SHA-256.");
            }

            const auto labelHash = sha256(label);
            const std::size_t dbLength = encoded_length - HashLength - 1U;
            Bytes dataBlock(dbLength, 0U);
            std::copy(labelHash.begin(), labelHash.end(), dataBlock.begin());
            const std::size_t delimiter = dbLength - message.size() - 1U;
            dataBlock[delimiter] = 1U;
            std::copy(message.begin(), message.end(), dataBlock.begin() + static_cast<std::ptrdiff_t>(delimiter + 1U));

            const Bytes seed = SecureRandom::bytes(HashLength);
            const Bytes dbMask = mgf1_sha256(seed, dbLength);
            const Bytes maskedDb = xor_bytes(dataBlock, dbMask);
            const Bytes seedMask = mgf1_sha256(maskedDb, HashLength);
            const Bytes maskedSeed = xor_bytes(seed, seedMask);

            Bytes encoded(encoded_length, 0U);
            encoded[0] = 0U;
            std::copy(maskedSeed.begin(), maskedSeed.end(), encoded.begin() + 1);
            std::copy(maskedDb.begin(), maskedDb.end(),
                      encoded.begin() + static_cast<std::ptrdiff_t>(1U + HashLength));
            return encoded;
        }

        [[nodiscard]] Bytes oaep_decode(const std::span<const std::uint8_t> encoded,
                                        const std::span<const std::uint8_t> label)
        {
            if (encoded.size() < 2U * HashLength + 2U || encoded[0] != 0U)
            {
                raise_error(ErrorCode::InvalidFormat, "RSA-OAEP decryption failed.");
            }

            const std::size_t dbLength = encoded.size() - HashLength - 1U;
            const auto maskedSeed = encoded.subspan(1U, HashLength);
            const auto maskedDb = encoded.subspan(1U + HashLength);
            const Bytes seedMask = mgf1_sha256(maskedDb, HashLength);
            const Bytes seed = xor_bytes(maskedSeed, seedMask);
            const Bytes dbMask = mgf1_sha256(seed, dbLength);
            const Bytes dataBlock = xor_bytes(maskedDb, dbMask);
            const auto expectedLabelHash = sha256(label);

            std::uint8_t difference = 0;
            for (std::size_t i = 0; i < HashLength; ++i)
            {
                difference |= static_cast<std::uint8_t>(dataBlock[i] ^ expectedLabelHash[i]);
            }
            if (difference != 0U)
            {
                raise_error(ErrorCode::InvalidFormat, "RSA-OAEP decryption failed.");
            }

            std::size_t index = HashLength;
            while (index < dataBlock.size() && dataBlock[index] == 0U)
            {
                ++index;
            }
            if (index >= dataBlock.size() || dataBlock[index] != 1U)
            {
                raise_error(ErrorCode::InvalidFormat, "RSA-OAEP decryption failed.");
            }
            return Bytes(dataBlock.begin() + static_cast<std::ptrdiff_t>(index + 1U), dataBlock.end());
        }

        [[nodiscard]] Bytes pss_encode(const std::span<const std::uint8_t> message,
                                       const std::size_t em_bits,
                                       const std::size_t salt_length)
        {
            const std::size_t emLength = (em_bits + 7U) / 8U;
            if (emLength < HashLength + salt_length + 2U)
            {
                raise_error(ErrorCode::InvalidLength, "RSA modulus is too small for the selected PSS salt length.");
            }

            const auto messageHash = sha256(message);
            const Bytes salt = SecureRandom::bytes(salt_length);
            Bytes mPrime(8U, 0U);
            mPrime.insert(mPrime.end(), messageHash.begin(), messageHash.end());
            mPrime.insert(mPrime.end(), salt.begin(), salt.end());
            const auto h = sha256(mPrime);

            const std::size_t dbLength = emLength - HashLength - 1U;
            Bytes db(dbLength, 0U);
            db[dbLength - salt_length - 1U] = 1U;
            std::copy(salt.begin(), salt.end(), db.end() - static_cast<std::ptrdiff_t>(salt_length));

            const Bytes dbMask = mgf1_sha256(h, dbLength);
            Bytes maskedDb = xor_bytes(db, dbMask);
            const unsigned int unused = static_cast<unsigned int>(8U * emLength - em_bits);
            maskedDb[0] &= static_cast<std::uint8_t>(0xFFU >> unused);

            Bytes encoded;
            encoded.reserve(emLength);
            encoded.insert(encoded.end(), maskedDb.begin(), maskedDb.end());
            encoded.insert(encoded.end(), h.begin(), h.end());
            encoded.push_back(0xBCU);
            return encoded;
        }

        [[nodiscard]] bool pss_verify_encoded(const std::span<const std::uint8_t> encoded,
                                              const std::span<const std::uint8_t> message,
                                              const std::size_t em_bits,
                                              const std::size_t salt_length)
        {
            const std::size_t emLength = (em_bits + 7U) / 8U;
            if (encoded.size() != emLength || emLength < HashLength + salt_length + 2U ||
                encoded.back() != 0xBCU)
            {
                return false;
            }

            const std::size_t dbLength = emLength - HashLength - 1U;
            const auto maskedDb = encoded.first(dbLength);
            const auto h = encoded.subspan(dbLength, HashLength);
            const unsigned int unused = static_cast<unsigned int>(8U * emLength - em_bits);
            if (unused > 0U && (maskedDb[0] & static_cast<std::uint8_t>(0xFFU << (8U - unused))) != 0U)
            {
                return false;
            }

            const Bytes mask = mgf1_sha256(h, dbLength);
            Bytes db = xor_bytes(maskedDb, mask);
            db[0] &= static_cast<std::uint8_t>(0xFFU >> unused);

            const std::size_t delimiter = dbLength - salt_length - 1U;
            for (std::size_t i = 0; i < delimiter; ++i)
            {
                if (db[i] != 0U)
                {
                    return false;
                }
            }
            if (db[delimiter] != 1U)
            {
                return false;
            }

            const auto messageHash = sha256(message);
            Bytes mPrime(8U, 0U);
            mPrime.insert(mPrime.end(), messageHash.begin(), messageHash.end());
            mPrime.insert(mPrime.end(), db.end() - static_cast<std::ptrdiff_t>(salt_length), db.end());
            const auto expected = sha256(mPrime);

            std::uint8_t difference = 0;
            for (std::size_t i = 0; i < HashLength; ++i)
            {
                difference |= static_cast<std::uint8_t>(expected[i] ^ h[i]);
            }
            return difference == 0U;
        }
    }

    RsaKeyPair RSA::generate_key_pair(
        const std::size_t modulus_bits,
        const std::uint32_t public_exponent)
    {
        if (modulus_bits < 1024U || modulus_bits % 2U != 0U)
        {
            raise_error(ErrorCode::InvalidArgument, "RSA modulus size must be an even number of at least 1024 bits.");
        }
        if (public_exponent < 3U || (public_exponent % 2U) == 0U)
        {
            raise_error(ErrorCode::InvalidArgument, "RSA public exponent must be an odd integer of at least 3.");
        }

        const BigInt e = public_exponent;
        const std::size_t pBits = modulus_bits / 2U;
        const std::size_t qBits = modulus_bits - pBits;

        while (true)
        {
            const BigInt p = generate_prime(pBits, e);
            BigInt q = generate_prime(qBits, e);
            if (p == q)
            {
                continue;
            }

            const BigInt n = p * q;
            if (bit_length(n) != modulus_bits)
            {
                continue;
            }

            const BigInt phi = (p - 1) * (q - 1);
            const BigInt d = inverse_mod(e, phi);
            return {{n, e}, {n, d}};
        }
    }

    std::vector<std::uint8_t> RSA::encrypt_oaep_sha256(
        const RsaPublicKey& key,
        const std::span<const std::uint8_t> plaintext,
        const std::span<const std::uint8_t> label)
    {
        if (key.modulus <= 0 || key.public_exponent <= 1)
        {
            raise_error(ErrorCode::InvalidArgument, "Invalid RSA public key.");
        }
        const std::size_t k = (bit_length(key.modulus) + 7U) / 8U;
        const Bytes encoded = oaep_encode(plaintext, k, label);
        const BigInt messageRepresentative = os2ip(encoded);
        if (messageRepresentative >= key.modulus)
        {
            raise_error(ErrorCode::InvalidArgument, "RSA-OAEP encoded message is out of range.");
        }
        return i2osp(mod_pow(messageRepresentative, key.public_exponent, key.modulus), k);
    }

    std::vector<std::uint8_t> RSA::decrypt_oaep_sha256(
        const RsaPrivateKey& key,
        const std::span<const std::uint8_t> ciphertext,
        const std::span<const std::uint8_t> label)
    {
        if (key.modulus <= 0 || key.private_exponent <= 0)
        {
            raise_error(ErrorCode::InvalidArgument, "Invalid RSA private key.");
        }
        const std::size_t k = (bit_length(key.modulus) + 7U) / 8U;
        if (ciphertext.size() != k)
        {
            raise_error(ErrorCode::InvalidLength, "RSA-OAEP ciphertext has an invalid length.");
        }
        const BigInt c = os2ip(ciphertext);
        if (c >= key.modulus)
        {
            raise_error(ErrorCode::InvalidFormat, "RSA-OAEP decryption failed.");
        }
        const BigInt m = mod_pow(c, key.private_exponent, key.modulus);
        return oaep_decode(i2osp(m, k), label);
    }

    std::vector<std::uint8_t> RSA::sign_pss_sha256(
        const RsaPrivateKey& key,
        const std::span<const std::uint8_t> message,
        const std::size_t salt_length)
    {
        if (key.modulus <= 0 || key.private_exponent <= 0)
        {
            raise_error(ErrorCode::InvalidArgument, "Invalid RSA private key.");
        }
        const std::size_t modBits = bit_length(key.modulus);
        const std::size_t k = (modBits + 7U) / 8U;
        const Bytes encoded = pss_encode(message, modBits - 1U, salt_length);
        const BigInt m = os2ip(encoded);
        return i2osp(mod_pow(m, key.private_exponent, key.modulus), k);
    }

    bool RSA::verify_pss_sha256(
        const RsaPublicKey& key,
        const std::span<const std::uint8_t> message,
        const std::span<const std::uint8_t> signature,
        const std::size_t salt_length)
    {
        if (key.modulus <= 0 || key.public_exponent <= 1)
        {
            return false;
        }
        const std::size_t modBits = bit_length(key.modulus);
        const std::size_t k = (modBits + 7U) / 8U;
        if (signature.size() != k)
        {
            return false;
        }
        const BigInt s = os2ip(signature);
        if (s >= key.modulus)
        {
            return false;
        }
        const BigInt m = mod_pow(s, key.public_exponent, key.modulus);
        const std::size_t emLength = (modBits - 1U + 7U) / 8U;
        return pss_verify_encoded(i2osp(m, emLength), message, modBits - 1U, salt_length);
    }
}
