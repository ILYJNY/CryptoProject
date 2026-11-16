#include "MLKEM768.h"

#include "Random/SecureRandom.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::standard
{
namespace
{
    using Byte = std::uint8_t;
    using Bytes = std::vector<Byte>;

    constexpr std::int32_t Q = 3329;
    constexpr std::size_t N = 256;
    constexpr std::size_t K = 3;
    constexpr std::size_t SYMBYTES = 32;
    constexpr std::size_t POLY12_BYTES = 384;
    constexpr std::size_t PKE_SECRET_KEY_BYTES = K * POLY12_BYTES;
    constexpr std::size_t PUBLIC_KEY_BYTES = K * POLY12_BYTES + SYMBYTES;
    constexpr std::size_t SECRET_KEY_BYTES = PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES + 2 * SYMBYTES;
    constexpr std::size_t CIPHERTEXT_BYTES = K * 320 + 128;

    struct Poly
    {
        std::array<std::int32_t, N> c{};
    };

    using PolyVec = std::array<Poly, K>;
    using Matrix = std::array<PolyVec, K>;
    using Seed = std::array<Byte, SYMBYTES>;
    using SharedSecret = std::array<Byte, SYMBYTES>;

    [[nodiscard]] std::int32_t mod_q(const std::int64_t value) noexcept
    {
        const auto reduced = static_cast<std::int32_t>(value % Q);
        return reduced < 0 ? reduced + Q : reduced;
    }

    [[nodiscard]] std::int32_t pow_mod(std::int32_t base, std::uint32_t exponent) noexcept
    {
        std::int32_t result = 1;
        while (exponent != 0U)
        {
            if ((exponent & 1U) != 0U)
                result = mod_q(static_cast<std::int64_t>(result) * base);
            base = mod_q(static_cast<std::int64_t>(base) * base);
            exponent >>= 1U;
        }
        return result;
    }

    [[nodiscard]] unsigned int bit_reverse_7(unsigned int value) noexcept
    {
        unsigned int result = 0U;
        for (unsigned int i = 0U; i < 7U; ++i)
        {
            result = (result << 1U) | (value & 1U);
            value >>= 1U;
        }
        return result;
    }

    [[nodiscard]] const std::array<std::int32_t, 128>& zetas()
    {
        static const std::array<std::int32_t, 128> values = []
        {
            std::array<std::int32_t, 128> table{};
            for (unsigned int i = 0U; i < table.size(); ++i)
                table[i] = pow_mod(17, bit_reverse_7(i));
            return table;
        }();
        return values;
    }

    // Keccak-f[1600], used by SHA3-256, SHA3-512, SHAKE128 and SHAKE256.
    constexpr std::array<std::uint64_t, 24> KECCAK_ROUND_CONSTANTS{
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808AULL, 0x8000000080008000ULL,
        0x000000000000808BULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008AULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800AULL, 0x800000008000000AULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };

    constexpr std::array<unsigned int, 25> KECCAK_ROTATION{
        0U, 1U, 62U, 28U, 27U,
        36U, 44U, 6U, 55U, 20U,
        3U, 10U, 43U, 25U, 39U,
        41U, 45U, 15U, 21U, 8U,
        18U, 2U, 61U, 56U, 14U
    };

    [[nodiscard]] std::uint64_t rotate_left(const std::uint64_t value, const unsigned int shift) noexcept
    {
        return shift == 0U ? value : (value << shift) | (value >> (64U - shift));
    }

    void keccak_f1600(std::array<std::uint64_t, 25>& state) noexcept
    {
        for (const std::uint64_t round_constant : KECCAK_ROUND_CONSTANTS)
        {
            std::array<std::uint64_t, 5> c{};
            std::array<std::uint64_t, 5> d{};
            for (std::size_t x = 0; x < 5; ++x)
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            for (std::size_t x = 0; x < 5; ++x)
                d[x] = c[(x + 4) % 5] ^ rotate_left(c[(x + 1) % 5], 1U);
            for (std::size_t y = 0; y < 5; ++y)
                for (std::size_t x = 0; x < 5; ++x)
                    state[x + 5 * y] ^= d[x];

            std::array<std::uint64_t, 25> b{};
            for (std::size_t y = 0; y < 5; ++y)
            {
                for (std::size_t x = 0; x < 5; ++x)
                {
                    const std::size_t destination_x = y;
                    const std::size_t destination_y = (2 * x + 3 * y) % 5;
                    b[destination_x + 5 * destination_y] =
                        rotate_left(state[x + 5 * y], KECCAK_ROTATION[x + 5 * y]);
                }
            }
            for (std::size_t y = 0; y < 5; ++y)
            {
                for (std::size_t x = 0; x < 5; ++x)
                    state[x + 5 * y] = b[x + 5 * y] ^
                        ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
            state[0] ^= round_constant;
        }
    }

    class Sponge final
    {
    public:
        explicit Sponge(const std::size_t rate, const Byte domain)
            : rate_(rate), domain_(domain)
        {
            if (rate_ == 0U || rate_ >= 200U)
                throw std::invalid_argument("Invalid Keccak sponge rate.");
        }

        void absorb(const std::span<const Byte> input)
        {
            if (finalized_)
                throw std::logic_error("Cannot absorb after sponge finalization.");
            for (const Byte byte : input)
            {
                state_[position_ / 8U] ^= static_cast<std::uint64_t>(byte)
                    << static_cast<unsigned int>((position_ % 8U) * 8U);
                ++position_;
                if (position_ == rate_)
                {
                    keccak_f1600(state_);
                    position_ = 0U;
                }
            }
        }

        void squeeze(const std::span<Byte> output)
        {
            if (!finalized_)
            {
                state_[position_ / 8U] ^= static_cast<std::uint64_t>(domain_)
                    << static_cast<unsigned int>((position_ % 8U) * 8U);
                const std::size_t last = rate_ - 1U;
                state_[last / 8U] ^= std::uint64_t{0x80U}
                    << static_cast<unsigned int>((last % 8U) * 8U);
                keccak_f1600(state_);
                position_ = 0U;
                finalized_ = true;
            }

            for (Byte& byte : output)
            {
                if (position_ == rate_)
                {
                    keccak_f1600(state_);
                    position_ = 0U;
                }
                byte = static_cast<Byte>(state_[position_ / 8U] >>
                    static_cast<unsigned int>((position_ % 8U) * 8U));
                ++position_;
            }
        }

    private:
        std::array<std::uint64_t, 25> state_{};
        std::size_t rate_;
        std::size_t position_ = 0U;
        Byte domain_;
        bool finalized_ = false;
    };

    [[nodiscard]] Bytes sponge_hash(const std::span<const Byte> input,
                                    const std::size_t rate,
                                    const Byte domain,
                                    const std::size_t output_size)
    {
        Sponge sponge(rate, domain);
        sponge.absorb(input);
        Bytes output(output_size);
        sponge.squeeze(output);
        return output;
    }

    [[nodiscard]] Seed sha3_256(const std::span<const Byte> input)
    {
        const Bytes digest = sponge_hash(input, 136U, 0x06U, 32U);
        Seed output{};
        std::copy(digest.begin(), digest.end(), output.begin());
        return output;
    }

    [[nodiscard]] std::array<Byte, 64> sha3_512(const std::span<const Byte> input)
    {
        const Bytes digest = sponge_hash(input, 72U, 0x06U, 64U);
        std::array<Byte, 64> output{};
        std::copy(digest.begin(), digest.end(), output.begin());
        return output;
    }

    [[nodiscard]] Bytes shake128(const std::span<const Byte> input, const std::size_t output_size)
    {
        return sponge_hash(input, 168U, 0x1FU, output_size);
    }

    [[nodiscard]] Bytes shake256(const std::span<const Byte> input, const std::size_t output_size)
    {
        return sponge_hash(input, 136U, 0x1FU, output_size);
    }

    void secure_zero(void* pointer, const std::size_t size) noexcept
    {
        auto* bytes = static_cast<volatile Byte*>(pointer);
        for (std::size_t i = 0; i < size; ++i)
            bytes[i] = 0U;
    }

    void secure_clear(Bytes& bytes) noexcept
    {
        if (!bytes.empty()) secure_zero(bytes.data(), bytes.size());
        bytes.clear();
    }

    void ntt(Poly& polynomial) noexcept
    {
        const auto& zeta_table = zetas();
        unsigned int k = 1U;
        for (int length = 128; length >= 2; length >>= 1)
        {
            for (int start = 0; start < 256; start += 2 * length)
            {
                const std::int32_t zeta = zeta_table[k++];
                for (int j = start; j < start + length; ++j)
                {
                    const std::int32_t t = mod_q(static_cast<std::int64_t>(zeta) *
                        polynomial.c[static_cast<std::size_t>(j + length)]);
                    const std::int32_t a = polynomial.c[static_cast<std::size_t>(j)];
                    polynomial.c[static_cast<std::size_t>(j)] = mod_q(a + t);
                    polynomial.c[static_cast<std::size_t>(j + length)] = mod_q(a - t);
                }
            }
        }
    }

    void inverse_ntt(Poly& polynomial) noexcept
    {
        const auto& zeta_table = zetas();
        unsigned int k = 127U;
        for (int length = 2; length <= 128; length <<= 1)
        {
            for (int start = 0; start < 256; start += 2 * length)
            {
                const std::int32_t zeta = zeta_table[k--];
                for (int j = start; j < start + length; ++j)
                {
                    const std::int32_t a = polynomial.c[static_cast<std::size_t>(j)];
                    const std::int32_t b = polynomial.c[static_cast<std::size_t>(j + length)];
                    polynomial.c[static_cast<std::size_t>(j)] = mod_q(a + b);
                    polynomial.c[static_cast<std::size_t>(j + length)] =
                        mod_q(static_cast<std::int64_t>(zeta) * (b - a));
                }
            }
        }
        constexpr std::int32_t inverse_128 = 3303; // 128^-1 mod 3329.
        for (std::int32_t& coefficient : polynomial.c)
            coefficient = mod_q(static_cast<std::int64_t>(coefficient) * inverse_128);
    }

    [[nodiscard]] Poly base_multiply_pair(const std::array<std::int32_t, 2>& a,
                                          const std::array<std::int32_t, 2>& b,
                                          const std::int32_t zeta) noexcept
    {
        Poly result;
        result.c[0] = mod_q(static_cast<std::int64_t>(a[0]) * b[0] +
            static_cast<std::int64_t>(zeta) * a[1] * b[1]);
        result.c[1] = mod_q(static_cast<std::int64_t>(a[0]) * b[1] +
            static_cast<std::int64_t>(a[1]) * b[0]);
        return result;
    }

    [[nodiscard]] Poly base_multiply(const Poly& a, const Poly& b) noexcept
    {
        Poly result;
        const auto& zeta_table = zetas();
        for (std::size_t i = 0; i < 64U; ++i)
        {
            const std::int32_t zeta = zeta_table[64U + i];
            const std::array<std::int32_t, 2> a0{a.c[4U * i], a.c[4U * i + 1U]};
            const std::array<std::int32_t, 2> b0{b.c[4U * i], b.c[4U * i + 1U]};
            const std::array<std::int32_t, 2> a1{a.c[4U * i + 2U], a.c[4U * i + 3U]};
            const std::array<std::int32_t, 2> b1{b.c[4U * i + 2U], b.c[4U * i + 3U]};
            const Poly r0 = base_multiply_pair(a0, b0, zeta);
            const Poly r1 = base_multiply_pair(a1, b1, mod_q(-zeta));
            result.c[4U * i] = r0.c[0];
            result.c[4U * i + 1U] = r0.c[1];
            result.c[4U * i + 2U] = r1.c[0];
            result.c[4U * i + 3U] = r1.c[1];
        }
        return result;
    }

    [[nodiscard]] Poly dot_product(const PolyVec& left, const PolyVec& right) noexcept
    {
        Poly result{};
        for (std::size_t i = 0; i < K; ++i)
        {
            const Poly product = base_multiply(left[i], right[i]);
            for (std::size_t j = 0; j < N; ++j)
                result.c[j] = mod_q(result.c[j] + product.c[j]);
        }
        return result;
    }

    void add_poly(Poly& destination, const Poly& source) noexcept
    {
        for (std::size_t i = 0; i < N; ++i)
            destination.c[i] = mod_q(destination.c[i] + source.c[i]);
    }

    void subtract_poly(Poly& destination, const Poly& source) noexcept
    {
        for (std::size_t i = 0; i < N; ++i)
            destination.c[i] = mod_q(destination.c[i] - source.c[i]);
    }

    [[nodiscard]] std::array<Byte, 3> sample_ntt_candidate(const Byte* bytes) noexcept
    {
        return {bytes[0], bytes[1], bytes[2]};
    }

    [[nodiscard]] Poly sample_ntt(const Seed& rho, const Byte x, const Byte y)
    {
        std::array<Byte, SYMBYTES + 2U> input{};
        std::copy(rho.begin(), rho.end(), input.begin());
        input[SYMBYTES] = x;
        input[SYMBYTES + 1U] = y;

        std::size_t output_length = 1024U;
        Bytes stream;
        Poly polynomial;
        std::size_t count = 0U;
        while (count < N)
        {
            count = 0U;
            stream = shake128(input, output_length);
            for (std::size_t offset = 0; offset + 2U < stream.size() && count < N; offset += 3U)
            {
                const auto candidate = sample_ntt_candidate(stream.data() + offset);
                const std::uint16_t d1 = static_cast<std::uint16_t>(candidate[0]) |
                    (static_cast<std::uint16_t>(candidate[1] & 0x0FU) << 8U);
                const std::uint16_t d2 = static_cast<std::uint16_t>(candidate[1] >> 4U) |
                    (static_cast<std::uint16_t>(candidate[2]) << 4U);
                if (d1 < Q) polynomial.c[count++] = d1;
                if (d2 < Q && count < N) polynomial.c[count++] = d2;
            }
            if (count < N)
            {
                if (output_length > (1U << 20U))
                    throw std::runtime_error("ML-KEM SampleNTT exceeded its bounded XOF workspace.");
                output_length *= 2U;
            }
        }
        secure_clear(stream);
        return polynomial;
    }

    [[nodiscard]] Poly sample_noise(const Seed& seed, const Byte nonce)
    {
        std::array<Byte, SYMBYTES + 1U> input{};
        std::copy(seed.begin(), seed.end(), input.begin());
        input[SYMBYTES] = nonce;
        Bytes buffer = shake256(input, 128U); // eta=2, 64 * 4 bytes.
        Poly polynomial;
        for (std::size_t block = 0; block < 32U; ++block)
        {
            const std::uint32_t t = static_cast<std::uint32_t>(buffer[4U * block]) |
                (static_cast<std::uint32_t>(buffer[4U * block + 1U]) << 8U) |
                (static_cast<std::uint32_t>(buffer[4U * block + 2U]) << 16U) |
                (static_cast<std::uint32_t>(buffer[4U * block + 3U]) << 24U);
            const std::uint32_t d = (t & 0x55555555U) + ((t >> 1U) & 0x55555555U);
            for (std::size_t j = 0; j < 8U; ++j)
            {
                const std::int32_t a = static_cast<std::int32_t>((d >> (4U * j)) & 0x3U);
                const std::int32_t b = static_cast<std::int32_t>((d >> (4U * j + 2U)) & 0x3U);
                polynomial.c[8U * block + j] = mod_q(a - b);
            }
        }
        secure_clear(buffer);
        secure_zero(input.data(), input.size());
        return polynomial;
    }

    [[nodiscard]] Matrix generate_matrix(const Seed& rho, const bool transpose)
    {
        Matrix matrix{};
        for (std::size_t i = 0; i < K; ++i)
        {
            for (std::size_t j = 0; j < K; ++j)
            {
                const Byte x = static_cast<Byte>(transpose ? i : j);
                const Byte y = static_cast<Byte>(transpose ? j : i);
                matrix[i][j] = sample_ntt(rho, x, y);
            }
        }
        return matrix;
    }

    [[nodiscard]] Bytes encode_poly_12(const Poly& polynomial)
    {
        Bytes output(POLY12_BYTES);
        for (std::size_t i = 0; i < N / 2U; ++i)
        {
            const std::uint16_t a = static_cast<std::uint16_t>(polynomial.c[2U * i]);
            const std::uint16_t b = static_cast<std::uint16_t>(polynomial.c[2U * i + 1U]);
            output[3U * i] = static_cast<Byte>(a & 0xFFU);
            output[3U * i + 1U] = static_cast<Byte>((a >> 8U) | ((b & 0x0FU) << 4U));
            output[3U * i + 2U] = static_cast<Byte>(b >> 4U);
        }
        return output;
    }

    [[nodiscard]] bool decode_poly_12(const std::span<const Byte> input, Poly& polynomial) noexcept
    {
        if (input.size() != POLY12_BYTES) return false;
        bool valid = true;
        for (std::size_t i = 0; i < N / 2U; ++i)
        {
            const std::uint16_t a = static_cast<std::uint16_t>(input[3U * i]) |
                (static_cast<std::uint16_t>(input[3U * i + 1U] & 0x0FU) << 8U);
            const std::uint16_t b = static_cast<std::uint16_t>(input[3U * i + 1U] >> 4U) |
                (static_cast<std::uint16_t>(input[3U * i + 2U]) << 4U);
            valid = valid && a < Q && b < Q;
            polynomial.c[2U * i] = static_cast<std::int32_t>(a % Q);
            polynomial.c[2U * i + 1U] = static_cast<std::int32_t>(b % Q);
        }
        return valid;
    }

    [[nodiscard]] Bytes encode_polyvec_12(const PolyVec& vector)
    {
        Bytes output;
        output.reserve(K * POLY12_BYTES);
        for (const Poly& polynomial : vector)
        {
            const Bytes encoded = encode_poly_12(polynomial);
            output.insert(output.end(), encoded.begin(), encoded.end());
        }
        return output;
    }

    [[nodiscard]] bool decode_polyvec_12(const std::span<const Byte> input, PolyVec& vector) noexcept
    {
        if (input.size() != K * POLY12_BYTES) return false;
        bool valid = true;
        for (std::size_t i = 0; i < K; ++i)
            valid = decode_poly_12(input.subspan(i * POLY12_BYTES, POLY12_BYTES), vector[i]) && valid;
        return valid;
    }

    [[nodiscard]] std::uint16_t compress_coefficient(const std::int32_t coefficient,
                                                     const unsigned int bits) noexcept
    {
        const std::uint32_t scale = 1U << bits;
        const std::uint32_t value = static_cast<std::uint32_t>(mod_q(coefficient));
        return static_cast<std::uint16_t>(((value * scale + static_cast<std::uint32_t>(Q / 2)) /
            static_cast<std::uint32_t>(Q)) & (scale - 1U));
    }

    [[nodiscard]] std::int32_t decompress_coefficient(const std::uint16_t value,
                                                      const unsigned int bits) noexcept
    {
        return static_cast<std::int32_t>((static_cast<std::uint32_t>(Q) * value +
            (1U << (bits - 1U))) >> bits);
    }

    [[nodiscard]] Bytes encode_compressed_poly(const Poly& polynomial, const unsigned int bits)
    {
        if (bits == 4U)
        {
            Bytes output(N / 2U);
            for (std::size_t i = 0; i < N / 2U; ++i)
            {
                const std::uint16_t a = compress_coefficient(polynomial.c[2U * i], 4U);
                const std::uint16_t b = compress_coefficient(polynomial.c[2U * i + 1U], 4U);
                output[i] = static_cast<Byte>(a | (b << 4U));
            }
            return output;
        }
        if (bits == 10U)
        {
            Bytes output(320U);
            for (std::size_t i = 0; i < N / 4U; ++i)
            {
                const std::uint16_t t0 = compress_coefficient(polynomial.c[4U * i], 10U);
                const std::uint16_t t1 = compress_coefficient(polynomial.c[4U * i + 1U], 10U);
                const std::uint16_t t2 = compress_coefficient(polynomial.c[4U * i + 2U], 10U);
                const std::uint16_t t3 = compress_coefficient(polynomial.c[4U * i + 3U], 10U);
                output[5U * i] = static_cast<Byte>(t0);
                output[5U * i + 1U] = static_cast<Byte>((t0 >> 8U) | (t1 << 2U));
                output[5U * i + 2U] = static_cast<Byte>((t1 >> 6U) | (t2 << 4U));
                output[5U * i + 3U] = static_cast<Byte>((t2 >> 4U) | (t3 << 6U));
                output[5U * i + 4U] = static_cast<Byte>(t3 >> 2U);
            }
            return output;
        }
        throw std::invalid_argument("Unsupported ML-KEM polynomial compression width.");
    }

    [[nodiscard]] Poly decode_compressed_poly(const std::span<const Byte> input,
                                              const unsigned int bits)
    {
        Poly polynomial;
        if (bits == 4U)
        {
            if (input.size() != 128U) throw std::invalid_argument("Invalid compressed 4-bit polynomial length.");
            for (std::size_t i = 0; i < N / 2U; ++i)
            {
                polynomial.c[2U * i] = decompress_coefficient(input[i] & 0x0FU, 4U);
                polynomial.c[2U * i + 1U] = decompress_coefficient(input[i] >> 4U, 4U);
            }
            return polynomial;
        }
        if (bits == 10U)
        {
            if (input.size() != 320U) throw std::invalid_argument("Invalid compressed 10-bit polynomial length.");
            for (std::size_t i = 0; i < N / 4U; ++i)
            {
                const std::uint16_t t0 = static_cast<std::uint16_t>(input[5U * i]) |
                    (static_cast<std::uint16_t>(input[5U * i + 1U]) << 8U);
                const std::uint16_t t1 = static_cast<std::uint16_t>(input[5U * i + 1U] >> 2U) |
                    (static_cast<std::uint16_t>(input[5U * i + 2U]) << 6U);
                const std::uint16_t t2 = static_cast<std::uint16_t>(input[5U * i + 2U] >> 4U) |
                    (static_cast<std::uint16_t>(input[5U * i + 3U]) << 4U);
                const std::uint16_t t3 = static_cast<std::uint16_t>(input[5U * i + 3U] >> 6U) |
                    (static_cast<std::uint16_t>(input[5U * i + 4U]) << 2U);
                polynomial.c[4U * i] = decompress_coefficient(t0 & 0x03FFU, 10U);
                polynomial.c[4U * i + 1U] = decompress_coefficient(t1 & 0x03FFU, 10U);
                polynomial.c[4U * i + 2U] = decompress_coefficient(t2 & 0x03FFU, 10U);
                polynomial.c[4U * i + 3U] = decompress_coefficient(t3 & 0x03FFU, 10U);
            }
            return polynomial;
        }
        throw std::invalid_argument("Unsupported ML-KEM polynomial decompression width.");
    }

    [[nodiscard]] Poly message_to_poly(const Seed& message) noexcept
    {
        Poly polynomial;
        for (std::size_t i = 0; i < N; ++i)
            polynomial.c[i] = ((message[i / 8U] >> (i % 8U)) & 1U) != 0U ? (Q + 1) / 2 : 0;
        return polynomial;
    }

    [[nodiscard]] Seed poly_to_message(const Poly& polynomial) noexcept
    {
        Seed message{};
        for (std::size_t i = 0; i < N; ++i)
        {
            const std::uint16_t bit = compress_coefficient(polynomial.c[i], 1U);
            message[i / 8U] |= static_cast<Byte>(bit << (i % 8U));
        }
        return message;
    }

    struct PkeKeyPair
    {
        Bytes public_key;
        Bytes secret_key;
    };

    [[nodiscard]] PkeKeyPair pke_keygen(const Seed& d)
    {
        std::array<Byte, SYMBYTES + 1U> input{};
        std::copy(d.begin(), d.end(), input.begin());
        input[SYMBYTES] = static_cast<Byte>(K);
        auto expanded = sha3_512(input);
        Seed rho{};
        Seed sigma{};
        std::copy_n(expanded.begin(), SYMBYTES, rho.begin());
        std::copy_n(expanded.begin() + static_cast<std::ptrdiff_t>(SYMBYTES), SYMBYTES, sigma.begin());

        Matrix matrix = generate_matrix(rho, false);
        PolyVec secret{};
        PolyVec error{};
        Byte nonce = 0U;
        for (std::size_t i = 0; i < K; ++i) secret[i] = sample_noise(sigma, nonce++);
        for (std::size_t i = 0; i < K; ++i) error[i] = sample_noise(sigma, nonce++);
        for (std::size_t i = 0; i < K; ++i) ntt(secret[i]);
        for (std::size_t i = 0; i < K; ++i) ntt(error[i]);

        PolyVec public_vector{};
        for (std::size_t i = 0; i < K; ++i)
        {
            public_vector[i] = dot_product(matrix[i], secret);
            add_poly(public_vector[i], error[i]);
        }

        PkeKeyPair result;
        result.public_key = encode_polyvec_12(public_vector);
        result.public_key.insert(result.public_key.end(), rho.begin(), rho.end());
        result.secret_key = encode_polyvec_12(secret);

        secure_zero(secret.data(), sizeof(secret));
        secure_zero(error.data(), sizeof(error));
        secure_zero(matrix.data(), sizeof(matrix));
        secure_zero(public_vector.data(), sizeof(public_vector));
        secure_zero(sigma.data(), sigma.size());
        secure_zero(rho.data(), rho.size());
        secure_zero(expanded.data(), expanded.size());
        return result;
    }

    [[nodiscard]] Bytes pke_encrypt(const std::span<const Byte> public_key,
                                    const Seed& message,
                                    const Seed& coins)
    {
        if (public_key.size() != PUBLIC_KEY_BYTES)
            throw std::invalid_argument("ML-KEM-768 encapsulation key must be exactly 1184 bytes.");

        PolyVec public_vector{};
        if (!decode_polyvec_12(public_key.first(K * POLY12_BYTES), public_vector))
            throw std::invalid_argument("ML-KEM-768 encapsulation key contains non-canonical polynomial coefficients.");
        Seed rho{};
        std::copy(public_key.end() - static_cast<std::ptrdiff_t>(SYMBYTES), public_key.end(), rho.begin());
        Matrix matrix_transpose = generate_matrix(rho, true);

        PolyVec r{};
        PolyVec e1{};
        Byte nonce = 0U;
        for (std::size_t i = 0; i < K; ++i) r[i] = sample_noise(coins, nonce++);
        for (std::size_t i = 0; i < K; ++i) e1[i] = sample_noise(coins, nonce++);
        Poly e2 = sample_noise(coins, nonce++);
        for (std::size_t i = 0; i < K; ++i) ntt(r[i]);

        PolyVec u{};
        for (std::size_t i = 0; i < K; ++i)
        {
            u[i] = dot_product(matrix_transpose[i], r);
            inverse_ntt(u[i]);
            add_poly(u[i], e1[i]);
        }

        Poly v = dot_product(public_vector, r);
        inverse_ntt(v);
        add_poly(v, e2);
        const Poly message_poly = message_to_poly(message);
        add_poly(v, message_poly);

        Bytes ciphertext;
        ciphertext.reserve(CIPHERTEXT_BYTES);
        for (const Poly& polynomial : u)
        {
            const Bytes encoded = encode_compressed_poly(polynomial, 10U);
            ciphertext.insert(ciphertext.end(), encoded.begin(), encoded.end());
        }
        const Bytes encoded_v = encode_compressed_poly(v, 4U);
        ciphertext.insert(ciphertext.end(), encoded_v.begin(), encoded_v.end());

        secure_zero(public_vector.data(), sizeof(public_vector));
        secure_zero(matrix_transpose.data(), sizeof(matrix_transpose));
        secure_zero(r.data(), sizeof(r));
        secure_zero(e1.data(), sizeof(e1));
        secure_zero(&e2, sizeof(e2));
        secure_zero(&v, sizeof(v));
        return ciphertext;
    }

    [[nodiscard]] Seed pke_decrypt(const std::span<const Byte> secret_key,
                                   const std::span<const Byte> ciphertext)
    {
        if (secret_key.size() != PKE_SECRET_KEY_BYTES)
            throw std::invalid_argument("ML-KEM-768 PKE secret key must be exactly 1152 bytes.");
        if (ciphertext.size() != CIPHERTEXT_BYTES)
            throw std::invalid_argument("ML-KEM-768 ciphertext must be exactly 1088 bytes.");

        PolyVec secret{};
        if (!decode_polyvec_12(secret_key, secret))
            throw std::invalid_argument("ML-KEM-768 decapsulation key contains non-canonical secret coefficients.");
        PolyVec u{};
        std::size_t offset = 0U;
        for (std::size_t i = 0; i < K; ++i)
        {
            u[i] = decode_compressed_poly(ciphertext.subspan(offset, 320U), 10U);
            offset += 320U;
            ntt(u[i]);
        }
        Poly v = decode_compressed_poly(ciphertext.subspan(offset, 128U), 4U);
        Poly product = dot_product(secret, u);
        inverse_ntt(product);
        subtract_poly(v, product);
        const Seed message = poly_to_message(v);

        secure_zero(secret.data(), sizeof(secret));
        secure_zero(u.data(), sizeof(u));
        secure_zero(&v, sizeof(v));
        secure_zero(&product, sizeof(product));
        return message;
    }

    struct KemKeyPair
    {
        Bytes public_key;
        Bytes secret_key;
    };

    [[nodiscard]] KemKeyPair kem_keygen()
    {
        Seed d{};
        Seed z{};
        crypto::SecureRandom::fill(d);
        crypto::SecureRandom::fill(z);
        PkeKeyPair pke = pke_keygen(d);
        const Seed h = sha3_256(pke.public_key);

        KemKeyPair result;
        result.public_key = std::move(pke.public_key);
        result.secret_key.reserve(SECRET_KEY_BYTES);
        result.secret_key.insert(result.secret_key.end(), pke.secret_key.begin(), pke.secret_key.end());
        result.secret_key.insert(result.secret_key.end(), result.public_key.begin(), result.public_key.end());
        result.secret_key.insert(result.secret_key.end(), h.begin(), h.end());
        result.secret_key.insert(result.secret_key.end(), z.begin(), z.end());

        secure_clear(pke.secret_key);
        secure_zero(d.data(), d.size());
        secure_zero(z.data(), z.size());
        return result;
    }

    struct Encapsulation
    {
        Bytes ciphertext;
        SharedSecret shared_secret{};
    };

    [[nodiscard]] Encapsulation kem_encapsulate(const std::span<const Byte> public_key)
    {
        if (public_key.size() != PUBLIC_KEY_BYTES)
            throw std::invalid_argument("ML-KEM-768 encapsulation key must be exactly 1184 bytes.");
        PolyVec decoded_public{};
        if (!decode_polyvec_12(public_key.first(K * POLY12_BYTES), decoded_public))
            throw std::invalid_argument("ML-KEM-768 encapsulation key contains non-canonical coefficients.");
        secure_zero(decoded_public.data(), sizeof(decoded_public));

        Seed message{};
        crypto::SecureRandom::fill(message);
        const Seed h = sha3_256(public_key);
        std::array<Byte, 2U * SYMBYTES> input{};
        std::copy(message.begin(), message.end(), input.begin());
        std::copy(h.begin(), h.end(), input.begin() + static_cast<std::ptrdiff_t>(SYMBYTES));
        auto expanded = sha3_512(input);

        Encapsulation result;
        std::copy_n(expanded.begin(), SYMBYTES, result.shared_secret.begin());
        Seed coins{};
        std::copy_n(expanded.begin() + static_cast<std::ptrdiff_t>(SYMBYTES), SYMBYTES, coins.begin());
        result.ciphertext = pke_encrypt(public_key, message, coins);

        secure_zero(message.data(), message.size());
        secure_zero(coins.data(), coins.size());
        secure_zero(expanded.data(), expanded.size());
        secure_zero(input.data(), input.size());
        return result;
    }

    [[nodiscard]] SharedSecret kem_decapsulate(const std::span<const Byte> secret_key,
                                               const std::span<const Byte> ciphertext)
    {
        if (secret_key.size() != SECRET_KEY_BYTES)
            throw std::invalid_argument("ML-KEM-768 decapsulation key must be exactly 2400 bytes.");
        if (ciphertext.size() != CIPHERTEXT_BYTES)
            throw std::invalid_argument("ML-KEM-768 ciphertext must be exactly 1088 bytes.");

        const auto pke_secret_key = secret_key.first(PKE_SECRET_KEY_BYTES);
        const auto public_key = secret_key.subspan(PKE_SECRET_KEY_BYTES, PUBLIC_KEY_BYTES);
        const auto stored_hash = secret_key.subspan(PKE_SECRET_KEY_BYTES + PUBLIC_KEY_BYTES, SYMBYTES);
        const auto rejection_seed = secret_key.last(SYMBYTES);

        const Seed computed_hash = sha3_256(public_key);
        Byte key_check_difference = 0U;
        for (std::size_t i = 0; i < SYMBYTES; ++i)
            key_check_difference |= static_cast<Byte>(computed_hash[i] ^ stored_hash[i]);
        if (key_check_difference != 0U)
            throw std::invalid_argument("ML-KEM-768 decapsulation key integrity check failed.");

        Seed message = pke_decrypt(pke_secret_key, ciphertext);
        std::array<Byte, 2U * SYMBYTES> input{};
        std::copy(message.begin(), message.end(), input.begin());
        std::copy(stored_hash.begin(), stored_hash.end(), input.begin() + static_cast<std::ptrdiff_t>(SYMBYTES));
        auto expanded = sha3_512(input);

        Seed coins{};
        SharedSecret candidate{};
        std::copy_n(expanded.begin(), SYMBYTES, candidate.begin());
        std::copy_n(expanded.begin() + static_cast<std::ptrdiff_t>(SYMBYTES), SYMBYTES, coins.begin());
        const Bytes reencryption = pke_encrypt(public_key, message, coins);

        Byte difference = static_cast<Byte>(reencryption.size() ^ ciphertext.size());
        for (std::size_t i = 0; i < ciphertext.size(); ++i)
            difference |= static_cast<Byte>(reencryption[i] ^ ciphertext[i]);

        Bytes rejection_input;
        rejection_input.reserve(SYMBYTES + ciphertext.size());
        rejection_input.insert(rejection_input.end(), rejection_seed.begin(), rejection_seed.end());
        rejection_input.insert(rejection_input.end(), ciphertext.begin(), ciphertext.end());
        Bytes fallback = shake256(rejection_input, SYMBYTES);

        const Byte valid_mask = static_cast<Byte>(0U - static_cast<unsigned int>(difference == 0U));
        SharedSecret result{};
        for (std::size_t i = 0; i < SYMBYTES; ++i)
            result[i] = static_cast<Byte>((candidate[i] & valid_mask) |
                (fallback[i] & static_cast<Byte>(~valid_mask)));

        secure_zero(message.data(), message.size());
        secure_zero(coins.data(), coins.size());
        secure_zero(candidate.data(), candidate.size());
        secure_zero(expanded.data(), expanded.size());
        secure_clear(rejection_input);
        secure_clear(fallback);
        secure_zero(input.data(), input.size());
        return result;
    }

    [[nodiscard]] bool matches_hex(const std::span<const Byte> bytes,
                                   const std::string_view expected) noexcept
    {
        if (bytes.size() * 2U != expected.size()) return false;
        const auto hex_value = [](const char ch) noexcept -> int
        {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            const int high = hex_value(expected[2U * i]);
            const int low = hex_value(expected[2U * i + 1U]);
            if (high < 0 || low < 0) return false;
            if (bytes[i] != static_cast<Byte>((high << 4) | low)) return false;
        }
        return true;
    }

    void run_primitive_self_tests()
    {
        const Bytes empty;
        const Seed sha3_256_empty = sha3_256(empty);
        if (!matches_hex(sha3_256_empty,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"))
            throw std::runtime_error("SHA3-256 known-answer test failed.");

        const auto sha3_512_empty = sha3_512(empty);
        if (!matches_hex(sha3_512_empty,
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"))
            throw std::runtime_error("SHA3-512 known-answer test failed.");

        const Bytes shake128_empty = shake128(empty, 32U);
        if (!matches_hex(shake128_empty,
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"))
            throw std::runtime_error("SHAKE128 known-answer test failed.");

        const Bytes shake256_empty = shake256(empty, 32U);
        if (!matches_hex(shake256_empty,
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"))
            throw std::runtime_error("SHAKE256 known-answer test failed.");

        Poly a{};
        Poly b{};
        std::array<std::int64_t, N> expected{};
        for (std::size_t i = 0; i < N; ++i)
        {
            a.c[i] = static_cast<std::int32_t>((13U * i * i + 11U * i + 7U) % Q);
            b.c[i] = static_cast<std::int32_t>((17U * i + 5U * (i % 19U) + 3U) % Q);
        }
        for (std::size_t i = 0; i < N; ++i)
        {
            for (std::size_t j = 0; j < N; ++j)
            {
                const std::size_t degree = i + j;
                const std::int64_t term = static_cast<std::int64_t>(a.c[i]) * b.c[j];
                if (degree < N) expected[degree] += term;
                else expected[degree - N] -= term;
            }
        }
        Poly a_hat = a;
        Poly b_hat = b;
        ntt(a_hat);
        ntt(b_hat);
        Poly product_hat = base_multiply(a_hat, b_hat);
        inverse_ntt(product_hat);
        for (std::size_t i = 0; i < N; ++i)
        {
            if (product_hat.c[i] != mod_q(expected[i]))
                throw std::runtime_error("ML-KEM NTT/base multiplication self-test failed.");
        }
        secure_zero(a_hat.c.data(), sizeof(a_hat.c));
        secure_zero(b_hat.c.data(), sizeof(b_hat.c));
        secure_zero(product_hat.c.data(), sizeof(product_hat.c));
    }

    [[nodiscard]] bool constant_time_equal(const SharedSecret& left,
                                           const SharedSecret& right) noexcept
    {
        Byte difference = 0U;
        for (std::size_t i = 0; i < left.size(); ++i)
            difference |= static_cast<Byte>(left[i] ^ right[i]);
        return difference == 0U;
    }
}

MlKem768KeyPair::~MlKem768KeyPair()
{
    if (!decapsulation_key.empty()) secure_zero(decapsulation_key.data(), decapsulation_key.size());
}

MlKem768Encapsulation::~MlKem768Encapsulation()
{
    secure_zero(shared_secret.data(), shared_secret.size());
}

bool mlkem768_available() noexcept
{
    return true;
}

MlKem768KeyPair mlkem768_generate_keypair()
{
    KemKeyPair generated = kem_keygen();
    MlKem768KeyPair result;
    result.encapsulation_key = std::move(generated.public_key);
    result.decapsulation_key = std::move(generated.secret_key);
    return result;
}

MlKem768Encapsulation mlkem768_encapsulate(const std::span<const std::uint8_t> encapsulation_key)
{
    Encapsulation generated = kem_encapsulate(encapsulation_key);
    MlKem768Encapsulation result;
    result.ciphertext = std::move(generated.ciphertext);
    result.shared_secret = generated.shared_secret;
    secure_zero(generated.shared_secret.data(), generated.shared_secret.size());
    return result;
}

std::array<std::uint8_t, MLKEM768_SHARED_SECRET_BYTES> mlkem768_decapsulate(
    const std::span<const std::uint8_t> decapsulation_key,
    const std::span<const std::uint8_t> ciphertext)
{
    return kem_decapsulate(decapsulation_key, ciphertext);
}

MlKem768DemoResult run_mlkem768_demo()
{
    MlKem768DemoResult result;
    result.available = true;
    result.encapsulation_key_bytes = PUBLIC_KEY_BYTES;
    result.ciphertext_bytes = CIPHERTEXT_BYTES;
    result.shared_secret_bytes = SYMBYTES;

    try
    {
        run_primitive_self_tests();
        MlKem768KeyPair key_pair = mlkem768_generate_keypair();
        MlKem768Encapsulation encapsulation = mlkem768_encapsulate(key_pair.encapsulation_key);
        SharedSecret recovered = mlkem768_decapsulate(key_pair.decapsulation_key, encapsulation.ciphertext);
        result.passed = constant_time_equal(encapsulation.shared_secret, recovered);
        result.detail = result.passed
            ? "Portable in-tree C++ ML-KEM-768 key generation, encapsulation, and decapsulation succeeded."
            : "ML-KEM-768 self-test failed: encapsulated and decapsulated shared secrets differ.";
        secure_clear(encapsulation.ciphertext);
        secure_zero(recovered.data(), recovered.size());
    }
    catch (const std::exception& exception)
    {
        result.passed = false;
        result.detail = std::string("ML-KEM-768 self-test failed: ") + exception.what();
    }
    return result;
}

std::string mlkem768_status_message()
{
    return "ML-KEM-768 is provided by the portable in-tree C++ implementation (FIPS 203 parameter set). No Windows CNG ML-KEM API is required.";
}
}
