#include "Random/SecureRandom.h"
#include "ErrorHandling/CryptoException.h"

#include <array>
#include <cerrno>
#include <climits>

#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
#elif defined(__linux__)
    #include <sys/random.h>
    #include <fcntl.h>
    #include <unistd.h>
#elif defined(__APPLE__)
    #include <cstdlib>
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace crypto
{
    void SecureRandom::fill(const std::span<std::uint8_t> output)
    {
        if (output.empty()) return;
#if defined(_WIN32)
        std::size_t offset = 0;
        while (offset < output.size())
        {
            const std::size_t remaining = output.size() - offset;
            const auto chunk = static_cast<ULONG>(remaining > static_cast<std::size_t>(ULONG_MAX) ? ULONG_MAX : remaining);
            const NTSTATUS status = BCryptGenRandom(nullptr,
                reinterpret_cast<PUCHAR>(output.data() + offset), chunk,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (status < 0) raise_error(ErrorCode::RandomGenerationFailed, "Windows system random number generation failed.");
            offset += static_cast<std::size_t>(chunk);
        }
#elif defined(__linux__)
        std::size_t offset = 0;
        while (offset < output.size())
        {
            const ssize_t result = ::getrandom(output.data() + offset, output.size() - offset, 0);
            if (result > 0) { offset += static_cast<std::size_t>(result); continue; }
            if (result < 0 && errno == EINTR) continue;
            break;
        }
        if (offset < output.size())
        {
            const int fd = ::open("/dev/urandom", O_RDONLY);
            if (fd < 0) raise_error(ErrorCode::RandomGenerationFailed, "Unable to access the operating system random source.");
            while (offset < output.size())
            {
                const ssize_t result = ::read(fd, output.data() + offset, output.size() - offset);
                if (result > 0) offset += static_cast<std::size_t>(result);
                else if (result < 0 && errno == EINTR) continue;
                else { ::close(fd); raise_error(ErrorCode::RandomGenerationFailed, "Reading the operating system random source failed."); }
            }
            ::close(fd);
        }
#elif defined(__APPLE__)
        arc4random_buf(output.data(), output.size());
#elif defined(__unix__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        std::size_t offset = 0;
        const int fd = ::open("/dev/urandom", O_RDONLY);
        if (fd < 0) raise_error(ErrorCode::RandomGenerationFailed, "Unable to access the operating system random source.");
        while (offset < output.size())
        {
            const ssize_t result = ::read(fd, output.data() + offset, output.size() - offset);
            if (result > 0) offset += static_cast<std::size_t>(result);
            else if (result < 0 && errno == EINTR) continue;
            else { ::close(fd); raise_error(ErrorCode::RandomGenerationFailed, "Reading the operating system random source failed."); }
        }
        ::close(fd);
#else
        raise_error(ErrorCode::UnsupportedPlatform, "No supported operating system random source is available.");
#endif
    }

    std::vector<std::uint8_t> SecureRandom::bytes(const std::size_t count)
    {
        std::vector<std::uint8_t> result(count);
        fill(result);
        return result;
    }

    std::uint64_t SecureRandom::u64()
    {
        std::array<std::uint8_t, sizeof(std::uint64_t)> data{};
        fill(data);
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < data.size(); ++i)
            value |= static_cast<std::uint64_t>(data[i]) << static_cast<unsigned int>(i * 8U);
        return value;
    }

    std::uint64_t SecureRandom::uniform_u64(const std::uint64_t minimum, const std::uint64_t maximum)
    {
        if (minimum > maximum) raise_error(ErrorCode::InvalidArgument, "Random integer range has minimum greater than maximum.");
        const std::uint64_t range = maximum - minimum + 1U;
        if (range == 0) return u64();
        const std::uint64_t threshold = (std::uint64_t{0} - range) % range;
        while (true)
        {
            const std::uint64_t value = u64();
            if (value >= threshold) return minimum + (value % range);
        }
    }

    BigInt SecureRandom::below(const BigInt& exclusive_upper_bound)
    {
        if (exclusive_upper_bound <= 0)
            raise_error(ErrorCode::InvalidArgument, "Big integer random upper bound must be positive.");
        if (exclusive_upper_bound == 1) return 0;

        const std::size_t bits = bit_length(exclusive_upper_bound - 1);
        const std::size_t count = (bits + 7U) / 8U;
        const auto unused = static_cast<unsigned int>(count * 8U - bits);
        const auto mask = static_cast<std::uint8_t>(0xFFU >> unused);
        while (true)
        {
            auto data = bytes(count);
            data.front() &= mask;
            BigInt candidate = 0;
            for (const std::uint8_t byte : data) { candidate <<= 8; candidate += byte; }
            if (candidate < exclusive_upper_bound) return candidate;
        }
    }
}
