#include "BigInteger/BigInteger.h"
#include "Encoding/Encoding.h"
#include "Logger/Logger.h"
#include "PerformanceMonitor/PerformanceMonitor.h"
#include "Random/SecureRandom.h"
#include "Serialization/ByteReader.h"
#include "Serialization/ByteWriter.h"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <functional>

namespace
{
    void expect(const bool condition, const std::string& message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    template <typename Function>
    void expect_crypto_error(Function&& function, const std::string& message)
    {
        bool exceptionThrown = false;
        try
        {
            std::invoke(std::forward<Function>(function));
        }
        catch (const crypto::CryptoException&)
        {
            exceptionThrown = true;
        }
        expect(exceptionThrown, message);
    }

    void test_encoding()
    {
        const std::string source = "CryptoProject common module";
        const auto bytes = crypto::utf8_to_bytes(source);
        const auto decoded = crypto::hex_decode(crypto::hex_encode(bytes));
        expect(crypto::bytes_to_utf8(decoded) == source, "Encoding round-trip failed.");
        expect(crypto::is_valid_utf8(bytes), "Valid UTF-8 was rejected.");

        const std::vector<std::uint8_t> invalidUtf8{0xC0U, 0xAFU};
        expect(!crypto::is_valid_utf8(invalidUtf8), "Invalid UTF-8 was accepted.");
        expect_crypto_error(
            [] { (void)crypto::hex_decode("0G"); },
            "Invalid hexadecimal input did not raise CryptoException.");
    }

    void test_serialization()
    {
        crypto::ByteWriter writer;
        writer.write_u8(0xABU);
        writer.write_u16(0x1234U);
        writer.write_u32(0x12345678U);
        writer.write_u64(0x0123456789ABCDEFULL);
        writer.write_string("Serialization test");

        crypto::ByteReader reader(writer.data());
        expect(reader.read_u8() == 0xABU, "uint8 serialization failed.");
        expect(reader.read_u16() == 0x1234U, "uint16 serialization failed.");
        expect(reader.read_u32() == 0x12345678U, "uint32 serialization failed.");
        expect(reader.read_u64() == 0x0123456789ABCDEFULL, "uint64 serialization failed.");
        expect(reader.read_string() == "Serialization test", "String serialization failed.");
        expect(reader.empty(), "Reader did not reach the end of the input.");

        const std::vector<std::uint8_t> truncatedInput{0x01U};
        crypto::ByteReader truncatedReader(truncatedInput);
        expect_crypto_error(
            [&truncatedReader] { (void)truncatedReader.read_u32(); },
            "Truncated serialized input did not raise CryptoException.");
    }

    void test_big_integer()
    {
        using crypto::BigInt;
        expect(crypto::bit_length(BigInt(255)) == 8U, "Bit length failed.");
        expect(crypto::gcd(BigInt(-54), BigInt(24)) == 6, "GCD failed.");
        expect(crypto::mod_pow(BigInt(4), BigInt(13), BigInt(497)) == 445, "Modular exponentiation failed.");
        expect(crypto::from_decimal("-123456789") == BigInt(-123456789), "Decimal parsing failed.");
        expect(crypto::from_hex("0x1abcdef") == BigInt(0x1abcdef), "Hex parsing failed.");
        expect(crypto::to_hex(BigInt(0xBEEF), true) == "BEEF", "Hex formatting failed.");
    }

    void test_random()
    {
        expect(crypto::SecureRandom::bytes(32U).size() == 32U, "Random byte count is incorrect.");
        expect(crypto::SecureRandom::uniform_u64(9U, 9U) == 9U, "Single-value range failed.");
        for (int i = 0; i < 100; ++i)
        {
            const auto value = crypto::SecureRandom::uniform_u64(3U, 17U);
            expect(value >= 3U && value <= 17U, "Random value is outside the requested range.");
            const auto big = crypto::SecureRandom::below(crypto::BigInt(1000));
            expect(big >= 0 && big < 1000, "Random big integer is outside the requested range.");
        }
    }

    void test_performance_monitor()
    {
        crypto::PerformanceMonitor monitor;
        const int result = monitor.measure("SmokeTest.Calculation", "CPU", []
        {
            int sum = 0;
            for (int i = 0; i < 1000; ++i) sum += i;
            return sum;
        });
        expect(result == 499500, "PerformanceMonitor changed the measured function result.");

        monitor.measure("SmokeTest.Calculation", "CPU", []
        {
            volatile int value = 7;
            (void)value;
        });

        monitor.record_gpu_timing("SmokeTest.GPUPlaceholder", 1.25, 0.50, 2.00,
                                  "Synthetic timing record for CSV schema validation.");
        expect(monitor.records().size() == 3U, "Performance records were not stored.");
        const auto summaries = monitor.summary();
        expect(summaries.size() == 2U, "Performance summary grouping failed.");
        bool foundCpuSummary = false;
        for (const auto& item : summaries)
        {
            if (item.stage == "SmokeTest.Calculation" && item.backend == "CPU")
            {
                foundCpuSummary = true;
                expect(item.run_count == 2U, "Repeated-run count is incorrect.");
                expect(item.minimum_wall_time_ms <= item.maximum_wall_time_ms,
                       "Performance summary minimum exceeds maximum.");
            }
        }
        expect(foundCpuSummary, "CPU performance summary was not found.");

        const auto directory = std::filesystem::temp_directory_path() / "CryptoProjectCommonSmokeTest";
        const auto detailed = directory / "performance.csv";
        const auto summary = directory / "summary.csv";
        monitor.export_csv(detailed);
        monitor.export_summary_csv(summary);
        expect(std::filesystem::exists(detailed), "Detailed CSV was not created.");
        expect(std::filesystem::exists(summary), "Summary CSV was not created.");
        std::filesystem::remove_all(directory);
    }
}

int main()
{
    try
    {
        crypto::Logger::instance().set_min_level(crypto::LogLevel::Error);
        test_encoding();
        test_serialization();
        test_big_integer();
        test_random();
        test_performance_monitor();
        std::cout << "[PASS] Common module smoke tests completed successfully.\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[FAIL] " << exception.what() << '\n';
        return 1;
    }
}
