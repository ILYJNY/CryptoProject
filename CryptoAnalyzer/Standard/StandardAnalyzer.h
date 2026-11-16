#pragma once

#include "RSA/RSA.h"

#include <string>
#include <vector>

namespace crypto::analyzer
{
    struct CheckResult
    {
        std::string name;
        bool passed = false;
        std::string detail;
    };

    struct RsaAuditResult
    {
        bool acceptable_for_policy = false;
        std::size_t modulus_bits = 0;
        std::string recommendation;
    };

    class StandardAnalyzer final
    {
    public:
        [[nodiscard]] static std::vector<CheckResult> run_known_answer_tests();
        [[nodiscard]] static RsaAuditResult audit_rsa_public_key(
            const standard::RsaPublicKey& public_key);
    };
}
