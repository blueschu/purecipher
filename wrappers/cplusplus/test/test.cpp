#include "purecipher.hpp"

#include <iostream>
#include <algorithm>

using purecipher::Cipher;
using purecipher::SubstitutionBuilder;

namespace {
    bool test_builder_new_matches_null() {
        const std::array<Cipher, 2> ciphers{
            SubstitutionBuilder().into_cipher(),
            Cipher::null(),
        };
        uint8_t buf;

        for (uint_fast16_t b = 0; b <= std::numeric_limits<uint8_t>::max(); ++b) {
            for (const auto& cipher : ciphers) {
                buf = static_cast<uint8_t>(b);
                cipher.encipher_inplace(&buf, 1);
                if (buf != b) {
                    return false;
                }
            }
        }
        return true;
    };

    const auto TEST_CASES = std::array{
        std::make_pair(test_builder_new_matches_null, "test_false"),
    };
}

int main() {
    bool pass_flag = true;

    const auto run_test = [&pass_flag](const auto& step) {
        std::cout << "Running " << step.second << " ... ";
        if (!step.first()) {
            std::cout << "FAILED\n";
            pass_flag = false;
        } else {
            std::cout << "OK\n";
        }
    };

    std::for_each(TEST_CASES.begin(), TEST_CASES.end(), run_test);

    if (!pass_flag) {
        return 1;
    }
    return 0;
}

