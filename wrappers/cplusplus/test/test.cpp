#include "purecipher.hpp"

#include <iostream>
#include <algorithm>

#define TEST_CASE(LABEL) test_case_t{LABEL, #LABEL}

#define ITERABLE_EQUAL(LEFT, RIGHT) std::equal((LEFT).begin(), (LEFT).end(), (RIGHT).begin())

namespace {
    using purecipher::Cipher;
    using purecipher::SubstitutionBuilder;

    /// Raw sample text to be used in cipher test cases.
    constexpr std::string_view ROT13_SAMPLE_RAW = "Looks good! \xF0\x9F\x91\x8D";

    /// Ciphered sample text to be used in cipher test cases.
    constexpr std::string_view ROT13_SAMPLE_CIPHERED = "Ybbxf tbbq! \xF0\x9F\x91\x8D";

    /// Trivial structure representing a labeled test case.
    struct test_case_t {
        bool (* body)();
        std::string_view label;
    };

    /// Helper function for asserting that a cipher enciphers and deciphers
    /// strings as expected.
    bool check_cipher_string(
        const Cipher& cipher,
        const std::string& input,
        const std::string& expected_output
    ) {
        const std::string encipher_text = cipher.encipher(input);
        return encipher_text == expected_output && input == cipher.decipher(encipher_text);
    }

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

    bool test_cipher_vector() {
        const Cipher cipher_rot13{Cipher::rot13()};
        // Copy sample strings into vectors to ensure that the byte as unsigned.
        // Comparing signed char to unsigned chars will fail for values >=128.
        const std::vector<uint8_t> sample_raw{ROT13_SAMPLE_RAW.begin(), ROT13_SAMPLE_RAW.end()};
        const std::vector<uint8_t> sample_ciphered{ROT13_SAMPLE_CIPHERED.begin(), ROT13_SAMPLE_CIPHERED.end()};

        std::vector<uint8_t> output = cipher_rot13.encipher(sample_raw);

        return ITERABLE_EQUAL(sample_ciphered, output)
            && ITERABLE_EQUAL(sample_raw, cipher_rot13.decipher(output));
    }

    bool test_cipher_vector_inplace() {
        const Cipher cipher_rot13{Cipher::rot13()};
        const std::vector<uint8_t> sample_raw{ROT13_SAMPLE_RAW.begin(), ROT13_SAMPLE_RAW.end()};
        const std::vector<uint8_t> sample_ciphered{ROT13_SAMPLE_CIPHERED.begin(), ROT13_SAMPLE_CIPHERED.end()};

        std::vector<uint8_t> buffer{sample_raw};

        cipher_rot13.encipher_inplace(buffer);
        if (!ITERABLE_EQUAL(sample_ciphered, buffer)) {
            return false;
        }
        cipher_rot13.decipher_inplace(buffer);
        return ITERABLE_EQUAL(sample_raw, buffer);
    }

    bool test_rot13() {
        return check_cipher_string(Cipher::rot13(), "A well filled with pineapples.", "N jryy svyyrq jvgu cvarnccyrf.");
    }

    bool test_caesar() {
        return check_cipher_string(Cipher::caesar(), "We attack at dawn.", "Zh dwwdfn dw gdzq.");
    }

    bool test_leet() {
        return check_cipher_string(Cipher::leet(), "Pure ciphers are the BEST!", "Pur3 c!ph3rs @r3 1h3 BE5Ti");
    }

    /// All test cases that will be run.
    constexpr auto TEST_CASES = std::array{
        TEST_CASE(test_builder_new_matches_null),
        TEST_CASE(test_cipher_vector),
        TEST_CASE(test_cipher_vector_inplace),
        TEST_CASE(test_rot13),
        TEST_CASE(test_caesar),
        TEST_CASE(test_leet),
    };
}

int main() {
    bool pass_flag = true;

    const auto run_test = [&pass_flag](const test_case_t& test) {
        std::cout << "Running " << test.label << " ... ";
        if (!test.body()) {
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
