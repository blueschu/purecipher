/*
 * MIT License
 *
 * Copyright (c) 2018 Brian Schubert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "purecipher.h"

static bool test_builder_new_matches_null(void) {
    bool pass = true;
    uint8_t buf;

    const purecipher_obj_t ciphers[2] = {
        purecipher_builder_into_cipher(purecipher_builder_new()),
        purecipher_cipher_null(),
    };

    for (uint_fast16_t b = 0; b <= UINT8_MAX; b++) {
        for (size_t i = 0; i < 2; i++) {
            buf = (uint8_t) b;
            purecipher_encipher_buffer(ciphers[i], &buf, 1);
            if (buf != b) {
                pass = false;
            }
        }
    }

    for (size_t i = 0; i < 2; i++) {
        purecipher_free(ciphers[i]);
    }
    return pass;
}

static bool test_builder_rotate_forward(void) {
    bool pass = true;
    // Check that every possible shift value is handled correctly.
    for (int32_t offset = 0; offset <= UINT8_MAX; offset++) {
        purecipher_obj_t cipher;
        uint8_t buf;
        {
            purecipher_builder_t *builder = purecipher_builder_new();
            purecipher_builder_rotate(builder, 0, UINT8_MAX, offset);
            cipher = purecipher_builder_into_cipher(builder);
        }
        // Check that all bytes are ciphered correctly for the shift.
        for (uint_fast16_t b = 0; b <= UINT8_MAX; b++) {
            buf = (uint8_t) b;
            purecipher_encipher_buffer(cipher, &buf, 1);
            if (buf != (uint8_t) (b + offset)) {
                pass = false;
            }
            purecipher_decipher_buffer(cipher, &buf, 1);
            if (buf != b) {
                pass = false;
            }
        }
        purecipher_free(cipher);
    }
    return pass;
}

static bool test_builder_rotate_backward(void) {
    bool pass = true;
    // Check that every possible shift value is handled correctly.
    for (int32_t offset = -UINT8_MAX; offset <= 0; offset++) {
        purecipher_obj_t cipher;
        uint8_t buf;
        {
            purecipher_builder_t *builder = purecipher_builder_new();
            purecipher_builder_rotate(builder, 0, UINT8_MAX, offset);
            cipher = purecipher_builder_into_cipher(builder);
        }
        // Check that all bytes are ciphered correctly for the shift.
        for (uint_fast16_t b = 0; b <= UINT8_MAX; b++) {
            buf = (uint8_t) b;
            purecipher_encipher_buffer(cipher, &buf, 1);
            if (buf != (uint8_t) (b + offset)) {
                pass = false;
            }
            purecipher_decipher_buffer(cipher, &buf, 1);
            if (buf != b) {
                pass = false;
            }
        }
        purecipher_free(cipher);
    }
    return pass;
}

static bool test_builder_swap(void) {
    bool pass;
    purecipher_obj_t cipher;
    {
        purecipher_builder_t *builder = purecipher_builder_new();
        const uint8_t mappings[4][2] = {
            {'a', 'b'}, // a->b, b->a
            {'b', 'c'}, // c->a, b->c, a->b
            {'d', 'e'}, // c->a, b->c, a->b, d->e, e->d
            {'d', 'c'}, // d->a, c->e, b->c, a->b, e->d
        };

        for (size_t i = 0; i < sizeof(mappings)/sizeof(mappings[0]); i++) {
            purecipher_builder_swap(builder, mappings[i][0], mappings[i][1]);
        }
        cipher = purecipher_builder_into_cipher(builder);
    }

    uint8_t buffer[] = "abcde";
    purecipher_encipher_buffer(cipher, buffer, sizeof(buffer));
    pass = 0 == memcmp("bcead", buffer, sizeof(buffer));

    purecipher_free(cipher);
    return pass;
}

static bool test_caesar(void) {
    bool pass;
    const purecipher_obj_t caesar = purecipher_cipher_caesar();
    const uint8_t *expected = (uint8_t *) "Zh dwwdfn dw gdzq.";

    uint8_t buffer[] = "We attack at dawn.";

    purecipher_encipher_buffer(caesar, buffer, sizeof(buffer));

    pass = 0 == memcmp(expected, buffer, sizeof(buffer));

    purecipher_free(caesar);
    return pass;
}

static bool test_rot13(void) {
    bool pass;
    const purecipher_obj_t rot13 = purecipher_cipher_rot13();
    const uint8_t *expected = (uint8_t *) "Ybiryl cyhzntr, gur Abejrtvna Oyhr.";

    uint8_t buffer[] = "Lovely plumage, the Norwegian Blue.";

    purecipher_encipher_buffer(rot13, buffer, sizeof(buffer));

    pass = 0 == memcmp(expected, buffer, sizeof(buffer));

    purecipher_free(rot13);
    return pass;
}

static bool test_leet(void) {
    bool pass;
    const purecipher_obj_t leet = purecipher_cipher_leet();
    const uint8_t *expected = (uint8_t *) "Pur3 c!ph3rs @r3 1h3 BE5Ti";

    uint8_t buffer[] = "Pure ciphers are the BEST!";

    purecipher_encipher_buffer(leet, buffer, sizeof(buffer));

    pass = 0 == memcmp(expected, buffer, sizeof(buffer));

    purecipher_free(leet);
    return pass;
}

static bool test_null(void) {
    bool pass;
    const purecipher_obj_t cipher_null = purecipher_cipher_null();
    const uint8_t *expected = (uint8_t *) "Boring text that does not change.";

    uint8_t buffer[] = "Boring text that does not change.";

    purecipher_encipher_buffer(cipher_null, buffer, sizeof(buffer));

    pass = 0 == memcmp(expected, buffer, sizeof(buffer));

    purecipher_free(cipher_null);
    return pass;
}

/*
 * Run the provided named test case, setting the pass_flag to false if it fails.
 *
 * A failure notification is printed to stderr in the event of a test failure.
 * Otherwise, a pass notification is printed to stdout.
 */
static void run_test(bool test_case(), const char *name, bool *pass_flag) {
    if (!test_case()) {
        *pass_flag = false;
        fprintf(stderr, "FAILED: %s\n", name);
    } else {
        printf("PASSED: %s\n", name);
    }
}

int main(void) {
    bool pass_flag = true;

    run_test(test_builder_new_matches_null, "test_builder_new_matches_null", &pass_flag);
    run_test(test_builder_rotate_forward, "test_builder_rotate_forward", &pass_flag);
    run_test(test_builder_rotate_backward, "test_builder_rotate_backward", &pass_flag);
    run_test(test_builder_swap, "test_builder_swap", &pass_flag);
    run_test(test_caesar, "test_caesar", &pass_flag);
    run_test(test_rot13, "test_rot13", &pass_flag);
    run_test(test_leet, "test_leet", &pass_flag);
    run_test(test_null, "test_null", &pass_flag);

    if (!pass_flag) {
        return 1;
    }
    return 0;
}
