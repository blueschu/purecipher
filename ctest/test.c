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

static bool test_rot13(void) {
    const purecipher_obj_t rot13 = purecipher_cipher_rot13();
    const uint8_t *expected = (uint8_t *) "Ybiryl cyhzntr, gur Abejrtvna Oyhr.";

    uint8_t buffer[36] = "Lovely plumage, the Norwegian Blue.";

    purecipher_encipher_buffer(rot13, buffer, sizeof(buffer));

    bool pass = 0 == memcmp(expected, buffer, sizeof(buffer));

    purecipher_free(rot13);
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

    run_test(test_rot13, "test_rot13", &pass_flag);

    if (!pass_flag) {
        return 1;
    }
    return 0;
}