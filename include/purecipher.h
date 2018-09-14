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

#ifndef _PURECIPHER_H
#define _PURECIPHER_H

#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 * Fat pointer type for a pure cipher object.
 *
 * Since a pure cipher maintains no state between ciphering operations, a single
 * cipher can be safely reference from multiple points in a codebase without
 * causing data races.
 */
typedef struct {
    void *_data;
    void *_vtable;
} purecipher_obj_t;

/*
 * Frees the given purecipher_obj_t. This function must be called once for every
 * pure cipher instance created.
 *
 * Note that this function takes a purecipher_obj_t directly, NOT a pointer to
 * one.
 */
void purecipher_free(purecipher_obj_t cipher);

/*
 * Encodes the provided buffer with the given cipher.
 *
 * The buffer DOES NOT need to contain valid UTF-8 and may contain intermittent
 * NULLs. The length corresponds to the number of bytes in the buffer.
 *
 * If an error occurs, such as an invalid cipher being provided, the buffer will
 * be left unchanged.
 */
void purecipher_encipher_buffer(purecipher_obj_t cipher, uint8_t* buffer, size_t length);

/*
 * Decodes the provided buffer with the given cipher.
 *
 * The buffer DOES NOT need to contain valid UTF-8 and may contain intermittent
 * NULLs. The length corresponds to the number of bytes in the buffer.
 *
 * If an error occurs, such as an invalid cipher being provided, the buffer will
 * be left unchanged.
 */
void purecipher_decipher_buffer(purecipher_obj_t cipher, uint8_t* buffer, size_t length);


/*
 * Builds a pure cipher that shifts ASCII letters three ahead.
 */
purecipher_obj_t purecipher_cipher_caesar(void);

/*
 * Builds a pure cipher that performs rot13 encoding on ASCII letters.
 */
purecipher_obj_t purecipher_cipher_rot13(void);

/*
 * Builds a rough pure cipher for stereotypical "leet" speak.
 */
purecipher_obj_t purecipher_cipher_leet(void);

/*
 * Builds a cipher that performs no ciphering.
 *
 * This cipher does not store lookup tables for byte substitution and therefore
 * has less memory overhead than a cipher that maps bytes to themselves.
 */
purecipher_obj_t purecipher_cipher_null(void);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PURECIPHER_H
