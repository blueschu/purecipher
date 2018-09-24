/**
 * C++ Interface to the purecipher library.
 *
 * This header has been named `purecipher.hpp` to avoid collisions with the
 * purecipher header itself, `purecipher.h`.
 */

#ifndef PURECIPHER_PRUECIPHER_H
#define PURECIPHER_PRUECIPHER_H

#include "purecipher.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace purecipher {
    /**
     * A pure (stateless) cipher.
     *
     * This class serves as a thin wrapper over a purecipher_obj_t fat pointer.
     */
    class Cipher final {

        /**
         * Pointer to the cipher object that this instance wraps.
         */
        const purecipher_obj_t m_cipher_ptr;

        /**
         * Whether or not this instance's cipher pointer is owned by this instance.
         *
         * The pointer unfortunately cannot be placed under a std::unique_ptr
         * with a custom deleter because it is represented by a fat pointer
         * struct rather than an opaque pointer.
         */
        bool m_moved;

    public:
        /**
         * Creates a new Cipher from the given cipher object pointer.
         *
         * This object takes ownership of the cipher pointer is responsible
         * for freeing it at the end of its lifetime.
         *
         * @param cipher_ptr Owned cipher object pointer.
         */
        explicit Cipher(purecipher_obj_t cipher_ptr)
            : m_cipher_ptr{cipher_ptr}, m_moved{false} {}

        /*
         * Copy-constructor is disabled as no interface is provided for cloning
         * cipher objects.
         */
        Cipher(const Cipher& other) = delete;

        /*
         * Copy-assignment is disabled as no interface is provided for cloning
         * cipher objects.
         */
        Cipher& operator=(const Cipher& other) = delete;

        /*
         * Move-assignment is disabled as the cipher pointer is declared
         * constant and cannot be re-assigned.
         */
        Cipher& operator=(Cipher&& other) = delete;

        /*
         * Move-constructor.
         */
        Cipher(Cipher&& other) noexcept;

        /*
         * Deconstructor. Since this class is declared final, this method has
         * not been marked virtual.
         */
        ~Cipher() { if (!m_moved) { purecipher_free(m_cipher_ptr); }}

        /**
         * Enciphers the elements of the given vector of bytes inplace.
         *
         * @param buffer Sequence of bytes to be enciphered.
         */
        void encipher_inplace(std::vector<std::uint8_t>& buffer) const;

        /**
         * Deciphers the elements of the given vector of bytes inplace.
         *
         * @param buffer Sequence of bytes to be deciphered.
         */
        void decipher_inplace(std::vector<std::uint8_t>& buffer) const;

        /**
         * Encipher the given null-terminated string inplace.
         *
         * @param str Null-terminated c-style string.
         */
        void encipher_inplace(char* str) const {
            purecipher_encipher_str(m_cipher_ptr, str);
        };

        /**
         * Decipher the given null-terminated string inplace.
         *
         * @param str Null-terminated c-style string.
         */
        void decipher_inplace(char* str) const {
            purecipher_decipher_str(m_cipher_ptr, str);
        };

        /**
         * Encipher the buffer of bytes inplace.
         *
         * @param buf Buffer of bytes to operate on.
         * @param len The length of the given buffer.
         */
        void encipher_inplace(std::uint8_t* buf, std::size_t len) const {
            purecipher_encipher_buffer(m_cipher_ptr, buf, len);
        };

        /**
         * Decipher the buffer of bytes inplace.
         *
         * @param buf Buffer of bytes to operate on.
         * @param len The length of the given buffer.
         */
        void decipher_inplace(std::uint8_t* buf, std::size_t len) const {
            purecipher_decipher_buffer(m_cipher_ptr, buf, len);
        };

        /**
         * Encipher the given vector of bytes.
         *
         * @param buffer Sequence of bytes to be enciphered.
         * @return New sequence of enciphered bytes.
         */
        auto encipher(const std::vector<std::uint8_t>& buffer) const -> std::vector<std::uint8_t>;

        /**
         * Decipher the given vector of bytes.
         *
         * @param buffer Sequence of bytes to be deciphered.
         * @return New sequence of deciphered bytes.
         */
        std::vector<std::uint8_t> decipher(const std::vector<std::uint8_t>& buffer) const;

        /**
         * Encipher the given string.
         *
         * @param buffer String to be enciphered.
         * @return New enciphered string.
         */
        std::string encipher(const std::string& str) const;

        /**
         * Decipher the given string.
         *
         * @param buffer String to be deciphered.
         * @return New deciphered string.
         */
        std::string decipher(const std::string& str) const;

        /**
         * Builds a cipher that performs no ciphering.

         * @return Cipher that performs no ciphering.
         */
        static Cipher null() { return Cipher(purecipher_cipher_null()); };

        /**
         * Builds a pure cipher that shifts ASCII letters three ahead.
         *
         * @return Cipher that performs the classic caesar cipher.
         */
        static Cipher caesar() { return Cipher(purecipher_cipher_caesar()); };

        /**
         * Builds a pure cipher that performs rot13 encoding on ASCII letters.
         *
         * @return Cipher that performs rot13 encoding on ASCII letters.
         */
        static Cipher rot13() { return Cipher(purecipher_cipher_rot13()); };

        /**
         * Builds a rough pure cipher for stereotypical "leet" speak.
         *
         * @return Cipher for stereotypical "leet" speak.
         */
        static Cipher leet() { return Cipher(purecipher_cipher_leet()); };
    };

    /**
     * Helper class to builder substitution based pure ciphers.
     */
    class SubstitutionBuilder {
        /**
         * Pointer to the substituion cipher structure that this instance wraps.
         */
        std::unique_ptr<purecipher_builder_t, decltype(&purecipher_builder_discard)> m_builder_ptr;

    public:
        /**
         * Creates a new substituion cipher builder.
         */
        SubstitutionBuilder() : m_builder_ptr{purecipher_builder_new(), purecipher_builder_discard} {}

        /**
         * Creates a SubstitutionBuilder to wrap the given substituion cipher builder.
         *
         * @param builder_ptr Owned pointer to a substituion cipher builder.
         */
        explicit SubstitutionBuilder(purecipher_builder_t* const builder_ptr) : m_builder_ptr{
            builder_ptr,
            purecipher_builder_discard
        } {}

        /*
         * Copy-constructor is disabled as no interface is provided for cloning
         * substituion builder objects.
         */
        SubstitutionBuilder(const SubstitutionBuilder& other) = delete;

        /*
         * Copy-assignment is disabled as no interface is provided for cloning
         * substituion builder objects.
         */
        SubstitutionBuilder& operator=(const SubstitutionBuilder& other) = delete;

        /*
         * Move-constructor.
         */
        SubstitutionBuilder(SubstitutionBuilder&& other) noexcept;

        /*
         * Move-assignment.
         */
        SubstitutionBuilder& operator=(SubstitutionBuilder&& other) noexcept;

        /*
         * Default deconstructor used as the builder pointer is freed by its
         * deleter function.
         */
        virtual ~SubstitutionBuilder() = default;

        /**
         *Rotates each byte in the given inclusive range by the given offset in
         * the cipher mapping that this builder will produce.
         *
         * @param from Start of the range to be rotated.
         * @param to End of the range to be rotated (inclusive)
         * @param offset Magnitude and direction of the byte rotation.
         * @return This instance.
         */
        SubstitutionBuilder& rotate(std::uint8_t from, std::uint8_t to, std::int32_t offset);

        /**
         * Swaps the two given bytes in the cipher mapping that this builder
         * will produce.
         *
         * @param left The first byte to be swapped.
         * @param right The second byte to be swapped.
         * @return This instance.
         */
        SubstitutionBuilder& swap(std::uint8_t left, std::uint8_t right);

        /**
         * Converts this builder instances into a Cipher object.
         *
         * This member function consumes this substitution cipher builder.
         *
         * @return Cipher object implementing the mapping produced by this builder.
         */
        Cipher into_cipher();
    };
}

#endif //PURECIPHER_PRUECIPHER_H
