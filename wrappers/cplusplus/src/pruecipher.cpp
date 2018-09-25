#include "purecipher.hpp"

using purecipher::Cipher;
using purecipher::SubstitutionBuilder;

void Cipher::encipher_inplace(std::vector<std::uint8_t>& buffer) const {
    purecipher_encipher_buffer(m_cipher_ptr, buffer.data(), buffer.size());
}

void Cipher::decipher_inplace(std::vector<std::uint8_t>& buffer) const {
    purecipher_decipher_buffer(m_cipher_ptr, buffer.data(), buffer.size());
}

std::vector<std::uint8_t> Cipher::encipher(const std::vector<std::uint8_t>& buffer) const {
    std::vector<uint8_t> cipher_buffer(buffer.size());
    this->encipher_inplace(cipher_buffer);
    return cipher_buffer;
}

std::vector<std::uint8_t> Cipher::decipher(const std::vector<std::uint8_t>& buffer) const {
    std::vector<uint8_t> cipher_buffer(buffer.size());
    this->decipher_inplace(cipher_buffer);
    return cipher_buffer;
}

std::string Cipher::encipher(const std::string& str) const {
    // str.size() is used instead of .size() + 1 because the trailing null byte
    // added by std::string should be ignored. Otherwise, the cipher text will
    // contain an extraneous trailing null.
    std::vector<std::uint8_t> cipher_buffer(str.c_str(), str.c_str() + str.size());
    this->encipher_inplace(cipher_buffer);
    return std::string(cipher_buffer.begin(), cipher_buffer.end());
}

std::string Cipher::decipher(const std::string& str) const {
    // Trailing null byte ignored. See comment in implementation of encipher(std::string&).
    std::vector<std::uint8_t> cipher_buffer(str.c_str(), str.c_str() + str.size());
    this->decipher_inplace(cipher_buffer);
    return std::string(cipher_buffer.begin(), cipher_buffer.end());
}

Cipher::Cipher(Cipher&& other) noexcept: m_cipher_ptr{other.m_cipher_ptr}, m_moved{false} {
    other.m_moved = true;
}

SubstitutionBuilder::SubstitutionBuilder(SubstitutionBuilder&& other) noexcept
    : m_builder_ptr{std::move(other.m_builder_ptr)} {}

SubstitutionBuilder& SubstitutionBuilder::operator=(SubstitutionBuilder&& other) noexcept {
    this->m_builder_ptr = std::move(other.m_builder_ptr);
    return *this;
}

SubstitutionBuilder& SubstitutionBuilder::rotate(
    std::uint8_t from,
    std::uint8_t to,
    std::int32_t offset
) {
    purecipher_builder_rotate(m_builder_ptr.get(), from, to, offset);
    return *this;
}

SubstitutionBuilder& SubstitutionBuilder::swap(std::uint8_t left, std::uint8_t right) {
    purecipher_builder_swap(m_builder_ptr.get(), left, right);
    return *this;
}

Cipher SubstitutionBuilder::into_cipher() {
    purecipher_builder_t* builder = m_builder_ptr.release();
    return Cipher(purecipher_builder_into_cipher(builder));
}
