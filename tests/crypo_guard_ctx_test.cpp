#include "crypto_guard_ctx.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>

std::string bytes_to_hex(const std::string &input) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : input) {
        ss << "\\x" << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

std::string parse_hex_escapes(const std::string &input) {
    std::stringstream output;
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '\\' && (i + 1 < input.size()) && input[i + 1] == 'x') {
            if (i + 3 >= input.size()) {
                throw std::invalid_argument("Invalid hex escape sequence");
            }
            std::string hex = input.substr(i + 2, 2);
            i += 3;  // skip for \xXX
            try {
                int value = std::stoi(hex, nullptr, 16);
                output << static_cast<char>(value);
            } catch (...) {
                throw std::invalid_argument("Invalid hex digits: " + hex);
            }
        } else {
            output << input[i];
        }
    }
    return output.str();
}

class GryptoGuardTests : public ::testing::Test {
public:
    CryptoGuard::CryptoGuardCtx ctx{};
    std::stringstream input_stream{"some_data"};
    std::stringstream output_stream;
};

TEST_F(GryptoGuardTests, TestEncrypt) {
    ctx.EncryptFile(input_stream, output_stream, "pass");
    ASSERT_EQ(bytes_to_hex(output_stream.str()), R"(\x92\xfb\x6b\x92\x98\x16\x73\x58\x08\x5b\x4b\xed\x88\xb9\x59\x8d)");
}

TEST_F(GryptoGuardTests, TestDecrypt) {
    std::string encrypted_data =
        parse_hex_escapes(R"(\x92\xfb\x6b\x92\x98\x16\x73\x58\x08\x5b\x4b\xed\x88\xb9\x59\x8d)");

    std::stringstream encrypted_stream(encrypted_data);
    ctx.DecryptFile(encrypted_stream, output_stream, "pass");
    ASSERT_EQ(output_stream.str(), std::string{"some_data"});
}

TEST_F(GryptoGuardTests, TestEncryptDecryptConsistencyCtx) {
    auto password = "pass";
    std::stringstream decrypted_stream;

    ctx.EncryptFile(input_stream, output_stream, password);
    ctx.DecryptFile(output_stream, decrypted_stream, password);

    ASSERT_EQ(input_stream.str(), decrypted_stream.str());
}

TEST_F(GryptoGuardTests, TestChecksum) {
    auto result = ctx.CalculateChecksum(input_stream);
    std::string expected{"b48d1de58c39d2160a4b8a5a9cae90818da1212742ec1f11fba1209bed0a212c"};
    ASSERT_EQ(result, expected);
}

TEST_F(GryptoGuardTests, TestDecryptInvalidPassword) {
    std::string encrypted_data =
        parse_hex_escapes(R"(\x92\xfb\x6b\x92\x98\x16\x73\x58\x08\x5b\x4b\xed\x88\xb9\x59\x8d)");

    std::stringstream encrypted_stream(encrypted_data);
    ASSERT_THROW(ctx.DecryptFile(encrypted_stream, output_stream, "ANOTHER_PASSWORD"), std::runtime_error);
}

TEST_F(GryptoGuardTests, TestDecryptBrokenStream) {
    std::string encrypted_data = parse_hex_escapes(
        R"(\x92\xfb\x6b\x92\x98\x16\x73\x58\x08\x5b\x4b\xed\x88\xb9\x59\x8d\x8d\x8d\x8d\x8d\x8d\x8d)");

    std::stringstream encrypted_stream(encrypted_data);
    ASSERT_THROW(ctx.DecryptFile(encrypted_stream, output_stream, "pass"), std::runtime_error);
}