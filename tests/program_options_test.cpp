#include "cmd_options.h"
#include "gmock/gmock.h"
#include <boost/program_options.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>
#include <stdexcept>
#include <streambuf>

class TestedParser : public CryptoGuard::ProgramOptions {
public:
    MOCK_CONST_METHOD1(ValidateFileIsAvailable, void(const std::string &));
};

class ProgramOptionsTests : public ::testing::Test {
protected:
    TestedParser parser{};
    std::streambuf *orig_cerr;
    std::stringstream cerr_buff_mock;

    std::streambuf *orig_cout;
    std::stringstream cout_buff_mock;

    void SetUp() override {
        orig_cerr = std::cerr.rdbuf();
        std::cerr.rdbuf(cerr_buff_mock.rdbuf());

        orig_cout = std::cout.rdbuf();
        std::cout.rdbuf(cout_buff_mock.rdbuf());
    }

    void TearDown() override {
        std::cerr.rdbuf(orig_cerr);
        std::cout.rdbuf(orig_cout);
    }
};

TEST_F(ProgramOptionsTests, TestNoArgs) {
    const char *argv[] = {"./bin"};

    ASSERT_THROW(parser.Parse(1, const_cast<char **>(argv)), std::runtime_error);

    auto caught_cerr = cerr_buff_mock.str();
    ASSERT_FALSE(caught_cerr.empty());
    EXPECT_THAT(caught_cerr, ::testing::HasSubstr("Allowed options:"));
}

TEST_F(ProgramOptionsTests, TestHelpOutput) {
    const char *argv[] = {"./bin", "--help"};
    parser.Parse(2, const_cast<char **>(argv));

    auto caught_cout = cout_buff_mock.str();
    EXPECT_THAT(caught_cout, ::testing::HasSubstr("Allowed options:"));
}

TEST_F(ProgramOptionsTests, TestUnknownCommandsThrows) {
    const char *argv[] = {"./bin", "--wtf"};
    ASSERT_THROW(parser.Parse(2, const_cast<char **>(argv)), boost::program_options::unknown_option);
}

TEST_F(ProgramOptionsTests, TestValidateRightNumberOfArgsForEncrypt) {
    const char *argv[] = {"./bin",      "--input", "some.txt",  "--output", "out.txt",
                          "--password", "pass",    "--command", "encrypt"};
    EXPECT_CALL(parser, ValidateFileIsAvailable(::testing::_)).Times(1);
    parser.Parse(9, const_cast<char **>(argv));
}

TEST_F(ProgramOptionsTests, TestInvalidNumOfArgsForEncrypt) {
    // no password
    const char *argv[] = {"./bin", "--input", "some.txt", "--output", "out.txt", "--command", "encrypt"};
    EXPECT_CALL(parser, ValidateFileIsAvailable(::testing::_)).Times(0);
    ASSERT_THROW(parser.Parse(7, const_cast<char **>(argv)), std::runtime_error);
}

TEST_F(ProgramOptionsTests, TestValidateRightNumberOfArgsForDecrypt) {
    const char *argv[] = {"./bin",      "--input", "some.txt",  "--output", "out.txt",
                          "--password", "pass",    "--command", "decrypt"};
    EXPECT_CALL(parser, ValidateFileIsAvailable(::testing::_)).Times(1);
    parser.Parse(9, const_cast<char **>(argv));
}

TEST_F(ProgramOptionsTests, TestValidateRightNumberOfArgsForChecksum) {
    const char *argv[] = {"./bin",      "--input", "some.txt",  "--output", "out.txt",
                          "--password", "pass",    "--command", "checksum"};
    EXPECT_CALL(parser, ValidateFileIsAvailable(::testing::_)).Times(1);
    parser.Parse(9, const_cast<char **>(argv));
}