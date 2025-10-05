#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <string_view>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE { ENCRYPT, DECRYPT, CHECKSUM };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const noexcept { return command_; }
    std::string GetInputFile() const noexcept { return inputFile_; }
    std::string GetOutputFile() const noexcept { return outputFile_; }
    std::string GetPassword() const noexcept { return password_; }
    bool IsKnownCommand(std::string_view) const noexcept;
    bool IsEmpty() const noexcept;

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;

    bool empty_ = true;
};

}  // namespace CryptoGuard
