#include "cmd_options.h"
#include "utils.h"
#include <array>
#include <boost/exception/exception.hpp>
#include <boost/program_options/errors.hpp>
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;

    // clang-format off
    desc_.add_options()
        ("help,h", 
            po::bool_switch(), 
            "Print help message")
        ("input,i", 
            po::value<std::string>(&inputFile_), 
            "Path to input file")
        ("output,o", 
            po::value<std::string>(&outputFile_), 
            "Path to output file")
        ("password,p", 
            po::value<std::string>(&password_), 
            "Password for symetric encryption/description")
        ("command,c", 
            po::value<std::string>()
            ->notifier([this](const std::string& value){
                if (value.empty() && !IsKnownCommand(value)){
                    throw po::validation_error{
                        po::validation_error::invalid_option_value, 
                        "command", 
                        value
                    };
                }
            }), 
            "Mode: encrypt, decrtypt, checksum");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (argc == 1) {
        std::cerr << desc_ << std::endl;
        return;
    }

    if (vm.at("help").as<bool>()) {
        std::cout << desc_ << std::endl;
        return;
    }
    const auto &command_raw = vm.at("command");
    command_ = commandMapping_.at(command_raw.as<std::string>());

    // did not use `required` in `add_options` because of the optional `help`
    constexpr std::array<std::string_view, 4> requried_params = {"input", "output", "password", "command"};
    for (const auto &opt : requried_params) {

        if (command_ == COMMAND_TYPE::CHECKSUM && opt == "password") {
            continue;
        }

        if (!vm.count(std::string(opt))) {
            throw std::runtime_error{std::format("`{}` is requried", opt)};
        };
    }

    utils::ValidateFileIsAvailable(inputFile_);

    empty_ = false;
}

bool ProgramOptions::IsKnownCommand(std::string_view value) const noexcept {
    auto it = commandMapping_.find(value);
    return it != commandMapping_.end();
};

bool ProgramOptions::IsEmpty() const noexcept { return empty_; }

}  // namespace CryptoGuard
