#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <ios>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {

    auto args = CryptoGuard::ProgramOptions{};
    args.Parse(argc, argv);
    if (args.IsEmpty()) {
        return 0;
    }

    CryptoGuard::CryptoGuardCtx ctx{};

    std::ifstream input_st{args.GetInputFile(), std::ios_base::binary};
    if (!input_st.is_open()) {
        throw std::runtime_error{"Could not open input file"};
    }

    std::ofstream output_st{args.GetOutputFile(), std::ios_base::binary};
    if (!input_st.is_open()) {
        throw std::runtime_error{"Could not open output file"};
    }

    switch (args.GetCommand()) {
    case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT:
        ctx.EncryptFile(input_st, output_st, args.GetPassword());
        std::print("File encrypted\n");
        break;
    case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT:
        ctx.DecryptFile(input_st, output_st, args.GetPassword());
        std::print("File decrypted\n");
        break;
    case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM:
        auto ch_sum = ctx.CalculateChecksum(input_st);
        std::print("Checksum: {}\n", ch_sum);
        output_st.write(ch_sum.data(), ch_sum.size());
        break;
    }

    return 0;
}