
#include "crypto_guard_ctx.h"
#include "utils.h"
#include <array>
#include <iomanip>
#include <memory>
#include <openssl/evp.h>
#include <sstream>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() : ctx_(EVP_CIPHER_CTX_new()), md_ctx_(EVP_MD_CTX_new()) { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const;
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const;
    std::string CalculateChecksum(std::istream &inStream) const;

private:
    struct CtxDeleter {
        void operator()(EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); }
    };

    struct EVPMDCTXDeleter {
        void operator()(EVP_MD_CTX *ctx) const { EVP_MD_CTX_free(ctx); }
    };

    using CtxUniquePtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;
    using MDCtxUniquePtr = std::unique_ptr<EVP_MD_CTX, EVPMDCTXDeleter>;

    mutable CtxUniquePtr ctx_;
    mutable MDCtxUniquePtr md_ctx_;

    void InitCipherContext(std::string_view password, bool encrypt) const;
    void InitDigestContext() const;
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const;
    void RunContextLoop(std::istream &inStream, std::ostream &outStream) const;
};

// public wrapper over Impl
CryptoGuardCtx::CryptoGuardCtx() : pImpl_{std::make_unique<Impl>()} {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const {
    pImpl_->EncryptFile(inStream, outStream, password);
};
void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const {
    pImpl_->DecryptFile(inStream, outStream, password);
};

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}
//

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) const {
    AesCipherParams params;
    // static salt? write salt to the begging of the file?
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    auto password_data = reinterpret_cast<const unsigned char *>(password.data());
    int it_count = 1;

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(), password_data, password.size(), it_count,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

void CryptoGuardCtx::Impl::InitCipherContext(std::string_view password, bool encrypt) const {
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = encrypt;
    utils::ThrowOnOpenSSLErrCode(EVP_CipherInit_ex, ctx_.get(), params.cipher, nullptr, params.key.data(),
                                 params.iv.data(), params.encrypt);
}

void CryptoGuardCtx::Impl::InitDigestContext() const {
    utils::ThrowOnOpenSSLErrCode(EVP_DigestInit_ex, md_ctx_.get(), EVP_sha256(), nullptr);
}

void CryptoGuardCtx::Impl::EncryptFile(std::istream &inStream, std::ostream &outStream,
                                       std::string_view password) const {
    InitCipherContext(password, true);
    RunContextLoop(inStream, outStream);
};

void CryptoGuardCtx::Impl::DecryptFile(std::istream &inStream, std::ostream &outStream,
                                       std::string_view password) const {
    InitCipherContext(password, false);
    RunContextLoop(inStream, outStream);
};

void CryptoGuardCtx::Impl::RunContextLoop(std::istream &inStream, std::ostream &outStream) const {
    size_t chunk_size = 1024;

    std::vector<unsigned char> outBuf(chunk_size + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(chunk_size);

    while (inStream) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), chunk_size);
        const auto bytes_read = inStream.gcount();

        if (bytes_read > 0) {
            int out_len;
            utils::ThrowOnOpenSSLErrCode(EVP_CipherUpdate, ctx_.get(), outBuf.data(), &out_len, inBuf.data(),
                                         static_cast<int>(bytes_read));
            outStream.write(reinterpret_cast<const char *>(outBuf.data()), out_len);
        }
    }

    int out_len;
    utils::ThrowOnOpenSSLErrCode(EVP_CipherFinal_ex, ctx_.get(), outBuf.data(), &out_len);
    outStream.write(reinterpret_cast<const char *>(outBuf.data()), out_len);
};

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::istream &inStream) const {
    InitDigestContext();
    constexpr size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> buffer(BUFFER_SIZE);

    while (inStream) {
        inStream.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        const auto bytes_read = inStream.gcount();

        if (bytes_read > 0) {
            utils::ThrowOnOpenSSLErrCode(EVP_DigestUpdate, md_ctx_.get(), buffer.data(), bytes_read);
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;

    utils::ThrowOnOpenSSLErrCode(EVP_DigestFinal_ex, md_ctx_.get(), hash, &hashLen);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    }

    return ss.str();
}

}  // namespace CryptoGuard
