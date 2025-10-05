#pragma once
#include <functional>
#include <openssl/err.h>
#include <stdexcept>
#include <string>

namespace utils {

bool ValidateFileIsAvailable(const std::string &path);

template <typename Callable, typename... Args>
auto ThrowOnOpenSSLErrCode(Callable &&foo, Args &&...args) -> decltype(foo(args...)) {

    decltype(auto) val = std::invoke(std::forward<Callable>(foo), std::forward<Args>(args)...);

    if (auto ret_code = ERR_get_error(); ret_code != 0) {
        std::string err_str;
        std::array<char, 256> err_buf;
        while (ret_code != 0) {
            ERR_error_string_n(ret_code, err_buf.data(), err_buf.size());
            std::copy(err_buf.begin(), err_buf.end(), std::back_insert_iterator<std::string>(err_str));
            ret_code = ERR_get_error();
        }
        throw std::runtime_error{std::move(err_str)};
    }
    return val;
}

}  // namespace utils