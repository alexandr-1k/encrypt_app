#include "utils.h"
#include <filesystem>

namespace utils {

bool ValidateFileIsAvailable(const std::string &path) {
    namespace fs = std::filesystem;

    if (path.empty()) {
        throw std::runtime_error{"Empty path provided"};
    }

    auto resolved_path = fs::weakly_canonical(fs::current_path() / fs::path(path));

    if (!fs::exists(resolved_path)) {
        throw std::runtime_error{std::format("Path does not exist: {}", resolved_path.string())};
    }

    if ((fs::is_directory(resolved_path) || !fs::is_regular_file(resolved_path))) {
        throw std::runtime_error{std::format("Is not a regural file: {}", resolved_path.string())};
    }

    constexpr auto required_perm = fs::perms::owner_read | fs::perms::group_read;
    if (const auto file_perm = status(resolved_path).permissions(); (file_perm & required_perm) == fs::perms::none) {
        throw std::runtime_error{std::format("Does not have permissions to read the file: {}", resolved_path.string())};
    }

    return true;
}
}  // namespace utils