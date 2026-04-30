#pragma once

#include <string>

namespace fmxp {
std::string generateAESKey();

std::string aesEncrypt(const std::string& plaintext, const std::string& key);

std::string aesDecrypt(const std::string& encrypted, const std::string& key);
}  // namespace fmxp