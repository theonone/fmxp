#pragma once

#include <string>
#include <vector>

namespace fmxp {
void throwErr(const std::string& msg);

std::string base64Encode(const unsigned char* data, size_t len);
std::vector<unsigned char> base64Decode(const std::string& input);
}  // namespace fmxp