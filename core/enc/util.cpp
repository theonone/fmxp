#include "util.hpp"

#include <stdexcept>
#include <string>

namespace fmxp {

void throwErr(const std::string& msg) { throw std::runtime_error(msg); }

}  // namespace fmxp
