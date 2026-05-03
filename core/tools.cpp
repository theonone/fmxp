#include "tools.hpp"

#include <ctime>

namespace fmxp {
uint32_t getTimestamp() { return static_cast<uint32_t>(std::time(nullptr)); }
}  // namespace fmxp