#pragma once

#include <cstdint>

namespace fmxp {
/*
Cryptographically securely generates a 64 bit random number, using OpenSSL's
RAND_bytes
*/
uint64_t rand64();
}  // namespace fmxp