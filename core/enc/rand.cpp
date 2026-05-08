#include "rand.hpp"

#include <openssl/rand.h>

#include "../encoders.hpp"
#include "../errors.hpp"

namespace fmxp {

uint64_t rand64() {
  unsigned char key[8];

  if (RAND_bytes(key, sizeof(key)) != 1)
    throwErr(ERR_ENCRYPTION, "rand64 generation failed");

  return ptrToU64(key);
}
}  // namespace fmxp