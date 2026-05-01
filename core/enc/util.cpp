#include "util.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace fmxp {

void throwErr(const std::string& msg) { throw std::runtime_error(msg); }

std::string base64Encode(const unsigned char* data, size_t len) {
  BIO* bio = BIO_new(BIO_s_mem());
  BIO* b64 = BIO_new(BIO_f_base64());

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  BIO_write(bio, data, static_cast<int>(len));
  BIO_flush(bio);

  BUF_MEM* bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);

  std::string result(bufferPtr->data, bufferPtr->length);

  BIO_free_all(bio);
  return result;
}

std::vector<unsigned char> base64Decode(const std::string& input) {
  BIO* bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
  BIO* b64 = BIO_new(BIO_f_base64());

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  std::vector<unsigned char> buffer(input.size());

  int len = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
  if (len < 0) throwErr("Base64 decode failed");

  buffer.resize(len);
  BIO_free_all(bio);

  return buffer;
}
}  // namespace fmxp
