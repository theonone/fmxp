#include "aes.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>
#include <vector>

#include "util.hpp"

namespace fmxp {

std::string generateAESKey() {
  unsigned char key[32];

  if (RAND_bytes(key, sizeof(key)) != 1) throwErr("AES key generation failed");

  return base64Encode(key, sizeof(key));
}

std::string aesEncrypt(const std::string& plaintext,
                       const std::string& keyStr) {
  auto key = base64Decode(keyStr);

  if (key.size() != 32) throw std::runtime_error("Invalid AES-256 key");

  unsigned char iv[12];
  if (RAND_bytes(iv, sizeof(iv)) != 1) throwErr("IV generation failed");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  if (!ctx) throwErr("AES ctx failed");

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1)
    throwErr("Encrypt init failed");

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr);

  EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv);

  std::vector<unsigned char> ciphertext(plaintext.size());

  int len = 0;
  int total = 0;

  EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                    reinterpret_cast<const unsigned char*>(plaintext.data()),
                    plaintext.size());

  total += len;

  EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len);

  total += len;
  ciphertext.resize(total);

  unsigned char tag[16];

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

  EVP_CIPHER_CTX_free(ctx);

  return base64Encode(iv, sizeof(iv)) + ":" + base64Encode(tag, sizeof(tag)) +
         ":" + base64Encode(ciphertext.data(), ciphertext.size());
}

std::string aesDecrypt(const std::string& encrypted,
                       const std::string& keyStr) {
  auto key = base64Decode(keyStr);

  if (key.size() != 32) throw std::runtime_error("Invalid AES-256 key");

  size_t p1 = encrypted.find(':');
  size_t p2 = encrypted.find(':', p1 + 1);

  if (p1 == std::string::npos || p2 == std::string::npos)
    throw std::runtime_error("Bad AES packet");

  std::string ivStr = encrypted.substr(0, p1);
  std::string tagStr = encrypted.substr(p1 + 1, p2 - p1 - 1);
  std::string ctStr = encrypted.substr(p2 + 1);

  auto iv = base64Decode(ivStr);
  auto tag = base64Decode(tagStr);
  auto ct = base64Decode(ctStr);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);

  EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

  std::vector<unsigned char> plaintext(ct.size());

  int len = 0;
  int total = 0;

  EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct.data(), ct.size());

  total += len;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());

  int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);

  EVP_CIPHER_CTX_free(ctx);

  if (ret <= 0) throw std::runtime_error("AES authentication failed");

  total += len;
  plaintext.resize(total);

  return std::string(reinterpret_cast<char*>(plaintext.data()),
                     plaintext.size());
}
}  // namespace fmxp