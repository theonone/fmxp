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

ByteBuffer generateAESKey() {
  unsigned char key[32];

  if (RAND_bytes(key, sizeof(key)) != 1) throwErr("AES key generation failed");

  return ByteBuffer(key, sizeof(key));
}

ByteBuffer aesEncrypt(const ByteBuffer& plaintext, const ByteBuffer& keyBuf) {
  if (keyBuf.size() != 32) throw std::runtime_error("Invalid AES-256 key");

  const unsigned char* key =
      reinterpret_cast<const unsigned char*>(keyBuf.cdata());

  unsigned char iv[12];
  if (RAND_bytes(iv, sizeof(iv)) != 1) throwErr("IV generation failed");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throwErr("AES ctx failed");

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1)
    throwErr("Encrypt init failed");

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr);

  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
    throwErr("Encrypt key init failed");

  ByteBuffer ciphertext;
  ciphertext.reserve(plaintext.size());

  int len = 0;

  ciphertext.resize(
      plaintext.size());  // optional helper OR manual append buffer

  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &len,
          reinterpret_cast<const unsigned char*>(plaintext.cdata()),
          plaintext.size()) != 1)
    throwErr("Encrypt update failed");

  size_t total = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) != 1)
    throwErr("Encrypt final failed");

  total += len;
  ciphertext.resize(total);

  unsigned char tag[16];
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

  EVP_CIPHER_CTX_free(ctx);

  // Build final packet:
  // [IV][TAG][CIPHERTEXT]

  ByteBuffer result;
  result.append(reinterpret_cast<uint8_t*>(iv), sizeof(iv));
  result.append(reinterpret_cast<uint8_t*>(tag), sizeof(tag));
  result += ciphertext;

  return result;
}
ByteBuffer aesDecrypt(const ByteBuffer& encrypted, const ByteBuffer& keyBuf) {
  if (keyBuf.size() != 32) throw std::runtime_error("Invalid AES-256 key");

  if (encrypted.size() < 12 + 16)
    throw std::runtime_error("Invalid AES packet");

  const unsigned char* key =
      reinterpret_cast<const unsigned char*>(keyBuf.cdata());

  const unsigned char* iv = encrypted.cdata();
  const unsigned char* tag = encrypted.cdata() + 12;
  const unsigned char* ct = encrypted.cdata() + 28;
  size_t ctLen = encrypted.size() - 28;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throwErr("AES ctx failed");

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1)
    throwErr("Decrypt init failed");

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);

  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
    throwErr("Decrypt key init failed");

  ByteBuffer plaintext;
  plaintext.resize(ctLen);

  int len = 0;
  size_t total = 0;

  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct, ctLen) != 1)
    throwErr("Decrypt update failed");

  total += len;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);

  int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);

  EVP_CIPHER_CTX_free(ctx);

  if (ret <= 0) throw std::runtime_error("AES authentication failed");

  total += len;
  plaintext.resize(total);

  return plaintext;
}

}  // namespace fmxp