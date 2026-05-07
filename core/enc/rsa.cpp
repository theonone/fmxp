#include "rsa.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>
#include <vector>

#include "../errors.hpp"

namespace fmxp {

std::string bioToString(BIO* bio) {
  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  return std::string(mem->data, mem->length);
}

EVP_PKEY* loadPublicKey(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
  EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!key) throwErr(ERR_ENCRYPTION, "Failed loading public key");
  return key;
}

EVP_PKEY* loadPrivateKey(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!key) throwErr(ERR_ENCRYPTION, "Failed loading private key");
  return key;
}

RSAKeyPair generateRSAKeyPair() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) throwErr(ERR_ENCRYPTION, "Failed creating RSA context");

  if (EVP_PKEY_keygen_init(ctx) <= 0)
    throwErr(ERR_ENCRYPTION, "Keygen init failed");

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    throwErr(ERR_ENCRYPTION, "Failed setting RSA bits");

  EVP_PKEY* pkey = nullptr;

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    throwErr(ERR_ENCRYPTION, "RSA generation failed");

  BIO* pub = BIO_new(BIO_s_mem());
  BIO* priv = BIO_new(BIO_s_mem());

  PEM_write_bio_PUBKEY(pub, pkey);
  PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);

  RSAKeyPair pair{bioToString(pub), bioToString(priv)};

  BIO_free(pub);
  BIO_free(priv);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);

  return pair;
}

ByteBuffer rsaEncrypt(const ByteBuffer& plaintext,
                      const std::string& publicKeyPem) {
  EVP_PKEY* key = loadPublicKey(publicKeyPem);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx) throwErr(ERR_ENCRYPTION, "Encrypt ctx failed");

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    throwErr(ERR_ENCRYPTION, "Encrypt init failed");

  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

  size_t outLen = 0;

  if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.cdata(),
                       plaintext.size()) <= 0)
    throwErr(ERR_ENCRYPTION, "RSA encrypt size failed");

  ByteBuffer out;
  out.reserve(outLen);

  std::vector<uint8_t> tmp(outLen);

  if (EVP_PKEY_encrypt(ctx, tmp.data(), &outLen, plaintext.cdata(),
                       plaintext.size()) <= 0)
    throwErr(ERR_ENCRYPTION, "RSA encrypt failed");

  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);

  return ByteBuffer(reinterpret_cast<char*>(tmp.data()), outLen);
}

ByteBuffer rsaDecrypt(const ByteBuffer& ciphertext,
                      const std::string& privateKeyPem) {
  EVP_PKEY* key = loadPrivateKey(privateKeyPem);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx) throwErr(ERR_ENCRYPTION, "Decrypt ctx failed");

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    throwErr(ERR_ENCRYPTION, "Decrypt init failed");

  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

  size_t outLen = 0;

  if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.cdata(),
                       ciphertext.size()) <= 0)
    throwErr(ERR_ENCRYPTION, "RSA decrypt size failed");

  std::vector<uint8_t> tmp(outLen);

  if (EVP_PKEY_decrypt(ctx, tmp.data(), &outLen, ciphertext.cdata(),
                       ciphertext.size()) <= 0)
    throwErr(ERR_ENCRYPTION, "RSA decrypt failed");

  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);

  return ByteBuffer(reinterpret_cast<char*>(tmp.data()), outLen);
}

}  // namespace fmxp