#include "rsa.hpp"

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

std::string bioToString(BIO* bio) {
  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  return std::string(mem->data, mem->length);
}

EVP_PKEY* loadPublicKey(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!key) throwErr("Failed loading public key");

  return key;
}

EVP_PKEY* loadPrivateKey(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!key) throwErr("Failed loading private key");

  return key;
}

RSAKeyPair generateRSAKeyPair() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) throwErr("Failed creating RSA context");

  if (EVP_PKEY_keygen_init(ctx) <= 0) throwErr("Keygen init failed");

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    throwErr("Failed setting RSA bits");

  EVP_PKEY* pkey = nullptr;

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throwErr("RSA generation failed");

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

std::string rsaEncrypt(const std::string& plaintext,
                       const std::string& publicKeyPem) {
  EVP_PKEY* key = loadPublicKey(publicKeyPem);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx) throwErr("Encrypt ctx failed");

  EVP_PKEY_encrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

  size_t outLen = 0;

  EVP_PKEY_encrypt(ctx, nullptr, &outLen,
                   reinterpret_cast<const unsigned char*>(plaintext.data()),
                   plaintext.size());

  std::vector<unsigned char> out(outLen);

  if (EVP_PKEY_encrypt(ctx, out.data(), &outLen,
                       reinterpret_cast<const unsigned char*>(plaintext.data()),
                       plaintext.size()) <= 0)
    throwErr("RSA encrypt failed");

  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);

  return base64Encode(out.data(), outLen);
}

std::string rsaDecrypt(const std::string& ciphertext,
                       const std::string& privateKeyPem) {
  auto encrypted = base64Decode(ciphertext);

  EVP_PKEY* key = loadPrivateKey(privateKeyPem);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);

  EVP_PKEY_decrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

  size_t outLen = 0;

  EVP_PKEY_decrypt(ctx, nullptr, &outLen, encrypted.data(), encrypted.size());

  std::vector<unsigned char> out(outLen);

  if (EVP_PKEY_decrypt(ctx, out.data(), &outLen, encrypted.data(),
                       encrypted.size()) <= 0)
    throwErr("RSA decrypt failed");

  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);

  return std::string(reinterpret_cast<char*>(out.data()), outLen);
}
}  // namespace fmxp