#pragma once

#include <string>
/*
schema:
0. the server has a PINNED RSA-2048 key pair
1. server's pubkey is sewn into the client
2. server's private key is kept secret on the server
3. on connect the client generates a random AES-256-GCM key, encrypts it with
the server's pubkey, and sends it to the server
4. the server decrypts the AES key with its private key, encrypts a success
message with the AES key, and sends it to the client
5. the client decrypts the success message with the AES key, verifies integrity
6. if everything is fine, the main logic starts, uses AES for encryption
*/

namespace fmxp {

struct RSAKeyPair {
  std::string public_key;
  std::string private_key;
};

/*
Generates a RSA-2048 key pair using OpenSSL
@return struct RSAKeyPair (std::string public_key, std::string private_key)
*/
RSAKeyPair generateRSAKeyPair();

/*
Encrypts `plaintext` with `key` using RSA-2048. Due to `plaintext` length
limitations, it should only be used for encrypting the AES key.
@param plaintext string to encrypt
@param publicKeyPem RSA-2048 public key in PEM format
@return encrypted string
*/
std::string rsaEncrypt(const std::string& plaintext,
                       const std::string& publicKeyPem);

/*
Decrypts `ciphertext` with `key` using RSA-2048
@param ciphertext string to decrypt
@param privateKeyPem RSA-2048 private key in PEM format
@return decrypted string
*/
std::string rsaDecrypt(const std::string& ciphertext,
                       const std::string& privateKeyPem);

}  // namespace fmxp
