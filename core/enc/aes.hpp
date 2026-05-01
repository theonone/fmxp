#pragma once

#include <string>

namespace fmxp {

/*
Generates a AES-256-GCM key in a cryptographically secure way using OpenSSL's
RAND_bytes
*/
std::string generateAESKey();

/*
Encrypts `plaintext` with `key` using AES-256-GCM
@param plaintext string to encrypt
@param key AES-256-GCM key
@return encrypted string
*/
std::string aesEncrypt(const std::string& plaintext, const std::string& key);

/*
Decrypts `encrypted` with `key` using AES-256-GCM
@param encrypted string to decrypt
@param key AES-256-GCM key
@return decrypted string
*/
std::string aesDecrypt(const std::string& encrypted, const std::string& key);
}  // namespace fmxp