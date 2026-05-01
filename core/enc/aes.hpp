#pragma once

#include <string>

#include "../ByteBuffer.hpp"

namespace fmxp {

/*
Generates a AES-256-GCM key in a cryptographically secure way using OpenSSL's
RAND_bytes
*/
ByteBuffer generateAESKey();

/*
Encrypts `plaintext` with `key` using AES-256-GCM
@param plaintext string to encrypt
@param key AES-256-GCM key
@return encrypted string
*/
ByteBuffer aesEncrypt(const ByteBuffer& plaintext, const ByteBuffer& key);

/*
Decrypts `encrypted` with `key` using AES-256-GCM
@param encrypted string to decrypt
@param key AES-256-GCM key
@return decrypted string
*/
ByteBuffer aesDecrypt(const ByteBuffer& encrypted, const ByteBuffer& key);
}  // namespace fmxp