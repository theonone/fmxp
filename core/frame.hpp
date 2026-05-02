#pragma once

#include <cstdint>

#include "ByteBuffer.hpp"

#define __FMXP_VERSION 1

namespace fmxp {

static uint32_t _frame_count = 0;

const uint8_t STATUS_REQ = 0;
const uint8_t STATUS_OK = 1;
const uint8_t STATUS_BAD_REQ = 2;
const uint8_t STATUS_SERVER_ERROR = 3;
const uint8_t STATUS_NOT_FOUND = 4;
const uint8_t STATUS_UNAUTHORIZED = 5;
const uint8_t STATUS_FORBIDDEN = 6;

/*
 The struct used to represent the header of an individual frame
 @param length length of the sensitive data (path size in bytes + data size in
 bytes + 12 bytes before encryption, a bit more after)
 @param flags flags
 @param version protocol version (not encrypted)
*/
struct Header {
  uint64_t length = 0;
  uint8_t version = __FMXP_VERSION;
};

/*
 The struct used to represent an individual frame. Do NOT create instances
 manually, use the makeRequestFrame() and makeResponseFrame() functions

 @param id unique request identifier (not encrypted)
 @param status status code
 @param path path to the server handle
 @param data data
*/
struct Frame {
  uint32_t id;
  uint8_t status;
  uint8_t flags = 0;
  ByteBuffer path;
  ByteBuffer data;
};

class FMXPException : public std::exception {
 public:
  FMXPException(const std::string& msg) : _msg(msg) {}
  const char* what() const noexcept override { return _msg.c_str(); }

 private:
  std::string _msg;
};

Frame makeRequestFrame(const ByteBuffer& path, const ByteBuffer& data,
                       uint8_t flags);

Frame makeResponseFrame(uint8_t status, const ByteBuffer& path,
                        const ByteBuffer& data, uint8_t flags);

ByteBuffer encodeFrame(const Frame& frame, bool encrypt, const ByteBuffer& key);

Frame decodeFrame(const ByteBuffer& data, bool encrypted,
                  const ByteBuffer& key);

}  // namespace fmxp