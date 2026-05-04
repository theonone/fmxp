#pragma once

#include <atomic>
#include <cstdint>

#include "ByteBuffer.hpp"
#include "tools.hpp"

namespace fmxp {

constexpr uint8_t __FMXP_VERSION = 1;

static std::atomic<uint32_t> _frame_count = 0;

constexpr uint8_t STATUS_REQ = 0;
constexpr uint8_t STATUS_OK = 1;
constexpr uint8_t STATUS_BAD_REQ = 2;
constexpr uint8_t STATUS_SERVER_ERROR = 3;
constexpr uint8_t STATUS_NOT_FOUND = 4;
constexpr uint8_t STATUS_UNAUTHORIZED = 5;
constexpr uint8_t STATUS_FORBIDDEN = 6;

// fmxp<version:1b><size:8b><timestamp:4b><f_id:4b><flags:1b><status:1b><path_len:2b><path><data>
constexpr size_t __FMXP_HEADER_SIZE = 5 + 8;
constexpr size_t __FMXP_BODY_HEADER_SIZE =
    12;  // timestamp + id + flags + status + path_len
constexpr size_t __FMXP_MIN_FRAME_SIZE =
    __FMXP_BODY_HEADER_SIZE + __FMXP_HEADER_SIZE;  // header + body header

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
 @param flags flags
 @param path path to the server handle
 @param data data
 @param timestamp UTC tz UNIX timestamp in seconds, set automatically
*/
struct Frame {
  uint32_t id;
  uint8_t status;
  uint8_t flags = 0;
  std::string path;
  ByteBuffer data;
  uint32_t timestamp = getTimestamp();
};

Frame makeRequestFrame(const std::string& path, const ByteBuffer& data,
                       uint8_t flags);

Frame makeResponseFrame(uint8_t status, const std::string& path,
                        const ByteBuffer& data, uint8_t flags, uint32_t id);

Frame makeFrame(uint32_t id, uint8_t status, uint8_t flags,
                const std::string& path, const ByteBuffer& data);

ByteBuffer encodeFrame(const Frame& frame, bool encrypt, const ByteBuffer& key);

Frame decodeFrame(const ByteBuffer& data, bool encrypted,
                  const ByteBuffer& key);

uint64_t getFrameBodySize(const ByteBuffer& encoded);

uint32_t getBodyId(const ByteBuffer& encoded);

bool validateProtocol(const ByteBuffer& encoded);

const uint8_t* getFrameBodyPtr(const ByteBuffer& encoded);

uint8_t* getFrameBodyPtr(ByteBuffer& encoded);

uint8_t getFrameVersion(const ByteBuffer& encoded);

const uint8_t* getBodyDataPtr(const ByteBuffer& encoded);

uint8_t* getBodyDataPtr(ByteBuffer& encoded);

uint8_t getBodyStatus(const ByteBuffer& encoded);

uint8_t getBodyFlags(const ByteBuffer& encoded);

uint16_t getBodyPathLen(const ByteBuffer& encoded);

uint8_t* getBodyPathPtr(ByteBuffer& encoded);

const uint8_t* getBodyPathPtr(const ByteBuffer& encoded);
}  // namespace fmxp