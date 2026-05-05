#include "frame.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include "enc/aes.hpp"
#include "encoders.hpp"
#include "errors.hpp"
#include "tools.hpp"

namespace fmxp {

// fmxp<version:1b><size:8b><timestamp:4b><f_id:4b><flags:1b><status:1b><path_len:2b><path><data>

uint64_t getFrameBodySize(const ByteBuffer& encoded) {
  return ptrToU64(encoded.cdata() + 5);
}

uint8_t getFrameVersion(const ByteBuffer& encoded) {
  return *(encoded.cdata() + 4);
}

bool validateProtocol(const ByteBuffer& encoded) {
  return encoded.size() >= 4 && std::memcmp(encoded.cdata(), "fmxp", 4) == 0;
}

const uint8_t* getFrameBodyPtr(const ByteBuffer& encoded) {
  return encoded.cdata() + 5 + 8;
}

uint32_t getBodyTimestamp(const ByteBuffer& body) {
  return ptrToU32(body.cdata());
}

uint32_t getBodyId(const ByteBuffer& body) {
  return ptrToU32(body.cdata() + 4);
}

uint8_t getBodyFlags(const ByteBuffer& body) { return *(body.cdata() + 8); }

uint8_t getBodyStatus(const ByteBuffer& body) { return *(body.cdata() + 9); }

uint16_t getBodyPathLen(const ByteBuffer& body) {
  return ptrToU16(body.cdata() + 10);
}

const uint8_t* getBodyPathPtr(const ByteBuffer& body) {
  return body.cdata() + 12;
}

uint8_t* getBodyPathPtr(ByteBuffer& body) { return body.data() + 12; }

const uint8_t* getBodyDataPtr(const ByteBuffer& body) {
  uint16_t pathLen = getBodyPathLen(body);
  return body.cdata() + 12 + pathLen;
}

uint8_t* getBodyDataPtr(ByteBuffer& body) {
  uint16_t pathLen = getBodyPathLen(body);
  return body.data() + 12 + pathLen;
}

uint8_t makeFlags(bool compress) { return compress ? 0x01 : 0x00; }

Frame makeResponseFrame(uint8_t status, const std::string& path,
                        const ByteBuffer& data, uint8_t flags, uint32_t id) {
  return Frame{id, status, flags, path, data};
}

Frame makeFrame(uint32_t id, uint8_t status, uint8_t flags,
                const std::string& path, const ByteBuffer& data) {
  return {id, status, flags, path, data};
}

Frame makeRequestFrame(const std::string& path, const ByteBuffer& data,
                       uint8_t flags) {
  return Frame{++_frame_count, STATUS_REQ, flags, path, data};
}

// encoding:
// fmxp<version:1b><size:8b><timestamp:4b><f_id:4b><flags:1b><status:1b><path_len:2b><path><data>
ByteBuffer encodeFrame(const Frame& frame, bool encrypt,
                       const ByteBuffer& key) {
  ByteBuffer encoded;
  encoded += ByteBuffer("fmxp", 4);
  encoded += u8ToStr(__FMXP_VERSION);

  ByteBuffer body;
  body += u32ToStr(frame.timestamp);
  body += u32ToStr(frame.id);
  body += u8ToStr(frame.flags);
  body += u8ToStr(frame.status);
  body += u16ToStr(frame.path.size());
  body += frame.path;
  body += frame.data;

  if (encrypt) {
    body = aesEncrypt(body, key);
  }

  encoded += u64ToStr(body.size());
  encoded += body;

  return encoded;
}

// fmxp<version:1b><size:8b><timestamp:4b><f_id:4b><flags:1b><status:1b><path_len:2b><path><data>
/*
offsets:
fmxp - 0
version - 4
size - 5
timestamp - 5+8
id - 17
flags - 21
status - 22
path_len - 23
path - 25
data - 25 + path_len
*/
Frame decodeFrame(const ByteBuffer& data, bool encrypted,
                  const ByteBuffer& key) {
  size_t size = data.size();

  if (size < __FMXP_HEADER_SIZE)
    throw FMXPException(ERR_INVALID_FRAME, "Invalid frame size");

  if (!validateProtocol(data))
    throw FMXPException(ERR_INVALID_FRAME, "Invalid protocol");

  if (getFrameVersion(data) != __FMXP_VERSION)
    throw FMXPException(ERR_INVALID_FRAME, "Protocol version mismatch");

  uint64_t bodySize = getFrameBodySize(data);

  if (bodySize != size - __FMXP_HEADER_SIZE) {
    throw FMXPException(ERR_INVALID_FRAME, "Frame body size mismatch");
  }

  ByteBuffer body;

  if (encrypted) {
    ByteBuffer enc(getFrameBodyPtr(data), bodySize);
    body = aesDecrypt(enc, key);
  } else {
    body = ByteBuffer(getFrameBodyPtr(data), bodySize);
  }

  if (body.size() < __FMXP_BODY_HEADER_SIZE)
    throw FMXPException(ERR_INVALID_FRAME, "Body too small");

  uint32_t timestamp = getBodyTimestamp(body);
  uint32_t id = getBodyId(body);
  uint8_t flags = getBodyFlags(body);
  uint8_t status = getBodyStatus(body);
  uint16_t pathLen = getBodyPathLen(body);

  if (__FMXP_BODY_HEADER_SIZE + pathLen > body.size())
    throw FMXPException(ERR_INVALID_FRAME, "Invalid path length");

  ByteBuffer path(getBodyPathPtr(body), pathLen);

  size_t dataLen = body.size() - __FMXP_BODY_HEADER_SIZE - pathLen;
  ByteBuffer bodyData(getBodyDataPtr(body), dataLen);

  Frame f;
  f.timestamp = timestamp;
  f.id = id;
  f.flags = flags;
  f.status = status;
  f.path = path.toString();
  f.data = std::move(bodyData);

  return f;
}

}  // namespace fmxp