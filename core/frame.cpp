#include "frame.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include "enc/aes.hpp"
#include "encoders.hpp"
#include "errors.hpp"

namespace fmxp {
constexpr size_t __FMXP_HEADER_SIZE = 17;
constexpr size_t __FMXP_BODY_HEADER_SIZE = 4;  // flags + status + path_len
constexpr size_t __FMXP_MIN_FRAME_SIZE = 21;   // header + body header

uint64_t getFrameBodySize(const ByteBuffer& encoded) {
  return ptrToU64(encoded.cdata() + 9);
}

uint32_t getFrameId(const ByteBuffer& encoded) {
  return ptrToU32(encoded.cdata() + 5);
}

bool validateProtocol(const ByteBuffer& encoded) {
  if (encoded.size() < 4) return false;
  return std::memcmp(encoded.cdata(), "fmxp", 4) == 0;
}

uint8_t getFrameVersion(const ByteBuffer& encoded) {
  return *(encoded.cdata() + 4);
}

uint8_t getBodyFlags(const ByteBuffer& encoded) { return *(encoded.cdata()); }

uint8_t getBodyStatus(const ByteBuffer& encoded) {
  return *(encoded.cdata() + 1);
}

uint16_t getBodyPathLen(const ByteBuffer& encoded) {
  return ptrToU16(encoded.cdata() + 2);
}

uint8_t* getFrameBodyPtr(ByteBuffer& encoded) { return encoded.data() + 17; }

const uint8_t* getFrameBodyPtr(const ByteBuffer& encoded) {
  return encoded.cdata() + 17;
}

uint8_t* getBodyPathPtr(ByteBuffer& encoded) { return encoded.data() + 4; }

const uint8_t* getBodyPathPtr(const ByteBuffer& encoded) {
  return encoded.cdata() + 4;
}

uint8_t* getBodyDataPtr(ByteBuffer& encoded) {
  uint16_t pathLen = getBodyPathLen(encoded);
  return encoded.data() + 4 + pathLen;
}

const uint8_t* getBodyDataPtr(const ByteBuffer& encoded) {
  uint16_t pathLen = getBodyPathLen(encoded);
  return encoded.cdata() + 4 + pathLen;
}

uint8_t makeFlags(bool compress) { return compress ? 0x01 : 0x00; }

Frame makeResponseFrame(uint8_t status, const ByteBuffer& path,
                        const ByteBuffer& data, uint8_t flags, uint32_t id) {
  return Frame{id, status, flags, path, data};
}

Frame makeRequestFrame(const ByteBuffer& path, const ByteBuffer& data,
                       uint8_t flags) {
  return Frame{++_frame_count, STATUS_REQ, flags, path, data};
}

// encoding:
// fmxp<version:1b><f_id:4b><size:8b><flags:1b><status:1b><path_len:2b><path><data>
ByteBuffer encodeFrame(const Frame& frame, bool encrypt,
                       const ByteBuffer& key) {
  ByteBuffer encoded;
  encoded += ByteBuffer("fmxp", 4);
  encoded += u8ToStr(__FMXP_VERSION);
  encoded += u32ToStr(frame.id);

  ByteBuffer body;
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

std::string ptrToString(const uint8_t* ptr, size_t size) {
  return std::string(reinterpret_cast<const char*>(ptr), size);
}

// fmxp<version:1b><f_id:4b><size:8b><flags:1b><status:1b><path_len:2b><path><data>
/*
offsets:
fmxp - 0
version - 4
id - 5
size - 9
flags - 17
status - 18
path_len - 19
path - 21
data - 21 + path_len
*/
Frame decodeFrame(const ByteBuffer& data, bool encrypted,
                  const ByteBuffer& key) {
  size_t size = data.size();

  // fmxp + ver + id + size + flags + status + path_len is already 21 bytes
  if (size < 21) throw FMXPException(ERR_INVALID_FRAME, "Invalid frame size");

  if (!validateProtocol(data))
    throw FMXPException(ERR_INVALID_FRAME, "Invalid protocol");

  if (getFrameVersion(data) != __FMXP_VERSION)
    throw FMXPException(ERR_INVALID_FRAME, "Protocol version mismatch");

  uint32_t id = getFrameId(data);

  uint64_t bodySize = getFrameBodySize(data);

  if (bodySize != size - __FMXP_HEADER_SIZE)
    throw FMXPException(ERR_INVALID_FRAME, "Frame body size mismatch");

  ByteBuffer body;

  if (encrypted) {
    ByteBuffer enc(getFrameBodyPtr(data), bodySize);
    body = aesDecrypt(enc, key);
  } else {
    body = ByteBuffer(getFrameBodyPtr(data), bodySize);
  }

  if (body.size() < 4) throw FMXPException(ERR_INVALID_FRAME, "Body too small");

  uint8_t flags = getBodyFlags(body);
  uint8_t status = getBodyStatus(body);

  uint16_t pathLen = getBodyPathLen(body);

  if (pathLen + 21 > body.size())
    throw FMXPException(ERR_INVALID_FRAME, "Invalid path length");

  ByteBuffer path(getBodyPathPtr(body), pathLen);

  size_t dataLen = bodySize - pathLen - 4;

  ByteBuffer bodyData(getBodyDataPtr(body), dataLen);

  Frame f;
  f.id = id;
  f.status = status;
  f.path = std::move(path);
  f.data = std::move(bodyData);
  f.flags = flags;

  return f;
}

}  // namespace fmxp