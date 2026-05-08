#include "frame.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include "enc/aes.hpp"
#include "encoders.hpp"
#include "errors.hpp"
#include "tools.hpp"

namespace fmxp {

// fmxp<version:1b><size:4b><rid:4b><fid:4b><ssid:8b><flags:1b><status:1b><path_len:2b><path><data>

uint32_t getFrameBodySize(const ByteBuffer& encoded) {
  return ptrToU32(encoded.cdata() + 5);
}

uint8_t getFrameVersion(const ByteBuffer& encoded) {
  return *(encoded.cdata() + 4);
}

bool validateProtocol(const ByteBuffer& encoded) {
  return encoded.size() >= 4 && std::memcmp(encoded.cdata(), "fmxp", 4) == 0;
}

const uint8_t* getFrameBodyPtr(const ByteBuffer& encoded) {
  return encoded.cdata() + __FMXP_HEADER_SIZE;
}

uint32_t getBodyRid(const ByteBuffer& body) { return ptrToU32(body.cdata()); }

uint32_t getBodyFid(const ByteBuffer& body) {
  return ptrToU32(body.cdata() + 4);
}

uint64_t getBodySsid(const ByteBuffer& body) {
  return ptrToU64(body.cdata() + 8);
}

uint8_t getBodyFlags(const ByteBuffer& body) { return *(body.cdata() + 16); }

uint8_t getBodyStatus(const ByteBuffer& body) { return *(body.cdata() + 17); }

uint16_t getBodyPathLen(const ByteBuffer& body) {
  return ptrToU16(body.cdata() + 18);
}

const uint8_t* getBodyPathPtr(const ByteBuffer& body) {
  return body.cdata() + __FMXP_BODY_HEADER_SIZE;
}

uint8_t* getBodyPathPtr(ByteBuffer& body) {
  return body.data() + __FMXP_BODY_HEADER_SIZE;
}

const uint8_t* getBodyDataPtr(const ByteBuffer& body) {
  return body.cdata() + __FMXP_BODY_HEADER_SIZE + getBodyPathLen(body);
}

uint8_t* getBodyDataPtr(ByteBuffer& body) {
  return body.data() + __FMXP_BODY_HEADER_SIZE + getBodyPathLen(body);
}

uint8_t makeFlags(bool compress) { return compress ? 0x01 : 0x00; }

// Frame makeResponseFrame(uint8_t status, const std::string& path,
//                         const ByteBuffer& data, uint8_t flags, uint32_t id) {
//   return Frame{id, status, flags, path, data};
// }

Frame makeFrame(uint32_t fid, uint8_t status, uint8_t flags,
                const std::string& path, const ByteBuffer& data, uint32_t rid,
                uint64_t ssid) {
  return {fid, rid, ssid, status, flags, path, data};
}

// Frame makeRequestFrame(const std::string& path, const ByteBuffer& data,
//                        uint8_t flags) {
//   return Frame{0, STATUS_REQ, flags, path, data};
// }

// encoding:
// fmxp<version:1b><size:4b><rid:4b><fid:4b><ssid:8b><flags:1b><status:1b><path_len:2b><path><data>
ByteBuffer encodeFrame(const Frame& frame, bool encrypt, const ByteBuffer& key,
                       uint32_t fidReplacement) {
  ByteBuffer encoded;

  encoded += ByteBuffer("fmxp", 4);
  encoded += u8ToStr(__FMXP_VERSION);

  ByteBuffer body;

  body += u32ToStr(frame.rid);
  body += u32ToStr(fidReplacement == 0 ? frame.fid : fidReplacement);
  body += u64ToStr(frame.ssid);
  body += u8ToStr(frame.flags);
  body += u8ToStr(frame.status);
  body += u16ToStr(frame.path.size());
  body += frame.path;
  body += frame.data;

  if (encrypt) body = aesEncrypt(body, key);

  encoded += u32ToStr(body.size());
  encoded += body;

  return encoded;
}

// fmxp<version:1b><size:4b><rid:4b><fid:4b><ssid:8b><flags:1b><status:1b><path_len:2b><path><data>
/*
offsets:
fmxp - 0
version - 4
size - 5
body - 9, next relative to body
rid - 0
fid - 4
ssid - 8
flags - 8
status - 9
path_len - 10
path - 12
data - 12 + path_len
*/
Frame decodeFrame(const ByteBuffer& data, bool encrypted,
                  const ByteBuffer& key) {
  if (data.size() < __FMXP_HEADER_SIZE)
    throw FMXPException(ERR_INVALID_FRAME, "Invalid frame size");

  if (!validateProtocol(data))
    throw FMXPException(ERR_INVALID_FRAME, "Invalid protocol");

  if (getFrameVersion(data) != __FMXP_VERSION)
    throw FMXPException(ERR_INVALID_FRAME, "Protocol version mismatch");

  uint32_t bodySize = getFrameBodySize(data);

  if (bodySize != data.size() - __FMXP_HEADER_SIZE)
    throw FMXPException(ERR_INVALID_FRAME, "Frame body size mismatch");

  ByteBuffer body;

  if (encrypted) {
    ByteBuffer enc(getFrameBodyPtr(data), bodySize);
    body = aesDecrypt(enc, key);
  } else {
    body = ByteBuffer(getFrameBodyPtr(data), bodySize);
  }

  if (body.size() < __FMXP_BODY_HEADER_SIZE)
    throw FMXPException(ERR_INVALID_FRAME, "Body too small");

  uint32_t rid = getBodyRid(body);
  uint32_t fid = getBodyFid(body);
  uint64_t ssid = getBodySsid(body);
  uint8_t flags = getBodyFlags(body);
  uint8_t status = getBodyStatus(body);
  uint16_t pathLen = getBodyPathLen(body);

  if (__FMXP_BODY_HEADER_SIZE + pathLen > body.size())
    throw FMXPException(ERR_INVALID_FRAME, "Invalid path length");

  ByteBuffer path(getBodyPathPtr(body), pathLen);

  size_t dataLen = body.size() - __FMXP_BODY_HEADER_SIZE - pathLen;

  ByteBuffer bodyData(getBodyDataPtr(body), dataLen);

  Frame f;
  f.rid = rid;
  f.fid = fid;
  f.ssid = ssid;
  f.flags = flags;
  f.status = status;
  f.path = path.toString();
  f.data = std::move(bodyData);

  return f;
}

}  // namespace fmxp