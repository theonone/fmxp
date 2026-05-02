#include "frame.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include "enc/aes.hpp"
#include "encoders.hpp"

namespace fmxp {

uint8_t makeFlags(bool compress) { return compress ? 0x01 : 0x00; }

Frame makeResponseFrame(uint8_t status, const ByteBuffer& path,
                        const ByteBuffer& data, uint8_t flags) {
  return Frame{_frame_count++, status, flags, path, data};
}

Frame makeRequestFrame(const ByteBuffer& path, const ByteBuffer& data,
                       uint8_t flags) {
  return Frame{_frame_count++, STATUS_REQ, flags, path, data};
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
Frame decodeFrame(const ByteBuffer& data, bool encrypted,
                  const ByteBuffer& key) {
  const uint8_t* ptr = data.cdata();
  size_t size = data.size();

  // fmxp + ver + id + size + flags + status + path_len is already 17 bytes
  if (size < 17) throw FMXPException("Invalid frame size");

  size_t offset = 0;

  if (std::memcmp(ptr, "fmxp", 4) != 0) throw FMXPException("Invalid protocol");
  offset += 4;

  uint8_t version = ptr[offset++];
  if (version != __FMXP_VERSION)
    throw FMXPException("Protocol version mismatch");

  uint32_t id = ptrToU32(ptr + offset);
  offset += 4;

  uint64_t bodySize = ptrToU64(ptr + offset);
  offset += 8;

  if (bodySize != size - offset)
    throw FMXPException("Frame body size mismatch");

  ByteBuffer body;

  if (encrypted) {
    ByteBuffer enc(ptr + offset, bodySize);
    body = aesDecrypt(enc, key);
  } else {
    body = ByteBuffer(ptr + offset, bodySize);
  }

  const uint8_t* bodyPtr = body.cdata();

  if (body.size() < 4) throw FMXPException("Body too small");

  size_t bodyOffset = 0;

  uint8_t flags = bodyPtr[bodyOffset++];
  uint8_t status = bodyPtr[bodyOffset++];

  uint16_t pathLen = ptrToU16(bodyPtr + bodyOffset);
  bodyOffset += 2;

  if (bodyOffset + pathLen > body.size())
    throw FMXPException("Invalid path length");

  ByteBuffer path(bodyPtr + bodyOffset, pathLen);
  bodyOffset += pathLen;

  size_t dataLen = bodySize - bodyOffset;

  ByteBuffer bodyData(bodyPtr + bodyOffset, dataLen);

  Frame f;
  f.id = id;
  f.status = status;
  f.path = std::move(path);
  f.data = std::move(bodyData);
  f.flags = flags;

  return f;
}

}  // namespace fmxp