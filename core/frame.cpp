#include "frame.hpp"

#include "enc/aes.hpp"
#include "encoders.hpp"

namespace fmxp {
Frame makeResponseFrame(uint8_t status, const ByteBuffer& path,
                        const ByteBuffer& data) {
  return Frame{_frame_count++, status, path, data};
}

Frame makeRequestFrame(const ByteBuffer& path, const ByteBuffer& data) {
  return Frame{_frame_count++, STATUS_REQ, path, data};
}

// encoding:
// fmxp<version:1b><f_id:4b><size:8b><flags:1b><status:1b><path_len:2b><path><data_len:8b><data>
ByteBuffer encodeFrame(const Frame& frame, bool encrypt, bool compress,
                       const ByteBuffer& key) {
  //   Header h;
  //   h.flags |= compress;
  //   ByteBuffer encoded = "fmxp" + u8ToStr(h.version) + u32ToStr(frame.id);
  //   ByteBuffer body = u8ToStr(h.flags) + u8ToStr(frame.status) +
  //                     u16ToStr(frame.path.size()) + frame.path +
  //                     u64ToStr(frame.data.size()) + frame.data;

  //   if (encrypt) {
  //     body = aesEncrypt(body, key);
  //   }

  //   encoded += u64ToStr(body.size()) + body;

  //   return encoded;
  return {};
}
}  // namespace fmxp