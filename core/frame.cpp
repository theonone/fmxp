#include "frame.hpp"

#include "enc/aes.hpp"
#include "encoders.hpp"

namespace fmxp {
Frame makeResponseFrame(uint8_t status, const std::string& path,
                        const std::string& data) {
  return Frame{_frame_count++, status, path, data};
}

Frame makeRequestFrame(const std::string& path, const std::string& data) {
  return Frame{_frame_count++, STATUS_REQ, path, data};
}

// encoding:
// fmxp<version:1b><f_id:4b><size:8b><flags:1b><status:1b><path_len:2b><path><data_len:8b><data>
std::string encodeFrame(const Frame& frame, bool encrypt, bool compress,
                        const std::string& key) {
  Header h;
  h.flags |= compress;
  std::string encoded = "fmxp" + u8ToStr(h.version) + u32ToStr(frame.id);
  std::string body = u8ToStr(h.flags) + u8ToStr(frame.status) +
                     u16ToStr(frame.path.length()) + frame.path +
                     u64ToStr(frame.data.length()) + frame.data;

  if (encrypt) {
    body = aesEncrypt(body, key);
  }

  encoded += u64ToStr(body.length()) + body;

  return encoded;
}
}  // namespace fmxp