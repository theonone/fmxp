#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "../core/ByteBuffer.hpp"
#include "../core/frame.hpp"

namespace fmxp {

struct Request {
  Frame frame;
  int fd = -1;
};

struct Response {
  Frame frame;
  int fd = -1;
};

class Connection {
 private:
  int _fd = -1;
  uint64_t _maxFrameSize;
  ByteBuffer _aesKey;
  ByteBuffer _inFrameBuffer;
  std::function<void(uint8_t, const std::string&)> _onErr;

 public:
  Connection(int fd, uint64_t maxFrameSize);
  ~Connection();
  void closeConnection();
  int fd() const;
  void setAesKey(const ByteBuffer& aesKey);
  bool isSafe() const;
  bool isConnected() const;
  void appendToBuffer(const ByteBuffer& bytes);
  void setOnError(std::function<void(uint8_t, const std::string&)> onError);
  std::vector<Frame> parseFrames();
  void sendFrame(const Frame& frame);
};

}  // namespace fmxp
