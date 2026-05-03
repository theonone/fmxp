#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "../core/ByteBuffer.hpp"
#include "../core/frame.hpp"

namespace fmxp {

enum CloseReason {
  NATURAL = 0,
  ENCRYPTION_ERROR = 1,
  INVALID_REQUEST = 2,
  REQUEST_TOO_LONG = 3,
  SOCKET_ERROR = 4,
};

enum ConnectionState { HANDSHAKE, ACTIVE, CLOSED };

struct Request;

class ClientConnection {
 private:
  int _fd = -1;
  uint64_t _maxFrameSize;
  ConnectionState _state = ConnectionState::HANDSHAKE;
  ByteBuffer _aesKey;
  ByteBuffer _inFrameBuffer;
  std::function<void(int, CloseReason)> _onClose;
  const std::string& _rsaPrivKey;
  std::function<void(Request)> _onNewRequest;
  void _setAesKey(const ByteBuffer& aesKey);
  std::vector<Frame> _parseFrames();

 public:
  ClientConnection(int fd, uint64_t maxFrameSize, const std::string& rsaPrivKey,
                   std::function<void(Request)> onNewRequest);
  ~ClientConnection();
  void closeConnection(CloseReason reason, bool invokeOnClose = true);
  int fd() const;
  // bool isEncrypted() const;
  ConnectionState state() const;
  // void appendToBuffer(const ByteBuffer& bytes);
  void setOnClose(std::function<void(int, CloseReason)> onClose);
  void sendFrame(const Frame& frame);
  bool readFd();
};

struct Request {
  Frame frame;
  ClientConnection* conn;
};

struct Response {
  Frame frame;
  ClientConnection* conn;
};

}  // namespace fmxp
