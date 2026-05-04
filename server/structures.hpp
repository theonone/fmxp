#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "../core/ByteBuffer.hpp"
#include "../core/frame.hpp"
#include "../core/iostructs.hpp"

namespace fmxp {

enum CloseReason {
  NATURAL = 0,
  ENCRYPTION_ERROR = 1,
  INVALID_REQUEST = 2,
  REQUEST_TOO_LONG = 3,
  SOCKET_ERROR = 4,
};

enum ConnectionState { HANDSHAKE, ACTIVE, CLOSED };

class ClientConnection {
 private:
  static std::atomic<uint64_t> _connCount;
  int _fd = -1;
  uint64_t _connId;
  uint64_t _maxFrameSize;
  ConnectionState _state = ConnectionState::HANDSHAKE;
  ByteBuffer _aesKey;
  ByteBuffer _inFrameBuffer;
  std::function<void(int, CloseReason)> _onClose;
  const std::string& _rsaPrivKey;
  std::function<void(Request)> _onNewRequest;
  void _setAesKey(const ByteBuffer& aesKey);
  std::vector<Frame> _parseFrames();

  bool _validateFrame(const Frame& frame);

 public:
  ClientConnection(int fd, uint64_t maxFrameSize, const std::string& rsaPrivKey,
                   std::function<void(Request)> onNewRequest);
  ~ClientConnection();
  void closeConnection(CloseReason reason, bool invokeOnClose = true);
  uint64_t id() const;
  ConnectionState state() const;
  void setOnClose(std::function<void(int, CloseReason)> onClose);
  void sendFrame(const Frame& frame);
  bool readFd();

  ClientConnection(const ClientConnection&) = delete;
  ClientConnection& operator=(const ClientConnection&) = delete;
  ClientConnection(ClientConnection&&) = delete;
  ClientConnection& operator=(ClientConnection&&) = delete;
};

}  // namespace fmxp
