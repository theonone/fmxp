#include "structures.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "../core/enc/aes.hpp"
#include "../core/enc/rsa.hpp"
#include "../core/encoders.hpp"
#include "../core/errors.hpp"

namespace fmxp {

ClientConnection::ClientConnection(int fd, uint64_t maxFrameSize,
                                   const std::string& rsaPrivKey,
                                   std::function<void(Request)> onNewRequest)
    : _fd(fd),
      _maxFrameSize(maxFrameSize),
      _onNewRequest(onNewRequest),
      _rsaPrivKey(rsaPrivKey) {}

ClientConnection::~ClientConnection() { closeConnection(CloseReason::NATURAL); }

void ClientConnection::closeConnection(CloseReason reason, bool invokeOnClose) {
  if (_state == ConnectionState::CLOSED) return;
  int oldFd = _fd;
  if (_fd != -1) {
    close(_fd);
    _fd = -1;
  }
  _state = ConnectionState::CLOSED;

  if (invokeOnClose && _onClose) {
    _onClose(oldFd, reason);
  }
}

int ClientConnection::fd() const { return _fd; }

void ClientConnection::_setAesKey(const ByteBuffer& aesKey) {
  _aesKey = aesKey;
  auto frame = makeResponseFrame(STATUS_OK, ByteBuffer(),
                                 ByteBuffer("Connection secured"), 0, 0);
  sendFrame(frame);
  _state = ConnectionState::ACTIVE;
}

// bool ClientConnection::isEncrypted() const { return _aesKey.size() > 0; }

ConnectionState ClientConnection::state() const { return _state; }

// void ClientConnection::_appendToBuffer(const ByteBuffer& bytes) {
//   _inFrameBuffer += bytes;
// }

void ClientConnection::setOnClose(
    std::function<void(int, CloseReason)> onClose) {
  _onClose = onClose;
}

std::vector<Frame> ClientConnection::_parseFrames() {
  std::vector<Frame> frames;

  while (true) {
    if (_inFrameBuffer.size() < __FMXP_MIN_FRAME_SIZE) return frames;

    const uint8_t* ptr = _inFrameBuffer.cdata();
    if (!validateProtocol(_inFrameBuffer)) {  // invalid frame
      closeConnection(CloseReason::INVALID_REQUEST);
      return frames;
    }
    uint64_t bodyLen = getFrameBodySize(_inFrameBuffer);
    if (bodyLen + __FMXP_HEADER_SIZE > _maxFrameSize) {
      closeConnection(CloseReason::REQUEST_TOO_LONG);
      // cannot just decline, because in order to reject the rest, we have to
      // receive it
      return frames;
    }
    if (_inFrameBuffer.size() < bodyLen + __FMXP_HEADER_SIZE)
      return frames;  // less than 1 complete frame
    ByteBuffer frameBuf = _inFrameBuffer.slice(0, bodyLen + __FMXP_HEADER_SIZE);
    try {
      // if AES key not yet set, parse just ONE frame, return. the client is
      // expected to wait for the handshake to complete before sending requests
      if (_state == ConnectionState::HANDSHAKE) {
        Frame frame = decodeFrame(frameBuf, false, ByteBuffer());
        frames.push_back(frame);
        _inFrameBuffer = _inFrameBuffer.slice(bodyLen + __FMXP_HEADER_SIZE,
                                              _inFrameBuffer.size());
        return frames;
      }
      Frame frame = decodeFrame(frameBuf, true, _aesKey);
      frames.push_back(frame);
      _inFrameBuffer = _inFrameBuffer.slice(bodyLen + __FMXP_HEADER_SIZE,
                                            _inFrameBuffer.size());
    } catch (const FMXPException& e) {
      closeConnection(CloseReason::INVALID_REQUEST);
      return frames;
    }
  }
}

void ClientConnection::sendFrame(const Frame& frame) {
  ByteBuffer encoded = encodeFrame(frame, true, _aesKey);
  size_t total = 0;
  while (total < encoded.size()) {
    ssize_t sent =
        send(_fd, encoded.cdata() + total, encoded.size() - total, 0);

    if (sent <= 0) {
      closeConnection(CloseReason::SOCKET_ERROR);
      return;
    }

    total += sent;
  }
}

bool ClientConnection::readFd() {
  char buf[4096];

  ssize_t bytes = recv(_fd, buf, sizeof(buf), 0);

  if (bytes == 0) {
    closeConnection(CloseReason::NATURAL);
    return false;
  }

  if (bytes < 0) {
    closeConnection(SOCKET_ERROR);
    return false;
  }

  _inFrameBuffer.append(reinterpret_cast<uint8_t*>(buf), bytes);
  auto frames = _parseFrames();

  // the first frame is always expected to be an encrypted aes key, unless the
  // connection is set to be insecure
  if (_state == ConnectionState::HANDSHAKE && frames.size() > 0) {
    const auto& encAesKey = frames[0].data;
    try {
      auto decrypted = rsaDecrypt(encAesKey, _rsaPrivKey);
      if (decrypted.size() != __AES_KEY_SIZE) {
        closeConnection(CloseReason::ENCRYPTION_ERROR);
        return false;
      }
      _setAesKey(decrypted);
    } catch (const FMXPException& e) {
      closeConnection(CloseReason::ENCRYPTION_ERROR);
      return false;
    }
  } else if (_state == ConnectionState::ACTIVE) {
    for (const auto& frame : frames) {
      _onNewRequest(Request{frame, this});
    }
  }
  return true;
}

}  // namespace fmxp