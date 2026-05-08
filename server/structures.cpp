#include "structures.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "../core/enc/aes.hpp"
#include "../core/enc/rand.hpp"
#include "../core/enc/rsa.hpp"
#include "../core/encoders.hpp"
#include "../core/errors.hpp"

namespace fmxp {

std::atomic<uint64_t> ClientConnection::_connCount = 0;

ClientConnection::ClientConnection(int fd, uint32_t maxFrameSize,
                                   const std::string& rsaPrivKey,
                                   std::function<void(Request)> onNewRequest)
    : _fd(fd),
      _maxFrameSize(maxFrameSize),
      _onNewRequest(onNewRequest),
      _rsaPrivKey(rsaPrivKey) {
  _connId = ++_connCount;
}

ClientConnection::~ClientConnection() { closeConnection(CloseReason::NATURAL); }

void ClientConnection::closeConnection(CloseReason reason, bool invokeOnClose) {
  if (_state == ConnectionState::CLOSED) return;
  if (_fd != -1) {
    if (reason != CloseReason::NATURAL) {
      sendFrame(makeRespFrame("", ByteBuffer(), STATUS_OK, 0, 0));
    }
    close(_fd);
    _fd = -1;
  }
  _state = ConnectionState::CLOSED;

  if (invokeOnClose && _onClose) {
    _onClose(_connId, reason);
  }
}

uint64_t ClientConnection::id() const { return _connId; }

void ClientConnection::_setAesKey(const ByteBuffer& aesKey) {
  _aesKey = aesKey;
  _ssid = fmxp::rand64();
  auto frame =
      makeRespFrame("", ByteBuffer("Connection secured"), STATUS_OK, 0, 0);
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

    if (!validateProtocol(_inFrameBuffer)) {  // invalid frame
      closeConnection(CloseReason::INVALID_REQUEST);
      return frames;
    }
    uint32_t bodyLen = getFrameBodySize(_inFrameBuffer);
    if (bodyLen > _maxFrameSize ||
        bodyLen + __FMXP_HEADER_SIZE > _maxFrameSize) {
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
    } catch (const std::runtime_error& e) {
      closeConnection(CloseReason::INVALID_REQUEST);
      return frames;
    }
  }
}

bool ClientConnection::_validateFrame(const Frame& frame) {
  if (frame.ssid != _ssid || frame.fid <= _lastCliFid) {
    closeConnection(CloseReason::INVALID_REQUEST);
    return false;
  }
  return true;
}

Frame ClientConnection::makeRespFrame(const std::string& path,
                                      const ByteBuffer& data, uint8_t status,
                                      uint8_t flags, uint32_t rid) {
  return makeFrame(_fid, status, flags, path, data, rid, _ssid);
}

void ClientConnection::sendFrame(const Frame& frame) {
  try {
    ByteBuffer encoded = encodeFrame(frame, true, _aesKey, ++_fid);

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
  } catch (const std::runtime_error& e) {
    closeConnection(CloseReason::ENCRYPTION_ERROR);
    return;
  }
}

bool ClientConnection::readFd() {
  char buf[8192];

  while (true) {
    ssize_t bytes = recv(_fd, buf, sizeof(buf), 0);

    // disconnect
    if (bytes == 0) {
      closeConnection(CloseReason::NATURAL);
      return false;
    }

    // error or no data
    if (bytes < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;

      closeConnection(CloseReason::SOCKET_ERROR);
      return false;
    }

    // append received chunk
    _inFrameBuffer.append(reinterpret_cast<uint8_t*>(buf),
                          static_cast<size_t>(bytes));
  }
  auto frames = _parseFrames();

  // the first frame is always expected to be an encrypted aes key, unless the
  // connection is set to be insecure
  if (_state == ConnectionState::HANDSHAKE && frames.size() > 0) {
    const auto& encAesKey = frames[0].data;
    try {
      auto decrypted = rsaDecrypt(encAesKey, _rsaPrivKey);
      if (decrypted.size() != __AES_KEY_SIZE + 4) {
        closeConnection(CloseReason::ENCRYPTION_ERROR);
        return false;
      }
      auto timestamp = ptrToU32(decrypted.cdata() + __AES_KEY_SIZE);
      if (timestamp - getTimestamp() > 60) {
        closeConnection(CloseReason::ENCRYPTION_ERROR);
        return false;
      }

      _setAesKey(decrypted.slice(0, __AES_KEY_SIZE));
    } catch (const std::runtime_error& e) {
      closeConnection(CloseReason::ENCRYPTION_ERROR);
      return false;
    }
  } else if (_state == ConnectionState::ACTIVE) {
    for (const auto& frame : frames) {
      if (!_validateFrame(frame)) {
        return false;
      }
      _lastCliFid = frame.fid;
      _onNewRequest(Request(IOFrame{frame, _connId}));
    }
  }
  return true;
}

Request::Request(const IOFrame& ioFrame)
    : _connID(ioFrame.connectionID),
      _path(ioFrame.frame.path),
      _data(ioFrame.frame.data),
      _rid(ioFrame.frame.rid) {}

uint64_t Request::connectionID() const { return _connID; }

const std::string& Request::path() const { return _path; }

const ByteBuffer& Request::data() const { return _data; }

uint32_t Request::rid() const { return _rid; }

Response::Response(const Request& request, const ByteBuffer& data,
                   uint8_t status)
    : _connID(request.connectionID()),
      _path(request.path()),
      _data(data),
      _status(status),
      _rid(request.rid()) {}

Response::Response(uint64_t connectionID, const std::string& path,
                   const std::string& message, uint32_t rid, uint8_t status)
    : _connID(connectionID), _path(path), _status(status), _rid(rid) {}

uint64_t Response::connectionID() const { return _connID; }

const std::string& Response::path() const { return _path; }

const ByteBuffer& Response::data() const { return _data; }

uint8_t Response::status() const { return _status; }

uint32_t Response::rid() const { return _rid; }

}  // namespace fmxp