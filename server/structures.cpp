#include "structures.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "../core/encoders.hpp"
#include "../core/errors.hpp"

namespace fmxp {

Connection::Connection(int fd, uint64_t maxFrameSize)
    : _fd(fd), _maxFrameSize(maxFrameSize) {}

Connection::~Connection() { closeConnection(); }

void Connection::closeConnection() {
  if (_fd != -1) {
    close(_fd);
    _fd = -1;
  }
}

int Connection::fd() const { return _fd; }

void Connection::setAesKey(const ByteBuffer& aesKey) { _aesKey = aesKey; }

bool Connection::isSafe() const { return _aesKey.size() > 0; }

bool Connection::isConnected() const { return _fd != -1; }

void Connection::appendToBuffer(const ByteBuffer& bytes) {
  _inFrameBuffer += bytes;
}

void Connection::setOnError(
    std::function<void(uint8_t, const std::string&)> onError) {
  _onErr = onError;
}

std::vector<Frame> Connection::parseFrames() {
  std::vector<Frame> frames;

  while (true) {
    if (_inFrameBuffer.size() < 21) return frames;

    const uint8_t* ptr = _inFrameBuffer.cdata();
    if (std::memcmp(ptr, "fmxp", 4) != 0) {  // invalid frame
      _onErr(ERR_INVALID_FRAME, std::to_string(_fd) + ": Bad frame");
      return frames;
    }
    uint64_t bodyLen = ptrToU64(ptr + 9);
    if (bodyLen > _maxFrameSize) {
      _onErr(ERR_FRAME_TOO_LONG, std::to_string(_fd) + ": Frame too big");
      return frames;
    }
    ByteBuffer frameBuf = _inFrameBuffer.slice(0, bodyLen + 17);
    try {
      Frame frame = decodeFrame(frameBuf, isSafe(), _aesKey);
      frames.push_back(frame);
      _inFrameBuffer =
          _inFrameBuffer.slice(bodyLen + 17, _inFrameBuffer.size());
    } catch (const FMXPException& e) {
      _onErr(e.code(), std::to_string(_fd) + ": " + e.what());
      return frames;
    }
  }
}

void Connection::sendFrame(const Frame& frame) {
  ByteBuffer encoded = encodeFrame(frame, isSafe(), _aesKey);
  int sent = send(_fd, encoded.cdata(), encoded.size(), 0);
  if (sent == -1) {
    _onErr(ERR_SEND_FAILED, std::to_string(_fd) + ": Send failed");
  }
}

}  // namespace fmxp