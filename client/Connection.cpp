#include "Connection.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "../core/enc/aes.hpp"
#include "../core/enc/rsa.hpp"
#include "../core/encoders.hpp"
#include "../core/errors.hpp"

namespace fmxp {

Connection::Connection(const std::string& host, int port,
                       const std::string& pubKey, uint32_t maxFrameSize,
                       std::function<void(const Response&)> onResponse)
    : _host(host),
      _port(port),
      _pubKey(pubKey),
      _maxFrameSize(maxFrameSize),
      _onResponse(std::move(onResponse)) {
  _connect();
}

Connection::~Connection() { close(); }

void Connection::setOnResponse(std::function<void(const Response&)> cb) {
  _onResponse = std::move(cb);
}

void Connection::setOnClose(std::function<void()> cb) {
  _onClose = std::move(cb);
}

// void Connection::setOnError(std::function<void(uint8_t)> cb) {
//   _onClose = std::move(cb);
// }

void Connection::_connect() {
  _socket = socket(AF_INET, SOCK_STREAM, 0);
  if (_socket < 0) {
    throwErr(ERR_CONNECTION, "socket failed");
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(_port);

  if (inet_pton(AF_INET, _host.c_str(), &addr.sin_addr) <= 0) {
    throwErr(ERR_CONNECTION, "invalid address");
  }

  if (::connect(_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
    throwErr(ERR_CONNECTION, "connect failed");
  }

  fcntl(_socket, F_SETFL, O_NONBLOCK);

  _epollFd = epoll_create1(0);
  if (_epollFd < 0) {
    throwErr(ERR_CONNECTION, "epoll_create failed");
  }

  _cmdEvFd = eventfd(0, EFD_NONBLOCK);
  if (_cmdEvFd < 0) {
    throwErr(ERR_CONNECTION, "eventfd failed");
  }

  epoll_event ev{};
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = _socket;

  if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, _socket, &ev) < 0) {
    throwErr(ERR_CONNECTION, "epoll socket add failed");
  }

  ev.data.fd = _cmdEvFd;
  if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, _cmdEvFd, &ev) < 0) {
    throwErr(ERR_CONNECTION, "epoll eventfd add failed");
  }

  _running = true;
  _epollThread = std::thread(&Connection::_epollLoop, this);
}

std::vector<Frame> Connection::_parseFrames() {
  std::vector<Frame> frames;

  while (true) {
    if (_frameBuffer.size() < __FMXP_MIN_FRAME_SIZE) return frames;

    if (!validateProtocol(_frameBuffer)) {  // invalid frame
      close();
      return frames;
    }
    uint32_t bodyLen = getFrameBodySize(_frameBuffer);
    if (bodyLen > _maxFrameSize ||
        bodyLen + __FMXP_HEADER_SIZE >
            _maxFrameSize) {  // OR is for overflow protection
      close();
      // cannot just decline, because in order to reject the rest, we have to
      // receive it
      return frames;
    }
    if (_frameBuffer.size() < bodyLen + __FMXP_HEADER_SIZE)
      return frames;  // less than 1 complete frame
    ByteBuffer frameBuf = _frameBuffer.slice(0, bodyLen + __FMXP_HEADER_SIZE);
    try {
      Frame frame = decodeFrame(frameBuf, true, _aesKey);
      if (_state == ConnectionState::HANDSHAKE) {
        if (frame.data.toString() == "Connection secured") {
          _state = ConnectionState::CONNECTED;
          _ssid = frame.ssid;
          _frameBuffer = _frameBuffer.slice(bodyLen + __FMXP_HEADER_SIZE,
                                            _frameBuffer.size());

          continue;
        }
        throwErr(ERR_CONNECTION, "Handshake failed");
      }

      frames.push_back(frame);
      _frameBuffer =
          _frameBuffer.slice(bodyLen + __FMXP_HEADER_SIZE, _frameBuffer.size());

    } catch (const FMXPException& e) {
      close();
      return frames;
    }
  }
}

void Connection::_doHandshake() {
  _aesKey = generateAESKey();
  auto encedKey = rsaEncrypt(_aesKey + u32ToStr(getTimestamp()), _pubKey);
  ClientCommand c = {.type = ClientCommand::Type::SEND,
                     .frame = _makeReqFrame("", encedKey, 0)};
  _handleCommand(c);
}

Frame Connection::_makeReqFrame(const std::string& path, const ByteBuffer& data,
                                uint8_t flags) {
  return makeFrame(_fid, STATUS_REQ, flags, path, data, ++_rid, _ssid);
}

bool Connection::_validateFrame(const Frame& frame) {
  if (frame.fid <= _lastSrvFid || frame.ssid != _ssid) {
    close();
    return false;
  }
  return true;
}

bool Connection::send(const Request& req) {
  if (!_running || _state == ConnectionState::CLOSED) return false;
  _commandQueue.push(
      {ClientCommand::Type::SEND, _makeReqFrame(req.path(), req.data(), 0)});

  uint64_t one = 1;
  write(_cmdEvFd, &one, sizeof(one));

  return true;
}

void Connection::close() {
  if (!_running || _state == ConnectionState::CLOSED) return;

  if (_onClose) _onClose();
  _state = ConnectionState::CLOSED;

  _running = false;

  uint64_t one = 1;
  write(_cmdEvFd, &one, sizeof(one));

  if (_epollThread.joinable()) {
    _epollThread.join();
  }

  if (_socket != -1) ::close(_socket);
  if (_epollFd != -1) ::close(_epollFd);
  if (_cmdEvFd != -1) ::close(_cmdEvFd);

  _socket = -1;
  _epollFd = -1;
  _cmdEvFd = -1;
}

void Connection::_handleCommand(ClientCommand& cmd) {
  if (cmd.type == ClientCommand::Type::SEND) {
    ByteBuffer toBeSent;
    if (!cmd.frame.has_value())
      throwErr(
          ERR_CONNECTION,
          "Connection::_handleCommand: send command does not have a frame");
    if (_state == ConnectionState::HANDSHAKE) {
      if (_handshakeSent) return;
      _handshakeSent = true;  // the only frame we don't encrypt here
      toBeSent = encodeFrame(cmd.frame.value(), false, ByteBuffer());
      ::send(_socket, toBeSent.cdata(), toBeSent.size(), 0);
      return;
    }

    // now ID is assigned at the sending stage, ensuring no races happen
    cmd.frame->fid = ++_fid;

    ByteBuffer encoded = encodeFrame(cmd.frame.value(), true, _aesKey);
    ::send(_socket, encoded.cdata(), encoded.size(), 0);

  } else if (cmd.type == ClientCommand::Type::CLOSE) {
    close();
  }
}

void Connection::_epollLoop() {
  epoll_event events[32];

  _doHandshake();

  while (_running) {
    int n = epoll_wait(_epollFd, events, 32, -1);

    for (int i = 0; i < n; i++) {
      int fd = events[i].data.fd;

      if (fd == _cmdEvFd) {
        uint64_t counter;
        read(_cmdEvFd, &counter, sizeof(counter));

        ClientCommand cmd;
        while (_commandQueue.tryPop(cmd)) {
          _handleCommand(cmd);
        }
        continue;
      }

      if (fd == _socket) {
        // disconnect
        if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
          close();
          continue;
        }

        // read
        if (events[i].events & EPOLLIN) {
          char buf[8192];

          while (true) {
            ssize_t bytes = recv(_socket, buf, sizeof(buf), 0);

            // peer disconnected
            if (bytes == 0) {
              close();
              break;
            }

            // socket error
            if (bytes < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) break;
              close();
              break;
            }

            // append received chunk
            _frameBuffer.append(reinterpret_cast<uint8_t*>(buf),
                                static_cast<size_t>(bytes));
          }
          auto frames = _parseFrames();
          for (auto& frame : frames) {
            if (!_validateFrame(frame)) break;
            _lastSrvFid = frame.fid;
            _onResponse(frame);
          }
        }
      }
    }
  }
}

}  // namespace fmxp
