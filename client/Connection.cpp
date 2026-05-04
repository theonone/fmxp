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
#include "../core/errors.hpp"

namespace fmxp {

Connection::Connection(const std::string& host, int port,
                       const std::string& pubKey, uint64_t maxFrameSize)
    : _host(host), _port(port), _pubKey(pubKey), _maxFrameSize(maxFrameSize) {
  _connect();
}

Connection::~Connection() { close(); }

void Connection::setOnResponse(std::function<void(const Response&)> cb) {
  _onResponse = std::move(cb);
}

// void Connection::setOnError(std::function<void(uint8_t)> cb) {
//   _onClose = std::move(cb);
// }

void Connection::_connect() {
  std::cout << "Creating socket..." << std::endl;
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

  std::cout << "Connecting to " << _host << ":" << _port << "..." << std::endl;
  if (::connect(_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
    throwErr(ERR_CONNECTION, "connect failed");
  }

  fcntl(_socket, F_SETFL, O_NONBLOCK);

  std::cout << "Creating epoll and fd..." << std::endl;
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
  std::cout << "Starting epoll loop..." << std::endl;
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
    uint64_t bodyLen = getFrameBodySize(_frameBuffer);
    if (bodyLen + __FMXP_HEADER_SIZE > _maxFrameSize) {
      close();
      // cannot just decline, because in order to reject the rest, we have to
      // receive it
      return frames;
    }
    if (_frameBuffer.size() < bodyLen + __FMXP_HEADER_SIZE)
      return frames;  // less than 1 complete frame
    ByteBuffer frameBuf =
        _frameBuffer.slice(0, bodyLen + __FMXP_HEADER_SIZE - 1);
    try {
      Frame frame = decodeFrame(frameBuf, true, _aesKey);
      if (_state == ConnectionState::HANDSHAKE) {
        if (frame.data.toString() == "Connection secured") {
          std::cout << "Handshake complete, connection secured." << std::endl;
          _state = ConnectionState::CONNECTED;
          if (bodyLen + __FMXP_HEADER_SIZE < _frameBuffer.size()) {
            _frameBuffer = _frameBuffer.slice(bodyLen + __FMXP_HEADER_SIZE,
                                              _frameBuffer.size() - 1);
          } else {
            _frameBuffer.clear();
          }
          continue;
        }
        throwErr(ERR_CONNECTION, "Handshake failed");
      }

      frames.push_back(frame);
      if (bodyLen + __FMXP_HEADER_SIZE < _frameBuffer.size()) {
        _frameBuffer = _frameBuffer.slice(bodyLen + __FMXP_HEADER_SIZE,
                                          _frameBuffer.size() - 1);
      } else {
        _frameBuffer.clear();
      }
    } catch (const FMXPException& e) {
      close();
      return frames;
    }
  }
}

void Connection::_doHandshake() {
  _aesKey = generateAESKey();
  auto encedKey = rsaEncrypt(_aesKey, _pubKey);
  _handleCommand({.type = ClientCommand::Type::SEND,
                  .frame = Request("", encedKey).toFrame()});
}

void Connection::send(const Request& req) {
  _commandQueue.push({ClientCommand::Type::SEND, req.toFrame()});

  uint64_t one = 1;
  write(_cmdEvFd, &one, sizeof(one));
}

void Connection::close() {
  if (!_running) return;

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

void Connection::_handleCommand(const ClientCommand& cmd) {
  if (cmd.type == ClientCommand::Type::SEND) {
    ByteBuffer toBeSent;
    if (_state == ConnectionState::HANDSHAKE) {
      if (_handshakeSent) return;
      _handshakeSent = true;

      // the only frame we don't encrypt here
      toBeSent = encodeFrame(cmd.frame.value(), false, ByteBuffer());
      ::send(_socket, toBeSent.cdata(), toBeSent.size(), 0);
      std::cout << "Handshake sent" << std::endl;
      return;
    }

    // normal sending logic
    ByteBuffer encoded = encodeFrame(cmd.frame.value(), true, _aesKey);
    ::send(_socket, encoded.cdata(), encoded.size(), 0);
    std::cout << "Sent " << encoded.size() << " bytes" << std::endl;

  } else if (cmd.type == ClientCommand::Type::CLOSE) {
    close();
  }
}

void Connection::_epollLoop() {
  epoll_event events[32];

  std::cout << "Handshaking..." << std::endl;
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
          _running = false;
          //   if (_onClose) _onClose();
          _state = ConnectionState::CLOSED;
          continue;
        }

        // read
        if (events[i].events & EPOLLIN) {
          char buffer[4096];
          ssize_t len = recv(_socket, buffer, sizeof(buffer), 0);

          std::cout << "Received " << len << " bytes" << std::endl;

          if (len <= 0) {
            _running = false;
            // if (_onClose) _onClose();
            _state = ConnectionState::CLOSED;
            continue;
          }

          // handle read
          _frameBuffer.append(reinterpret_cast<uint8_t*>(buffer), len);
          auto frames = _parseFrames();
          for (auto& frame : frames) {
            _onResponse(frame);
          }
        }
      }
    }
  }
}

}  // namespace fmxp
