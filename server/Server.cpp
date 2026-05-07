#include "Server.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "../core/enc/aes.hpp"
#include "../core/enc/rsa.hpp"
#include "../core/errors.hpp"

namespace fmxp {
// runs inside threadpool
void Server::_router(Request req) {
  auto rtIt = _routes.find(req.path());
  if (rtIt != _routes.end()) {
    rtIt->second(req, _responder);
  } else {
    for (const auto& [matcher, handler] : _funcRoutes) {
      if (matcher(req)) {
        handler(req, _responder);
        return;
      }
    }

    _responder.respond(Response(req, "", fmxp::STATUS_NOT_FOUND));
  }
}

// always on epoll thread, so can send, close and whatever else
void Server::_handleCommand(const ServerCommand& cmd) {
  auto it = _connections.find(cmd.connID);
  if (it == _connections.end()) {
    _onErr(ERR_CONNECTION,
           std::to_string(cmd.connID) + ": Connection not found");
    return;
  }

  if (cmd.type == ServerCommand::Type::SEND) {
    it->second->sendFrame(cmd.frame.value());
  } else if (cmd.type == ServerCommand::Type::CLOSE) {
    it->second->closeConnection(CloseReason::NATURAL, true);
  }
}

void Server::_wakeEpoll() {
  uint64_t one = 1;
  write(_cmdEvFd, &one, sizeof(one));
}

Server::Server(int port, std::string privKey, size_t workerThreads,
               int maxConnections, int maxFrameSize)
    : _privKey(std::move(privKey)),
      _port(port),
      _maxConnections(maxConnections),
      _maxFrameSize(maxFrameSize),
      _tpool(workerThreads),
      _responder([this](const Response& resp) { sendResponse(resp); },
                 [this](uint64_t connID) { closeConnection(connID); }) {
  _onErr = [this](uint8_t code, const std::string& message) {
    _defaultErrorHandler(code, message);
  };
}

Server::~Server() { stop(); }

void Server::route(const std::string& path,
                   std::function<void(Request&, const Responder&)> handler) {
  _routes[path] = handler;
}

void Server::route(std::function<bool(const Request&)> matcher,
                   std::function<void(Request&, const Responder&)> handler) {
  _funcRoutes.push_back({matcher, handler});
}

void Server::sendResponse(const Response& resp) {
  _commandQueue.push({.type = ServerCommand::Type::SEND,
                      .connID = resp.connectionID(),
                      .frame = resp.toFrame()});

  _wakeEpoll();
}

void Server::closeConnection(uint64_t connectionID) {
  _commandQueue.push({.type = ServerCommand::Type::CLOSE,
                      .connID = connectionID,
                      .frame = std::nullopt});
  _wakeEpoll();
}

void Server::listen() {
  _socket = socket(AF_INET, SOCK_STREAM, 0);
  if (_socket < 0) {
    throwErr(ERR_CONNECTION, "socket creation failed");
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(_port);
  addr.sin_addr.s_addr = INADDR_ANY;

  int opt = 1;
  setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  if (bind(_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
    throwErr(ERR_CONNECTION, "bind failed");
  }

  if (::listen(_socket, _maxConnections) < 0) {
    throwErr(ERR_CONNECTION, "listen failed");
  }

  fcntl(_socket, F_SETFL, O_NONBLOCK);

  _epollFd = epoll_create1(0);
  if (_epollFd < 0) {
    throwErr(ERR_CONNECTION, "epoll_create failed");
  }

  _cmdEvFd = eventfd(0, EFD_NONBLOCK);
  if (_cmdEvFd == -1) {
    throwErr(ERR_CONNECTION, "eventfd create failed");
  }

  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = _socket;

  if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, _socket, &ev) == -1) {
    throwErr(ERR_CONNECTION, "epoll socket binding failed");
  }
  ev.data.fd = _cmdEvFd;
  if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, _cmdEvFd, &ev) == -1) {
    throwErr(ERR_CONNECTION, "epoll eventfd binding failed");
  }
  _running = true;
  //   _epollThread = std::thread(&Server::_epollLoop, this);
  _epollLoop();
}

void Server::stop() {
  _running = false;
  _commandQueue.clear();
  _wakeEpoll();

  for (auto& p : _connections) {
    delete p.second;
  }
  _connections.clear();
  _fdToId.clear();

  if (_socket != -1) close(_socket);
  if (_epollFd != -1) close(_epollFd);
}

void Server::setOnError(std::function<bool(uint8_t, const std::string&)> cb) {
  _onErr = [this, cb = std::move(cb)](uint8_t code,
                                      const std::string& message) {
    if (!cb(code, message)) {
      _defaultErrorHandler(code, message);
    }
  };
}

void Server::_epollLoop() {
  epoll_event events[64];

  while (_running) {
    int n = epoll_wait(_epollFd, events, 64, -1);

    for (int i = 0; i < n; i++) {
      int fd = events[i].data.fd;

      // new command in queue
      if (fd == _cmdEvFd) {
        uint64_t counter;
        read(_cmdEvFd, &counter, sizeof(counter));

        ServerCommand cmd;
        while (_commandQueue.tryPop(cmd)) {
          _handleCommand(cmd);
        }
        continue;
      }

      // new connection
      if (fd == _socket) {
        while (true) {
          int clientFd = accept(_socket, nullptr, nullptr);

          if (clientFd < 0) {
            break;
          }

          fcntl(clientFd, F_SETFL, O_NONBLOCK);

          epoll_event ev{};
          ev.events = EPOLLIN | EPOLLRDHUP;
          ev.data.fd = clientFd;

          epoll_ctl(_epollFd, EPOLL_CTL_ADD, clientFd, &ev);

          ClientConnection* conn =
              new ClientConnection(clientFd, _maxFrameSize, _privKey,
                                   [this](Request req) { _onRequest(req); });
          if (_onDisconn) conn->setOnClose(_onDisconn);
          _connections[conn->id()] = conn;
          _fdToId[clientFd] = conn->id();
        }
        continue;
      }

      // existing connection
      auto it = _fdToId.find(fd);
      if (it == _fdToId.end()) continue;
      uint64_t connId = it->second;

      auto it2 = _connections.find(connId);
      if (it2 == _connections.end()) continue;
      ClientConnection* conn = it2->second;

      // disconnect
      if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
        auto it = _connections.find(connId);
        if (it != _connections.end()) {
          delete it->second;
          _connections.erase(it);
        }
        continue;
      }

      // readable
      if (events[i].events & EPOLLIN) {
        bool ok = conn->readFd();

        if (!ok || (conn->state() == ConnectionState::CLOSED)) {
          delete conn;
          _connections.erase(it2);
        }
      }
    }
  }
}
void Server::_onRequest(Request req) {
  _tpool.enqueue([this, req = std::move(req)]() { _router(req); });
}

void Server::_defaultErrorHandler(uint8_t code, const std::string& message) {
  throw FMXPException(code, message);
}
}  // namespace fmxp
