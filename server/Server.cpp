#include "Server.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include "../core/enc/aes.hpp"
#include "../core/enc/rsa.hpp"
#include "../core/errors.hpp"

namespace fmxp {

Server::Server(int port, std::string privKey, int maxConnections,
               int maxFrameSize)
    : _privKey(std::move(privKey)),
      _port(port),
      _maxConnections(maxConnections),
      _maxFrameSize(maxFrameSize) {
  _onErr = [this](uint8_t code, const std::string& message) {
    _defaultErrorHandler(code, message);
  };
}

Server::~Server() { stop(); }

void Server::listen() {
  _socket = socket(AF_INET, SOCK_STREAM, 0);
  if (_socket < 0) {
    throwErr(ERR_CONNECTION, "socket failed");
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(_port);
  addr.sin_addr.s_addr = INADDR_ANY;

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

  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = _socket;

  epoll_ctl(_epollFd, EPOLL_CTL_ADD, _socket, &ev);

  _running = true;
  //   _epollThread = std::thread(&Server::_epollLoop, this);
  _epollLoop();
}

void Server::stop() {
  _running = false;

  for (auto& [fd, conn] : _connections) {
    delete conn;
  }
  _connections.clear();

  if (_socket != -1) close(_socket);
  if (_epollFd != -1) close(_epollFd);
}

void Server::_epollLoop() {
  epoll_event events[64];

  while (_running) {
    int n = epoll_wait(_epollFd, events, 64, -1);

    for (int i = 0; i < n; i++) {
      int fd = events[i].data.fd;

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
                                   [this](Request& req) { _onRequest(req); });
          if (_onDisconn) conn->setOnClose(_onDisconn);

          _connections[clientFd] = conn;
        }
        continue;
      }

      // existing connection
      auto it = _connections.find(fd);
      if (it == _connections.end()) continue;

      ClientConnection* conn = it->second;

      // disconnect
      if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
        conn->closeConnection();
        delete conn;
        _connections.erase(it);
        continue;
      }

      // readable
      if (events[i].events & EPOLLIN) {
        bool ok = conn->readFd();

        if (!ok || (conn->state() == ConnectionState::CLOSED)) {
          delete conn;
          _connections.erase(it);
        }
      }
    }
  }
}
void Server::_onRequest(Request& req) {
  std::lock_guard<std::mutex> lock(_reqQMutex);
  _reqQueue.push(req);
}

void Server::_defaultErrorHandler(uint8_t code, const std::string& message) {
  throw FMXPException(code, message);
}
}  // namespace fmxp
