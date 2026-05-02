// #include "Server.hpp"

// #include <netinet/in.h>
// #include <sys/epoll.h>
// #include <sys/socket.h>
// #include <unistd.h>

// #include <cstring>
// #include <iostream>

// #include "core/enc/aes.hpp"
// #include "core/enc/rsa.hpp"

// namespace fmxp {

// Server::Server(int port, std::string privKey, int maxConnections,
//                int maxFrameSize)
//     : _privKey(std::move(privKey)),
//       _port(port),
//       _maxConnections(maxConnections),
//       _maxFrameSize(maxFrameSize) {}

// Server::~Server() { stop(); }

// void Server::route(const std::string& path,
//                    std::function<void(Request&, Responder&)> handler) {
//   _routes[path] = std::move(handler);
// }

// void Server::route(std::function<bool(const Request&)> matcher,
//                    std::function<void(Request&, Responder&)> handler) {
//   _functionalRouters.push_back([matcher, handler](const Request& req) mutable
//   {
//     if (matcher(req)) {
//       Responder res;
//       handler(const_cast<Request&>(req), res);
//       return true;
//     }
//     return false;
//   });
// }

// // ---------------- Listen ----------------

// void Server::listen() {
//   // create socket
//   _socket = ::socket(AF_INET, SOCK_STREAM, 0);
//   if (_socket < 0) {
//     throwErr("Failed to create socket");
//   }

//   sockaddr_in addr{};
//   addr.sin_family = AF_INET;
//   addr.sin_port = htons(_port);
//   addr.sin_addr.s_addr = INADDR_ANY;

//   if (bind(_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
//     throwErr("Bind failed");
//   }

//   if (::listen(_socket, _maxConnections) < 0) {
//     throwErr("Listen failed");
//   }

//   // create epoll
//   _epollFd = epoll_create1(0);
//   if (_epollFd < 0) {
//     throwErr("Epoll create failed");
//   }

//   epoll_event ev{};
//   ev.events = EPOLLIN;
//   ev.data.fd = _socket;

//   epoll_ctl(_epollFd, EPOLL_CTL_ADD, _socket, &ev);

//   _running = true;

//   // run epoll loop in separate thread
//   _epollThread = std::thread(&Server::epollLoop, this);
// }

// // ---------------- Stop ----------------

// void Server::stop() {
//   _running = false;

//   if (_epollThread.joinable()) {
//     _epollThread.join();
//   }

//   if (_socket != -1) {
//     close(_socket);
//     _socket = -1;
//   }

//   if (_epollFd != -1) {
//     close(_epollFd);
//     _epollFd = -1;
//   }
// }

// // ---------------- Epoll Loop ----------------

// void Server::epollLoop() {
//   epoll_event events[64];

//   while (_running) {
//     int n = epoll_wait(_epollFd, events, 64, -1);

//     for (int i = 0; i < n; i++) {
//       int fd = events[i].data.fd;

//       // new connection
//       if (fd == _socket) {
//         int client = accept(_socket, nullptr, nullptr);
//         if (client < 0) continue;

//         epoll_event ev{};
//         ev.events = EPOLLIN | EPOLLRDHUP;
//         ev.data.fd = client;

//         epoll_ctl(_epollFd, EPOLL_CTL_ADD, client, &ev);

//         _clientFds.push_back(client);

//         continue;
//       }

//       // client disconnect
//       if (events[i].events & EPOLLRDHUP) {
//         close(fd);
//         continue;
//       }

//       // TODO:
//       // 1. read into per-fd buffer
//       // 2. extract frames
//       // 3. handleFrame(fd, frame)

//       char buffer[4096];
//       int bytes = recv(fd, buffer, sizeof(buffer), 0);

//       if (bytes <= 0) {
//         close(fd);
//         continue;
//       }

//       // placeholder: frame extraction happens later
//       std::string raw(buffer, bytes);

//       Frame frame;  // assume decoded elsewhere

//       handleFrame(fd, frame);
//     }
//   }
// }

// // ---------------- Frame Handling ----------------

// void Server::handleFrame(int fd, const Frame& frame) {
//   Request req;
//   req.path = frame.path;
//   req.data = frame.data;
//   req.id = frame.id;

//   Responder res;

//   // fast path routing
//   auto it = _routes.find(req.path);
//   if (it != _routes.end()) {
//     it->second(req, res);
//   } else {
//     // fallback functional routing
//     for (auto& r : _functionalRouters) {
//       if (r(req)) return;
//     }

//     if (onError) {
//       onError("Route not found: " + req.path);
//     }
//   }

//   // TODO:
//   // serialize response → encrypt → send(fd)
// }

// // ---------------- Response Sending ----------------

// void Server::sendResponse(Connection& conn, const Frame& frame) {
//   // placeholder for future:
//   // encodeFrame → aesEncrypt → send(fd)
// }

// }  // namespace fmxp
