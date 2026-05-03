#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "structures.hpp"

namespace fmxp {

class Server {
 private:
  std::string _privKey;
  int _port;
  int _maxConnections;
  int _maxFrameSize;

  int _socket = -1;

  int _epollFd = -1;

  bool _running = false;

  std::function<void(ClientConnection*)> _onConn;
  std::function<void(int, CloseReason)> _onDisconn;

  std::queue<Request> _reqQueue;

  std::map<int, ClientConnection*> _connections;

  void _epollLoop();

  void _onRequest(Request& req);
  void _defaultErrorHandler(uint8_t code, const std::string& message);

  std::function<void(uint8_t, const std::string&)> _onErr;

  std::mutex _reqQMutex;

 public:
  Server(int port, std::string privKey, int maxConnections = 1024,
         int maxFrameSize = 64 * 1024);

  ~Server();

  //   void route(const std::string& path,
  //              std::function<void(Request&, Responder&)> handler);

  //   void route(std::function<bool(const Request&)> matcher,
  //              std::function<void(Request&, Responder&)> handler);

  void listen();
  void stop();
};

}  // namespace fmxp
