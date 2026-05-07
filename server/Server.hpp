#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "../core/ConcurrentQueue.hpp"
#include "structures.hpp"
#include "tpool.hpp"

namespace fmxp {

struct ServerCommand {
  enum Type { SEND, CLOSE };
  Type type;
  uint64_t connID;
  std::optional<Frame> frame;
};

/*
@param respond respond to the request
@param close close the connection
*/
struct Responder {
  const std::function<void(const Response&)> respond;
  const std::function<void(uint64_t)> close;

  Responder(const std::function<void(const Response&)> respond,
            const std::function<void(uint64_t)> close)
      : respond(respond), close(close) {}
};

class Server {
 private:
  std::string _privKey;
  int _port;
  int _maxConnections;
  int _maxFrameSize;

  std::map<std::string, std::function<void(Request&, const Responder&)>>
      _routes;
  std::vector<std::pair<std::function<bool(const Request&)>,
                        std::function<void(Request&, const Responder&)>>>
      _funcRoutes;

  int _socket = -1;

  int _epollFd = -1;

  bool _running = false;

  ThreadPool _tpool;
  ConcurrentQueue<ServerCommand> _commandQueue;

  const Responder _responder;

  int _cmdEvFd;

  std::function<void(uint64_t)> _onConn;
  std::function<void(int, CloseReason)> _onDisconn;

  std::map<uint64_t, ClientConnection*> _connections;
  std::map<int, uint64_t> _fdToId;

  void _epollLoop();

  void _onRequest(Request req);
  void _defaultErrorHandler(uint8_t code, const std::string& message);

  std::function<void(uint8_t, const std::string&)> _onErr;

  void _router(Request req);

  void _handleCommand(const ServerCommand& cmd);

  void _wakeEpoll();

 public:
  Server(int port, std::string privKey, size_t workerThreads,
         int maxConnections = 1024, int maxFrameSize = 64 * 1024);

  ~Server();

  void route(const std::string& path,
             std::function<void(Request&, const Responder&)> handler);

  void route(std::function<bool(const Request&)> matcher,
             std::function<void(Request&, const Responder&)> handler);

  void sendResponse(const Response& resp);

  void closeConnection(uint64_t connectionID);

  void listen();
  void stop();

  /*
  Set a custom error handler. If the callback returns false, the default error
  handler will be called afterwards
  */
  void setOnError(std::function<bool(uint8_t, const std::string&)> cb);

  friend struct Responder;
};

}  // namespace fmxp
