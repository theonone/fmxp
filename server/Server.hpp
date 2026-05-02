// #pragma once

// #include <functional>
// #include <map>
// #include <string>
// #include <thread>
// #include <vector>

// namespace fmxp {

// class Request;
// class Responder;
// class Connection;
// struct Frame;

// class Server {
//  private:
//   std::string _privKey;
//   int _port;
//   int _maxConnections;
//   int _maxFrameSize;

//   int _socket = -1;

//   int _epollFd = -1;
//   std::thread _epollThread;

//   bool _running = false;

//   std::map<std::string, std::function<void(Request&, Responder&)>> _routes;

//   std::vector<std::function<bool(const Request&)>> _functionalRouters;

//   std::map<int, Connection*> _connections;

//   void* _workerQueue = nullptr;

//   void _epollLoop();
//   void _handleFrame(int fd, const Frame& frame);
//   void _sendResponse(Connection& conn, const Frame& frame);

//  public:
//   Server(int port, std::string privKey, int maxConnections = 1024,
//          int maxFrameSize = 64 * 1024);

//   ~Server();

//   void route(const std::string& path,
//              std::function<void(Request&, Responder&)> handler);

//   void route(std::function<bool(const Request&)> matcher,
//              std::function<void(Request&, Responder&)> handler);

//   void listen();
//   void stop();

//   std::function<void(Connection&)> onConnect;
//   std::function<void(Connection&)> onDisconnect;
//   std::function<void(std::string)> onError;
// };

// }  // namespace fmxp
