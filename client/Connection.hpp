#pragma once
#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../core/ConcurrentQueue.hpp"
#include "../core/frame.hpp"
#include "structures.hpp"

namespace fmxp {

struct ClientCommand {
  enum Type { SEND, CLOSE };
  Type type;
  std::optional<Frame> frame;
};

enum ConnectionState { HANDSHAKE, CONNECTED, CLOSED };

class Connection {
 private:
  std::string _host;
  int _port;
  std::string _pubKey;
  ByteBuffer _aesKey;

  ConnectionState _state = ConnectionState::HANDSHAKE;

  bool _handshakeSent = false;

  int _socket = -1;
  int _epollFd = -1;
  int _cmdEvFd = -1;
  uint64_t _maxFrameSize;

  std::atomic<bool> _running = false;
  std::thread _epollThread;

  ConcurrentQueue<ClientCommand> _commandQueue;

  ByteBuffer _frameBuffer;

  std::function<void(const Response&)> _onResponse;
  std::function<void()> _onClose;

  void _epollLoop();
  void _handleCommand(const ClientCommand& cmd);
  void _connect();

  std::vector<Frame> _parseFrames();

  void _doHandshake();

 public:
  Connection(const std::string& host, int port, const std::string& pubKey,
             uint64_t maxFrameSize,
             std::function<void(const Response&)> onResponse);
  ~Connection();

  void setOnResponse(std::function<void(const Response&)> cb);
  //   void setOnClose(std::function<void(uint8_t)> cb);

  void send(const Request& req);
  void close();
};

}  // namespace fmxp
