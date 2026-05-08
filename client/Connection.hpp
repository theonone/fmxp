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
  uint32_t _fid = 0;
  uint32_t _rid = 0;
  uint64_t _ssid = 0;
  uint32_t _lastSrvFid = 0;

  ConnectionState _state = ConnectionState::HANDSHAKE;

  bool _handshakeSent = false;

  int _socket = -1;
  int _epollFd = -1;
  int _cmdEvFd = -1;
  uint32_t _maxFrameSize;

  std::atomic<bool> _running = false;
  std::thread _epollThread;

  ConcurrentQueue<ClientCommand> _commandQueue;

  ByteBuffer _frameBuffer;

  std::function<void(const Response&)> _onResponse;
  std::function<void()> _onClose;

  void _epollLoop();
  void _handleCommand(ClientCommand& cmd);
  void _connect();

  std::vector<Frame> _parseFrames();

  void _doHandshake();

  Frame _makeReqFrame(const std::string& path, const ByteBuffer& data,
                      uint8_t flags);

  bool _validateFrame(const Frame& frame);

 public:
  Connection(const std::string& host, int port, const std::string& pubKey,
             uint32_t maxFrameSize,
             std::function<void(const Response&)> onResponse);
  ~Connection();

  void setOnResponse(std::function<void(const Response&)> cb);
  void setOnClose(std::function<void()> cb);

  /*
   * Send a request, returns false if connection is closed
   */
  bool send(const Request& req);
  void close();
};

}  // namespace fmxp
