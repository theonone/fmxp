#pragma once
#include "frame.hpp"

namespace fmxp {

struct IOFrame {
  Frame frame;
  uint64_t connectionID;
};

class Request {
 private:
  uint64_t _connID;
  std::string _path;
  ByteBuffer _data;
  uint32_t _id;

 public:
  Request(const IOFrame& ioFrame);
  uint64_t connectionID() const;
  const std::string& path() const;
  const ByteBuffer& data() const;
  uint32_t id() const;
  Frame toFrame() const;
};

class Response {
 private:
  uint64_t _connID;
  std::string _path;
  ByteBuffer _data;
  uint8_t _status;
  uint32_t _id;  // 0 is a special id indicating that the response is not
                 // tied to any request (server-side push)

 public:
  Response(const Request& request, const ByteBuffer& data,
           uint8_t status = STATUS_OK);
  Response(uint64_t connectionID, const std::string& path,
           const std::string& message, uint8_t status = STATUS_OK,
           uint32_t id = 0);
  uint64_t connectionID() const;
  const std::string& path() const;
  const ByteBuffer& data() const;
  uint8_t status() const;
  uint32_t id() const;
  Frame toFrame() const;
};
}  // namespace fmxp