#pragma once

#include <string>

#include "../core/frame.hpp"

namespace fmxp {

class Request {
 private:
  std::string _path;
  ByteBuffer _data;

 public:
  Request(const std::string& path, const ByteBuffer& data);
  const std::string& path() const;
  const ByteBuffer& data() const;
  Frame toFrame() const;
};

class Response {
 private:
  std::string _path;
  ByteBuffer _data;
  uint8_t _status;
  uint32_t _id;  // 0 is a special id indicating that the response is not
                 // tied to any request (server-side push)

 public:
  Response(const Frame& frame);
  const std::string& path() const;
  const ByteBuffer& data() const;
  uint8_t status() const;
  uint32_t id() const;
  Frame toFrame() const;
};

}  // namespace fmxp