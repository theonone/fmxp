#include "iostructs.hpp"

namespace fmxp {

Request::Request(const IOFrame& ioFrame)
    : _connID(ioFrame.connectionID),
      _path(ioFrame.frame.path),
      _data(ioFrame.frame.data),
      _id(ioFrame.frame.id) {}

uint64_t Request::connectionID() const { return _connID; }

const std::string& Request::path() const { return _path; }

const ByteBuffer& Request::data() const { return _data; }

uint32_t Request::id() const { return _id; }

Frame Request::toFrame() const {
  return makeFrame(_id, STATUS_REQ, 0, _path, _data);
}

Response::Response(const Request& request, const ByteBuffer& data,
                   uint8_t status)
    : _connID(request.connectionID()),
      _path(request.path()),
      _data(data),
      _status(status),
      _id(request.id()) {}

Response::Response(uint64_t connectionID, const std::string& path,
                   const std::string& message, uint8_t status, uint32_t id)
    : _connID(connectionID), _path(path), _status(status), _id(id) {}

uint64_t Response::connectionID() const { return _connID; }

const std::string& Response::path() const { return _path; }

const ByteBuffer& Response::data() const { return _data; }

uint8_t Response::status() const { return _status; }

uint32_t Response::id() const { return _id; }
Frame Response::toFrame() const {
  return {
      .id = _id,
      .status = _status,
      .path = _path,
      .data = _data,
  };
}
}  // namespace fmxp