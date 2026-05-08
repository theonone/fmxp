#include "structures.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "../core/enc/aes.hpp"
#include "../core/enc/rsa.hpp"
#include "../core/encoders.hpp"
#include "../core/errors.hpp"

namespace fmxp {

Request::Request(const std::string& path, const ByteBuffer& data)
    : _path(path), _data(data) {}

const std::string& Request::path() const { return _path; }

const ByteBuffer& Request::data() const { return _data; }

// Frame Request::toFrame() const { return makeRequestFrame(_path, _data, 0); }

Response::Response(const Frame& frame)
    : _path(frame.path), _data(frame.data), _status(frame.status) {}

const std::string& Response::path() const { return _path; }

const ByteBuffer& Response::data() const { return _data; }

uint8_t Response::status() const { return _status; }

// uint32_t Response::id() const { return _id; }
// Frame Response::toFrame() const {
//   return makeResponseFrame(_status, _path, _data, 0, _id);
// }
}  // namespace fmxp