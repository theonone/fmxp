#include "errors.hpp"

FMXPException::FMXPException(uint8_t code, const std::string& msg)
    : _code(code), _msg(msg) {}

const uint8_t& FMXPException::code() const noexcept { return _code; }

const char* FMXPException::what() const noexcept { return _msg.c_str(); }

void throwErr(uint8_t code, const std::string& msg) {
  throw std::runtime_error("(" + std::to_string(code) + ") " + msg);
}