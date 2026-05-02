#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

const uint8_t ERR_OTHER = 0;
const uint8_t ERR_INVALID_FRAME = 1;
const uint8_t ERR_FRAME_TOO_LONG = 2;
const uint8_t ERR_ENCRYPTION = 3;
const uint8_t ERR_SEND_FAILED = 4;

class FMXPException : public std::exception {
 public:
  FMXPException(uint8_t code, const std::string& msg = "");
  const char* what() const noexcept override;
  const uint8_t& code() const noexcept;

 private:
  std::string _msg = "";
  uint8_t _code = ERR_OTHER;
};

void throwErr(uint8_t code, const std::string& msg = "");