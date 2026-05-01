#include "encoders.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace fmxp {

std::string u8ToStr(uint8_t value) { return "" + static_cast<char>(value); }

uint8_t strToU8(const std::string& value) {
  return static_cast<uint8_t>(value[0]);
}

std::string u16ToStr(uint16_t v) {
  std::string s(2, '\0');
  s[0] = static_cast<char>((v >> 8) & 0xFF);
  s[1] = static_cast<char>(v & 0xFF);
  return s;
}

uint16_t strToU16(const std::string& s) {
  if (s.size() < 2) throw std::invalid_argument("input too short");
  return (static_cast<uint16_t>(static_cast<unsigned char>(s[0])) << 8) |
         static_cast<uint16_t>(static_cast<unsigned char>(s[1]));
}

std::string u32ToStr(uint32_t v) {
  std::string s(4, '\0');
  s[0] = static_cast<char>((v >> 24) & 0xFF);
  s[1] = static_cast<char>((v >> 16) & 0xFF);
  s[2] = static_cast<char>((v >> 8) & 0xFF);
  s[3] = static_cast<char>(v & 0xFF);
  return s;
}

uint32_t strToU32(const std::string& s) {
  if (s.size() < 4) throw std::invalid_argument("input too short");
  return (static_cast<uint32_t>(static_cast<unsigned char>(s[0])) << 24) |
         (static_cast<uint32_t>(static_cast<unsigned char>(s[1])) << 16) |
         (static_cast<uint32_t>(static_cast<unsigned char>(s[2])) << 8) |
         static_cast<uint32_t>(static_cast<unsigned char>(s[3]));
}

std::string u64ToStr(uint64_t v) {
  std::string s(8, '\0');
  for (int i = 0; i < 8; ++i)
    s[i] = static_cast<char>((v >> ((7 - i) * 8)) & 0xFF);
  return s;
}

uint64_t strToU64(const std::string& s) {
  if (s.size() < 8) throw std::invalid_argument("input too short");
  return (static_cast<uint64_t>(static_cast<unsigned char>(s[0])) << 56) |
         (static_cast<uint64_t>(static_cast<unsigned char>(s[1])) << 48) |
         (static_cast<uint64_t>(static_cast<unsigned char>(s[2])) << 40) |
         (static_cast<uint64_t>(static_cast<unsigned char>(s[3])) << 32) |
         (static_cast<uint64_t>(static_cast<unsigned char>(s[4])) << 24) |
         (static_cast<uint64_t>(static_cast<unsigned char>(s[5])) << 16) |
         (static_cast<uint64_t>(static_cast<unsigned char>(s[6])) << 8) |
         static_cast<uint64_t>(static_cast<unsigned char>(s[7]));
}

}  // namespace fmxp
