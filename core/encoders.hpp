#pragma once

#include <cstdint>
#include <string>

namespace fmxp {

/* coverts uint8_t value into a 1 character string */
std::string u8ToStr(uint8_t value);
uint8_t strToU8(const std::string& value);

/* coverts uint16_t value into a 2 character string */
std::string u16ToStr(uint16_t value);
uint16_t strToU16(const std::string& value);

/* coverts uint32_t value into a 4 character string */
std::string u32ToStr(uint32_t value);
uint32_t strToU32(const std::string& value);

/* coverts uint64_t value into a 8 character string */
std::string u64ToStr(uint64_t value);
uint64_t strToU64(const std::string& value);

uint16_t ptrToU16(const uint8_t* p);

uint32_t ptrToU32(const uint8_t* p);

uint64_t ptrToU64(const uint8_t* p);
}  // namespace fmxp