#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace fmxp {
class ByteBuffer {
 private:
  uint8_t* _data = nullptr;
  size_t _size = 0;
  size_t _capacity = 0;

  void ensureCapacity(size_t newCap);

 public:
  ByteBuffer();
  ByteBuffer(const std::string& str);
  ByteBuffer(const char* data, size_t len);
  ByteBuffer(const unsigned char* data, size_t len);

  ByteBuffer(const ByteBuffer& other);
  ByteBuffer(ByteBuffer&& other) noexcept;

  ByteBuffer& operator=(const ByteBuffer& other);
  ByteBuffer& operator=(ByteBuffer&& other) noexcept;

  ~ByteBuffer();

  uint8_t* data();
  const uint8_t* cdata() const;

  size_t size() const;
  size_t capacity() const;

  void append(const uint8_t* data, size_t len);
  void append(const std::string& str);

  void clear();
  void reserve(size_t cap);

  ByteBuffer& operator+=(const ByteBuffer& other);
  ByteBuffer& operator+=(const std::string& str);

  ByteBuffer operator+(const ByteBuffer& other) const;
  ByteBuffer operator+(const std::string& str) const;

  uint8_t& operator[](size_t index);
  const uint8_t& operator[](size_t index) const;

  void resize(size_t len);

  /*
  Slices the ByteBuffer into a new ByteBuffer [start, end)
  */
  ByteBuffer slice(size_t start, size_t end) const;

  std::string toString() const;
};
}  // namespace fmxp