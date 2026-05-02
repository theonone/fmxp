#include "ByteBuffer.hpp"

#include <cstring>
#include <stdexcept>
#include <utility>
namespace fmxp {

void ByteBuffer::ensureCapacity(size_t newCap) {
  if (newCap <= _capacity) return;

  size_t newCapacity = _capacity ? _capacity * 2 : 64;
  while (newCapacity < newCap) {
    newCapacity *= 2;
  }

  uint8_t* newData = new uint8_t[newCapacity];

  if (_data) {
    std::memcpy(newData, _data, _size);
    delete[] _data;
  }

  _data = newData;
  _capacity = newCapacity;
}

ByteBuffer::ByteBuffer() : _data(nullptr), _size(0), _capacity(0) {}

ByteBuffer::ByteBuffer(const std::string& str)
    : _data(nullptr), _size(0), _capacity(0) {
  append(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

ByteBuffer::ByteBuffer(const char* data, size_t len)
    : _data(nullptr), _size(0), _capacity(0) {
  append(reinterpret_cast<const uint8_t*>(data), len);
}

ByteBuffer::ByteBuffer(const unsigned char* data, size_t len) {
  append(reinterpret_cast<const uint8_t*>(data), len);
}

ByteBuffer::ByteBuffer(const ByteBuffer& other)
    : _data(nullptr), _size(0), _capacity(0) {
  append(other._data, other._size);
}

ByteBuffer::ByteBuffer(ByteBuffer&& other) noexcept
    : _data(other._data), _size(other._size), _capacity(other._capacity) {
  other._data = nullptr;
  other._size = 0;
  other._capacity = 0;
}

ByteBuffer& ByteBuffer::operator=(const ByteBuffer& other) {
  if (this == &other) return *this;

  clear();
  append(other._data, other._size);
  return *this;
}

ByteBuffer& ByteBuffer::operator=(ByteBuffer&& other) noexcept {
  if (this == &other) return *this;

  delete[] _data;

  _data = other._data;
  _size = other._size;
  _capacity = other._capacity;

  other._data = nullptr;
  other._size = 0;
  other._capacity = 0;

  return *this;
}

ByteBuffer::~ByteBuffer() { delete[] _data; }

uint8_t* ByteBuffer::data() { return _data; }

const uint8_t* ByteBuffer::cdata() const { return _data; }

size_t ByteBuffer::size() const { return _size; }

size_t ByteBuffer::capacity() const { return _capacity; }

void ByteBuffer::append(const uint8_t* data, size_t len) {
  if (len == 0) return;

  ensureCapacity(_size + len);
  std::memcpy(_data + _size, data, len);
  _size += len;
}

void ByteBuffer::append(const std::string& str) {
  append(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

void ByteBuffer::clear() { _size = 0; }

void ByteBuffer::reserve(size_t cap) { ensureCapacity(cap); }

ByteBuffer& ByteBuffer::operator+=(const ByteBuffer& other) {
  append(other._data, other._size);
  return *this;
}

ByteBuffer& ByteBuffer::operator+=(const std::string& str) {
  append(str);
  return *this;
}

ByteBuffer ByteBuffer::operator+(const ByteBuffer& other) const {
  ByteBuffer result(*this);
  result += other;
  return result;
}

ByteBuffer ByteBuffer::operator+(const std::string& str) const {
  ByteBuffer result(*this);
  result += str;
  return result;
}

uint8_t& ByteBuffer::operator[](size_t index) {
  if (index >= _size) throw std::out_of_range("Index out of range");
  return _data[index];
}

const uint8_t& ByteBuffer::operator[](size_t index) const {
  if (index >= _size) throw std::out_of_range("Index out of range");
  return _data[index];
}
void ByteBuffer::resize(size_t len) {
  ensureCapacity(len);
  _size = len;
}

ByteBuffer ByteBuffer::slice(size_t start, size_t end) const {
  if (end > _size || start >= end)
    throw std::out_of_range("Invalid slice range");
  return ByteBuffer(_data + start, end - start);
}

std::string ByteBuffer::toString() const {
  return std::string(reinterpret_cast<const char*>(_data), _size);
}
}  // namespace fmxp
