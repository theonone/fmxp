#pragma once

#include <mutex>
#include <queue>

namespace fmxp {

template <typename T>
class ConcurrentQueue {
 private:
  std::queue<T> _queue;
  std::mutex _mutex;

 public:
  void push(const T& value) {
    std::lock_guard lock(_mutex);
    _queue.push(std::move(value));
  }

  bool tryPop(T& out) {
    std::lock_guard lock(_mutex);
    if (_queue.empty()) return false;

    out = std::move(_queue.front());
    _queue.pop();
    return true;
  }
};

}  // namespace fmxp
