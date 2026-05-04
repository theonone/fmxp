#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace fmxp {

class ThreadPool {
 private:
  std::vector<std::thread> _workers;
  std::queue<std::function<void()>> _tasks;

  std::mutex _mutex;
  std::condition_variable _cv;
  bool _stop = false;

 public:
  ThreadPool(size_t threads);
  ~ThreadPool();

  void enqueue(std::function<void()> task);
};

}  // namespace fmxp
