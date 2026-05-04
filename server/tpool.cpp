#include "tpool.hpp"

namespace fmxp {

ThreadPool::ThreadPool(size_t threads) {
  for (size_t i = 0; i < threads; i++) {
    _workers.emplace_back([this]() {
      while (true) {
        std::function<void()> task;

        {
          std::unique_lock lock(_mutex);

          _cv.wait(lock, [this]() { return _stop || !_tasks.empty(); });

          if (_stop && _tasks.empty()) return;

          task = std::move(_tasks.front());
          _tasks.pop();
        }

        task();
      }
    });
  }
}

ThreadPool::~ThreadPool() {
  {
    std::unique_lock lock(_mutex);
    _stop = true;
  }

  _cv.notify_all();

  for (auto& t : _workers) {
    if (t.joinable()) t.join();
  }
}

void ThreadPool::enqueue(std::function<void()> task) {
  {
    std::unique_lock lock(_mutex);
    _tasks.push(std::move(task));
  }
  _cv.notify_one();
}

}  // namespace fmxp
