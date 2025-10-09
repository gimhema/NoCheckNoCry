#include <mutex>
#include <thread>
#include <chrono>
static std::mutex M;

// LONG-CRITICAL-LOOP: infinite loop while holding the mutex
void hold_forever_loop() {
    std::lock_guard<std::mutex> lk(M);
    while (true) {
        // busy work
    }
}

// LONG-CRITICAL-BLOCK: blocking call while holding the mutex
void hold_and_sleep() {
    std::lock_guard<std::mutex> lk(M);
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

// LONG-CRITICAL-BUDGET: large region under lock (> 60 lines)
void big_region() {
    std::unique_lock<std::mutex> lk(M);
    // lots of lines...
    int x=0;
    // 65 dummy lines to exceed budget
    x++;x++;x++;x++;x++;x++;x++;x++;x++;x++;
    x++;x++;x++;x++;x++;x++;x++;x++;x++;x++;
    x++;x++;x++;x++;x++;x++;x++;x++;x++;x++;
    x++;x++;x++;x++;x++;x++;x++;x++;x++;x++;
    x++;x++;x++;x++;x++;x++;x++;x++;x++;x++;
    x++;x++;x++;x++;x++;x++;x++;x++;x++;x++;
    x++;x++;x++;x++;x++;
    (void)x;
}