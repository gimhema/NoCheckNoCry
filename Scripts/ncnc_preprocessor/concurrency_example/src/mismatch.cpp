#include <mutex>
static std::mutex mx;

void leak_lock() {
    mx.lock();
    // forgot mx.unlock();
    if (false) { mx.unlock(); } // keep code compiling, but mismatch remains
}