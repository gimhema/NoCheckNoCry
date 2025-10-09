#include <mutex>
static std::mutex mx;
void leak_lock() {        // LOCK-MISMATCH
    mx.lock();
    if (false) { mx.unlock(); }
}