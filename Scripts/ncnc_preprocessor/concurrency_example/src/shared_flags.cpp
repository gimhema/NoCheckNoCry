#include "shared_flags.h"

bool stop_flag = false;             // @shared
volatile bool vstop = false;        // @shared
std::atomic<bool> proper{false};    // @shared
bool documented = false;            // @shared //@atomic_ok