#include <iostream>
#include "shared_queue.h"
#include "order.h"
#include "shared_flags.h"

// Compiles the project; running is optional.
int main() {
    SharedQueue q;
    q.push_unsafe(42); // don't run this in production—this is a static-analysis demo
    std::cout << "demo" << std::endl;
    return 0;
}