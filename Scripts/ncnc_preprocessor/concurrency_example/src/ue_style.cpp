#include "ue_compat.h"
#include "shared_queue.h"


void unreal_style_example(SharedQueue& q) {
    FScopeLock lk(&q.m);
    q.buf.push_back(1);  // guarded access OK while lock held
}