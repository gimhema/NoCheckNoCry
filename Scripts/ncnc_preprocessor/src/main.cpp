#include <iostream>
#include "a.h"
#include "b.h"
#include "util.h"

int main() {
    A a;

    // Trigger some behaviors (may crash if actually run — this is for static checker demo)
    // 1) Unchecked deref
    try {
        std::cout << "owner value = " << a.getOwnerValue() << "\n";
    } catch (...) {}

    // 2) PARAM-RAW-NOCHECK via sum
    A::Node *p = nullptr, *q = nullptr;
    try {
        std::cout << "sum = " << a.sum(p, q) << "\n";
    } catch (...) {}

    // 3) Address escape
    a.storeLocalAddress();
    a.leakLocalToGlobal();

    // 4) touch() inline in b.h
    Thing* t = nullptr;
    try {
        touch(t);
    } catch (...) {}

    std::cout << "Done demo.\n";
    return 0;
}