#include "b.h"

// Add something trivial so file exists
int bump(Thing* t) {
    // Still risky, on purpose
    t->x++;
    return t->x;
}