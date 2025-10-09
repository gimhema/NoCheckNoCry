#include "order.h"

std::mutex gA;
std::mutex gB;

// ❌ Lock order: A -> B
void path_A_then_B() {
    gA.lock();
    gB.lock();
    gB.unlock();
    gA.unlock();
}

// ❌ Opposite lock order: B -> A  (conflicts with above)
void path_B_then_A() {
    gB.lock();
    gA.lock();
    gA.unlock();
    gB.unlock();
}