#include "order.h"

std::mutex gA;
std::mutex gB;

void path_A_then_B() {
    gA.lock();
    gB.lock();
    gB.unlock();
    gA.unlock();
}


void path_B_then_A() {
    gB.lock();
    gA.lock();
    gA.unlock();
    gB.unlock();
}