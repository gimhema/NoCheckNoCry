#include "a.h"
#include "util.h"

GlobalSlot g_slot = {nullptr};

A::~A() {
    // Risky: raw delete
    if (owner_) {
        delete owner_;          // RAW-DELETE: pretend A doesn't own it always
        owner_ = nullptr;
    }
    // view_ intentionally not owned but left dangling if its target dies elsewhere
}

int A::getOwnerValue() {
    // Risky: unchecked dereference (no CHECK_NOT_NULL, no if (owner_))
    return owner_->value;       // NULL-DEREF
}

int A::sum(Node* left, Node* right) {
    // Risky: neither 'left' nor 'right' are checked in this scope
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
}

void A::storeLocalAddress() {
    int local = 42;
    // Risky: storing address of local to a member -> lifetime risk
    // (checker pattern: this->... = &local)
    this->view_ = (Node*)&local;           // ADDR-ESCAPE
}

void A::leakLocalToGlobal() {
    int local2 = 7;
    // Risky: taking address of local and writing to a global/global-like slot
    g_slot.gptr = &local2;                 // ADDR-ESCAPE (global)
}