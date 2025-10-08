
# Usage

## Example (ncnc_preprocessor/compile_preprocessor.py)

### Command
```
python compile_preprocessor.py <TARGET_DIRECTORY> --mode FREE
python compile_preprocessor.py <TARGET_DIRECTORY> --mode WARNING
python compile_preprocessor.py <TARGET_DIRECTORY> --mode ABORT
```

### Output
```
python compile_preprocessor.py src --mode FREE

[FREE] issues=9 (code=9, include_cycles=0)
```

```
python compile_preprocessor.py src --mode WARNING

[WARNING] Summary: total=9, code=9, include_cycles=0
== Issues ==
a.cpp:10:9: [RAW-DELETE] Avoid raw 'delete'/'delete[]' — prefer RAII (unique_ptr/shared_ptr) or custom deleter.
    delete owner_;          // RAW-DELETE: pretend A doesn't own it always
a.cpp:18:12: [NULL-DEREF] Pointer 'owner_' may be dereferenced without a preceding null-check in nearby scope.
    return owner_->value;       // NULL-DEREF
a.cpp:23:12: [NULL-DEREF] Pointer 'left' may be dereferenced without a preceding null-check in nearby scope.
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
a.cpp:23:26: [NULL-DEREF] Pointer 'right' may be dereferenced without a preceding null-check in nearby scope.
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
a.cpp:23:26: [PARAM-RAW-NOCHECK] Raw pointer parameter 'right' used via '->' without visible guard.
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
a.cpp:30:5: [NULL-DEREF] Pointer 'this' may be dereferenced without a preceding null-check in nearby scope.
    this->view_ = (Node*)&local;           // ADDR-ESCAPE
a.cpp:36:20: [ADDR-ESCAPE] Taking address of local 'local2' and storing globally — lifetime risk.
    g_slot.gptr = &local2;                 // ADDR-ESCAPE (global)
b.cpp:7:5: [NULL-DEREF] Pointer 't' may be dereferenced without a preceding null-check in nearby scope.
    t->x++;
b.cpp:8:12: [NULL-DEREF] Pointer 't' may be dereferenced without a preceding null-check in nearby scope.
    return t->x;
```

```
python compile_preprocessor.py src --mode ABORT

[ABORT] Summary: total=9, code=9, include_cycles=0
== Issues ==
a.cpp:10:9: [RAW-DELETE] Avoid raw 'delete'/'delete[]' — prefer RAII (unique_ptr/shared_ptr) or custom deleter.
    delete owner_;          // RAW-DELETE: pretend A doesn't own it always
a.cpp:18:12: [NULL-DEREF] Pointer 'owner_' may be dereferenced without a preceding null-check in nearby scope.
    return owner_->value;       // NULL-DEREF
a.cpp:23:12: [NULL-DEREF] Pointer 'left' may be dereferenced without a preceding null-check in nearby scope.
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
a.cpp:23:26: [NULL-DEREF] Pointer 'right' may be dereferenced without a preceding null-check in nearby scope.
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
a.cpp:23:26: [PARAM-RAW-NOCHECK] Raw pointer parameter 'right' used via '->' without visible guard.
    return left->value + right->value; // PARAM-RAW-NOCHECK + NULL-DEREF
a.cpp:30:5: [NULL-DEREF] Pointer 'this' may be dereferenced without a preceding null-check in nearby scope.
    this->view_ = (Node*)&local;           // ADDR-ESCAPE
a.cpp:36:20: [ADDR-ESCAPE] Taking address of local 'local2' and storing globally — lifetime risk.
    g_slot.gptr = &local2;                 // ADDR-ESCAPE (global)
b.cpp:7:5: [NULL-DEREF] Pointer 't' may be dereferenced without a preceding null-check in nearby scope.
    t->x++;
b.cpp:8:12: [NULL-DEREF] Pointer 't' may be dereferenced without a preceding null-check in nearby scope.
    return t->x;
```


