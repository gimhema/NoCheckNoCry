
# Usage

## Example

### Target File
```
test.cpp

struct SomeClass {
    void SomeAction() {}
};

int main() {
    SomeClass* someClassPtr; // 라인 5

    // null 체크 없음
    someClassPtr->SomeAction(); // 라인 8

    if (someClassPtr) {
        someClassPtr->SomeAction(); // 이건 안전
    }
}
```

### Command
```
python ncnc.py test.cpp

[경고] 'someClassPtr' 포인터가 라인 6에서 선언되었으나, NULL 체크 없이 라인 9에서 사용됨.
```
