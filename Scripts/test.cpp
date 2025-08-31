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
