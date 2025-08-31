#include "Someclass.h"

void SafeFunc(Someclass* obj)
{
    // 안전한 패턴 1: nullptr 확인 후 return
    if (!obj) return;
    obj->m_ptr->DoWork();  // 여긴 안전으로 간주됨

    // 안전한 패턴 2: guard macro 흉내 (CHECK)
    CHECK(obj);
    obj->m_ptr->DoWork();

    // 안전한 패턴 3: if 조건식에서 && 사용
    if (obj && obj->m_ptr)
    {
        obj->m_ptr->DoWork();
    }
}
