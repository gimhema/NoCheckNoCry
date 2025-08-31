#include "Someclass.h"
#include <iostream>

int main()
{
    Someclass* someClassPtr;   // 선언됨 (초기화 안 됨, 위험)

    // NULL 체크 없음 → 경고 대상
    someClassPtr->m_ptr->DoWork();

    // 이건 안전: NULL 체크 후 사용
    if (someClassPtr)
    {
        if (someClassPtr->m_ptr)
        {
            someClassPtr->m_ptr->DoWork();
        }
    }

    return 0;
}
