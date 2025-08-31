#pragma once

class SomeptrClass
{
public:
    void DoWork();
};

class Someclass
{
public:
    // 멤버 포인터 (프로젝트 전역에서 사용됨)
    SomeptrClass* m_ptr;
};
