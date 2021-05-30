#pragma once
#include <Windows.h>
#include <vector>

#define HISTRA(x) "\0"##x
#define HISTRW(x) L"\0"##x
#define GET_HISTRA(x) HISTR::nextA(HISTRA(x))
#define GET_HISTRW(x) HISTR::nextW(HISTRW(x))

class HISTR {
private:
    static std::vector<PVOID>& WINAPI list() {
        static std::vector<PVOID> g_strlist;
        return g_strlist;
    }

public:
    __declspec(noinline) static LONG WINAPI add(LPCSTR str) {
        auto& strlist = list();
        auto id = (LONG)strlist.size();
        strlist.push_back(::EncodePointer((PVOID)str));
        return id;
    }
    __declspec(noinline) static LONG WINAPI add(LPCWSTR str) {
        auto& strlist = list();
        auto id = (LONG)strlist.size();
        strlist.push_back(::EncodePointer((PVOID)str));
        return id;
    }
    __declspec(noinline) static LPCSTR WINAPI getA(LONG id) {
        return nextA((LPCSTR)::DecodePointer(list()[id]));
    }
    __declspec(noinline) static LPCWSTR WINAPI getW(LONG id) {
        return nextW((LPCWSTR)::DecodePointer(list()[id]));
    }
    __declspec(noinline) static LPCSTR WINAPI nextA(LPCSTR str) {
        return ++str;
    }
    __declspec(noinline) static LPCWSTR WINAPI nextW(LPCWSTR str) {
        return ++str;
    }
};