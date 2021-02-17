#pragma once
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <stdio.h>
#include <memory>
#include <array>

static void trace(const wchar_t* fmt, ...) {
	static std::unique_ptr<std::array<wchar_t, 0x1000>> buf;

	if (!buf)
		buf = std::make_unique<std::array<wchar_t, 0x1000>>();

	va_list arg;
	va_start(arg, fmt);
	vswprintf(buf->data(), fmt, arg);
	va_end(arg);

	OutputDebugStringW(buf->data());
}

#ifdef _DEBUG
#	define TRACE trace
#else
#	define TRACE
#endif