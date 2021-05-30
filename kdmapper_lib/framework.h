#pragma once
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <stdio.h>
#include <memory>
#include <array>
#include "histr.h"

static void trace(const char* fmt, ...) {
	static std::unique_ptr<std::array<char, 0x1000>> buf;

	if (!buf)
		buf = std::make_unique<std::array<char, 0x1000>>();

	va_list arg;
	va_start(arg, fmt);
	vsprintf(buf->data(), fmt, arg);
	va_end(arg);

	OutputDebugStringA(buf->data());
}

#ifdef _DEBUG
#	define TRACE trace
#else
#	define TRACE
#endif

#define HIDETXT(x) HISTR::nextA(HISTRA(x))