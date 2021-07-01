#pragma once
#ifndef _KDMAPPER_EXPORTS
#	ifdef _WIN64
#		ifdef _DEBUG
#			pragma comment(lib, "kdmapper64d.lib")
#		else
#			pragma comment(lib, "kdmapper64.lib")
#		endif
#	else
#		ifdef _DEBUG
#			pragma comment(lib, "kdmapper32d.lib")
#		else
#			pragma comment(lib, "kdmapper32.lib")
#		endif
#	endif
#endif

#include <Windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"

namespace kdmapper
{
	uint64_t MapDriver(HANDLE iqvw64e_device_handle, PBYTE driver_image);
	void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
}