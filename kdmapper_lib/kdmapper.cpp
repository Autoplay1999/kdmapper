#include "kdmapper.hpp"
#include "framework.h"

uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, PBYTE driver_image)
{
	/*std::vector<uint8_t> raw_image = { 0 };

	if (!utils::ReadFileToMemory(driver_path, &raw_image))
	{
		TRACE("[-] Failed to read image to memory");
		return 0;
	}*/

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(driver_image);

	if (!nt_headers)
	{
		TRACE("[-] Invalid format of PE image");
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		TRACE("[-] Image is not 64 bit");
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
	
	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;

	uint64_t kernel_image_base = intel_driver::AllocatePool(iqvw64e_device_handle, nt::POOL_TYPE::NonPagedPool, image_size - TotalVirtualHeaderSize);

	do
	{
		if (!kernel_image_base)
		{
			TRACE("[-] Failed to allocate remote image in kernel");
			break;
		}

		std::cout << "[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl;

		// Copy image headers

		memcpy(local_image_base, driver_image, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
		
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(driver_image) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}
		
		uint64_t realBase = kernel_image_base;
		kernel_image_base -= TotalVirtualHeaderSize;

		TRACE("[+] Skipped 0x%08X bytes of PE Header", TotalVirtualHeaderSize);

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base)))
		{
			TRACE("[-] Failed to resolve imports");
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(iqvw64e_device_handle, realBase, (PVOID)((uintptr_t)local_image_base + TotalVirtualHeaderSize), image_size - TotalVirtualHeaderSize))
		{
			TRACE("[-] Failed to write local image to remote image");
			kernel_image_base = realBase;
			break;
		}

		// Call driver entry point

		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		std::cout << "[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl;

		NTSTATUS status = 0;

		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point))
		{
			TRACE("[-] Failed to call driver entry");
			kernel_image_base = realBase;
			break;
		}

		std::cout << "[+] DriverEntry returned 0x" << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << status << std::nouppercase << std::dec << std::endl;
		
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);

	
	VirtualFree(local_image_base, 0, MEM_RELEASE);

	intel_driver::FreePool(iqvw64e_device_handle, kernel_image_base);

	return 0;
}

void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				* reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports)
{
	for (const auto& current_import : imports)
	{
		if (!utils::GetKernelModuleAddress(current_import.module_name))
		{
			TRACE("[-] Dependency %s wasn't found", current_import.module_name);
			return false;
		}

		for (auto& current_function_data : current_import.function_datas)
		{
			const uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, utils::GetKernelModuleAddress(current_import.module_name), current_function_data.name);

			if (!function_address)
			{
				TRACE("[-] Failed to resolve import %s (%s)",current_function_data.name, current_import.module_name);
				return false;
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}