#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include "HookModule.h"
#include "FuncWrappers.h"
#include "imports.h"

#pragma comment(lib, "ntdll.lib")

///////////////////////////////////////////////
//          Macro Definitions               //
/////////////////////////////////////////////
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

int main(int argc, char* argv[]) {

	printf("[*] Program Started\n");
	IntializeHooks();

	WCHAR image_path[] = L"\\??\\C:\\Windows\\System32\\calc.exe";
	UNICODE_STRING NtImagePath;
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	HANDLE hProcess, hThread = NULL;

	BOOL success = FALSE;
	LPVOID remote_base_addr = NULL;
	CONTEXT thread_context = { 0 };

	// create the target process in a suspended state so we can modify its memory and the context of its main thread
	if (wrpNtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL,
		NULL, NULL, ProcessParameters, &CreateInfo, AttributeList))
	{
		printf("CreateProcessA() Failed with error: %d\n", GetLastError());
		return -1;
	}

	DestroyHooks();
	printf("[*] Program Ended\n");
	return 1;
}
