
#pragma once
#include <Windows.h>
#include <stdio.h>
#include "FuncWrappers.h"
#include "HookModule.h"
#include "imports.h"

FARPROC RetrieveSyscallAddress(const char* FuncName) {
    return GetProcAddress(GetModuleHandleA("ntdll.dll"), FuncName);
}

///////////////////////////////////////////////
//          Function Prototypes	            //
/////////////////////////////////////////////

typedef NTSTATUS(NTAPI* orgNtCreateProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* orgNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI* orgNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* orgNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS(NTAPI* orgNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* orgNtSuspendProcess)(HANDLE);
typedef NTSTATUS(NTAPI* orgNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* orgNtResumeProcess)(HANDLE);
typedef NTSTATUS(NTAPI* orgNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* orgNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* orgNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* orgNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* orgNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* orgNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* orgNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* orgNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* orgNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS(NTAPI* orgNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI* orgNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* orgNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* orgNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* orgNtMapViewOfSection)(HANDLE, HANDLE, PVOID, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(NTAPI* orgNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* orgNtAdjustPrivilegesToken)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG);
typedef NTSTATUS(NTAPI* orgNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* orgNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* orgNtWaitForMultipleObjects)(ULONG, PHANDLE, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* orgNtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI* orgNtAlertResumeThread)(HANDLE, PULONG);

ULONG wrpNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
    orgNtCreateProcess pNtCreateProcess = (orgNtCreateProcess)RetrieveSyscallAddress("NtCreateProcess");
    if (pNtCreateProcess == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtCreateProcess\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtCreateProcess\n");
    int ssn = GetSsnByName((PCHAR)"NtCreateProcess");
    SetHwBp((ULONG_PTR)pNtCreateProcess, TRUE, ssn);
    return pNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}

ULONG wrpNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    orgNtCreateThreadEx pNtCreateThreadEx = (orgNtCreateThreadEx)RetrieveSyscallAddress("NtCreateThreadEx");
    if (pNtCreateThreadEx == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtCreateThreadEx\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtCreateThreadEx\n");
    int ssn = GetSsnByName((PCHAR)"NtCreateThreadEx");
    SetHwBp((ULONG_PTR)pNtCreateThreadEx, TRUE, ssn);
    return pNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

ULONG wrpNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    orgNtOpenProcess pNtOpenProcess = (orgNtOpenProcess)RetrieveSyscallAddress("NtOpenProcess");
    if (pNtOpenProcess == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtOpenProcess\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtOpenProcess\n");
    int ssn = GetSsnByName((PCHAR)"NtOpenProcess");
    SetHwBp((ULONG_PTR)pNtOpenProcess, TRUE, ssn);
    return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

ULONG wrpNtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle) {
    orgNtOpenProcessToken pNtOpenProcessToken = (orgNtOpenProcessToken)RetrieveSyscallAddress("NtOpenProcessToken");
    if (pNtOpenProcessToken == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtOpenProcessToken\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtOpenProcessToken\n");
    int ssn = GetSsnByName((PCHAR)"NtOpenProcessToken");
    SetHwBp((ULONG_PTR)pNtOpenProcessToken, TRUE, ssn);
    return pNtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

ULONG wrpNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    orgNtOpenThread pNtOpenThread = (orgNtOpenThread)RetrieveSyscallAddress("NtOpenThread");
    if (pNtOpenThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtOpenThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtOpenThread\n");
    int ssn = GetSsnByName((PCHAR)"NtOpenThread");
    SetHwBp((ULONG_PTR)pNtOpenThread, TRUE, ssn);
    return pNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

ULONG wrpNtSuspendProcess(HANDLE ProcessHandle) {
    orgNtSuspendProcess pNtSuspendProcess = (orgNtSuspendProcess)RetrieveSyscallAddress("NtSuspendProcess");
    if (pNtSuspendProcess == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtSuspendProcess\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtSuspendProcess\n");
    int ssn = GetSsnByName((PCHAR)"NtSuspendProcess");
    SetHwBp((ULONG_PTR)pNtSuspendProcess, TRUE, ssn);
    return pNtSuspendProcess(ProcessHandle);
}

ULONG wrpNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    orgNtSuspendThread pNtSuspendThread = (orgNtSuspendThread)RetrieveSyscallAddress("NtSuspendThread");
    if (pNtSuspendThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtSuspendThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtSuspendThread\n");
    int ssn = GetSsnByName((PCHAR)"NtSuspendThread");
    SetHwBp((ULONG_PTR)pNtSuspendThread, TRUE, ssn);
    return pNtSuspendThread(ThreadHandle, PreviousSuspendCount);
}

ULONG wrpNtResumeProcess(HANDLE ProcessHandle) {
    orgNtResumeProcess pNtResumeProcess = (orgNtResumeProcess)RetrieveSyscallAddress("NtResumeProcess");
    if (pNtResumeProcess == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtResumeProcess\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtResumeProcess\n");
    int ssn = GetSsnByName((PCHAR)"NtResumeProcess");
    SetHwBp((ULONG_PTR)pNtResumeProcess, TRUE, ssn);
    return pNtResumeProcess(ProcessHandle);
}

ULONG wrpNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    orgNtResumeThread pNtResumeThread = (orgNtResumeThread)RetrieveSyscallAddress("NtResumeThread");
    if (pNtResumeThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtResumeThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtResumeThread\n");
    int ssn = GetSsnByName((PCHAR)"NtResumeThread");
    SetHwBp((ULONG_PTR)pNtResumeThread, TRUE, ssn);
    return pNtResumeThread(ThreadHandle, PreviousSuspendCount);
}

ULONG wrpNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    orgNtGetContextThread pNtGetContextThread = (orgNtGetContextThread)RetrieveSyscallAddress("NtGetContextThread");
    if (pNtGetContextThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtGetContextThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtGetContextThread\n");
    int ssn = GetSsnByName((PCHAR)"NtGetContextThread");
    SetHwBp((ULONG_PTR)pNtGetContextThread, TRUE, ssn);
    return pNtGetContextThread(ThreadHandle, ThreadContext);
}

ULONG wrpNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    orgNtSetContextThread pNtSetContextThread = (orgNtSetContextThread)RetrieveSyscallAddress("NtSetContextThread");
    if (pNtSetContextThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtSetContextThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtSetContextThread\n");
    int ssn = GetSsnByName((PCHAR)"NtSetContextThread");
    SetHwBp((ULONG_PTR)pNtSetContextThread, TRUE, ssn);
    return pNtSetContextThread(ThreadHandle, Context);
}

ULONG wrpNtClose(HANDLE Handle) {
    orgNtClose pNtClose = (orgNtClose)RetrieveSyscallAddress("NtClose");
    if (pNtClose == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtClose\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtClose\n");
    int ssn = GetSsnByName((PCHAR)"NtClose");
    SetHwBp((ULONG_PTR)pNtClose, TRUE, ssn);
    return pNtClose(Handle);
}

ULONG wrpNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    orgNtReadVirtualMemory pNtReadVirtualMemory = (orgNtReadVirtualMemory)RetrieveSyscallAddress("NtReadVirtualMemory");
    if (pNtReadVirtualMemory == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtReadVirtualMemory\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtReadVirtualMemory\n");
    int ssn = GetSsnByName((PCHAR)"NtReadVirtualMemory");
    SetHwBp((ULONG_PTR)pNtReadVirtualMemory, TRUE, ssn);
    return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

ULONG wrpNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    orgNtWriteVirtualMemory pNtWriteVirtualMemory = (orgNtWriteVirtualMemory)RetrieveSyscallAddress("NtWriteVirtualMemory");
    if (pNtWriteVirtualMemory == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtWriteVirtualMemory\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtWriteVirtualMemory\n");
    int ssn = GetSsnByName((PCHAR)"NtWriteVirtualMemory");
    SetHwBp((ULONG_PTR)pNtWriteVirtualMemory, TRUE, ssn);
    return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

ULONG wrpNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    orgNtAllocateVirtualMemory pNtAllocateVirtualMemory = (orgNtAllocateVirtualMemory)RetrieveSyscallAddress("NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtAllocateVirtualMemory\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtAllocateVirtualMemory\n");
    int ssn = GetSsnByName((PCHAR)"NtAllocateVirtualMemory");
    SetHwBp((ULONG_PTR)pNtAllocateVirtualMemory, TRUE, ssn);
    return pNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

ULONG wrpNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    orgNtProtectVirtualMemory pNtProtectVirtualMemory = (orgNtProtectVirtualMemory)RetrieveSyscallAddress("NtProtectVirtualMemory");
    if (pNtProtectVirtualMemory == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtProtectVirtualMemory\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtProtectVirtualMemory\n");
    int ssn = GetSsnByName((PCHAR)"NtProtectVirtualMemory");
    SetHwBp((ULONG_PTR)pNtProtectVirtualMemory, TRUE, ssn);
    return pNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

ULONG wrpNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    orgNtFreeVirtualMemory pNtFreeVirtualMemory = (orgNtFreeVirtualMemory)RetrieveSyscallAddress("NtFreeVirtualMemory");
    if (pNtFreeVirtualMemory == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtFreeVirtualMemory\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtFreeVirtualMemory\n");
    int ssn = GetSsnByName((PCHAR)"NtFreeVirtualMemory");
    SetHwBp((ULONG_PTR)pNtFreeVirtualMemory, TRUE, ssn);
    return pNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

ULONG wrpNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    orgNtQuerySystemInformation pNtQuerySystemInformation = (orgNtQuerySystemInformation)RetrieveSyscallAddress("NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtQuerySystemInformation\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtQuerySystemInformation\n");
    int ssn = GetSsnByName((PCHAR)"NtQuerySystemInformation");
    SetHwBp((ULONG_PTR)pNtQuerySystemInformation, TRUE, ssn);
    return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

ULONG wrpNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    orgNtQueryDirectoryFile pNtQueryDirectoryFile = (orgNtQueryDirectoryFile)RetrieveSyscallAddress("NtQueryDirectoryFile");
    if (pNtQueryDirectoryFile == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtQueryDirectoryFile\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtQueryDirectoryFile\n");
    int ssn = GetSsnByName((PCHAR)"NtQueryDirectoryFile");
    SetHwBp((ULONG_PTR)pNtQueryDirectoryFile, TRUE, ssn);
    return pNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}

ULONG wrpNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    orgNtQueryInformationFile pNtQueryInformationFile = (orgNtQueryInformationFile)RetrieveSyscallAddress("NtQueryInformationFile");
    if (pNtQueryInformationFile == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtQueryInformationFile\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtQueryInformationFile\n");
    int ssn = GetSsnByName((PCHAR)"NtQueryInformationFile");
    SetHwBp((ULONG_PTR)pNtQueryInformationFile, TRUE, ssn);
    return pNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

ULONG wrpNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    orgNtQueryInformationProcess pNtQueryInformationProcess = (orgNtQueryInformationProcess)RetrieveSyscallAddress("NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtQueryInformationProcess\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtQueryInformationProcess\n");
    int ssn = GetSsnByName((PCHAR)"NtQueryInformationProcess");
    SetHwBp((ULONG_PTR)pNtQueryInformationProcess, TRUE, ssn);
    return pNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

ULONG wrpNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
    orgNtQueryInformationThread pNtQueryInformationThread = (orgNtQueryInformationThread)RetrieveSyscallAddress("NtQueryInformationThread");
    if (pNtQueryInformationThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtQueryInformationThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtQueryInformationThread\n");
    int ssn = GetSsnByName((PCHAR)"NtQueryInformationThread");
    SetHwBp((ULONG_PTR)pNtQueryInformationThread, TRUE, ssn);
    return pNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

ULONG wrpNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    orgNtCreateSection pNtCreateSection = (orgNtCreateSection)RetrieveSyscallAddress("NtCreateSection");
    if (pNtCreateSection == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtCreateSection\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtCreateSection\n");
    int ssn = GetSsnByName((PCHAR)"NtCreateSection");
    SetHwBp((ULONG_PTR)pNtCreateSection, TRUE, ssn);
    return pNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

ULONG wrpNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    orgNtOpenSection pNtOpenSection = (orgNtOpenSection)RetrieveSyscallAddress("NtOpenSection");
    if (pNtOpenSection == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtOpenSection\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtOpenSection\n");
    int ssn = GetSsnByName((PCHAR)"NtOpenSection");
    SetHwBp((ULONG_PTR)pNtOpenSection, TRUE, ssn);
    return pNtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}

ULONG wrpNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    orgNtMapViewOfSection pNtMapViewOfSection = (orgNtMapViewOfSection)RetrieveSyscallAddress("NtMapViewOfSection");
    if (pNtMapViewOfSection == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtMapViewOfSection\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtMapViewOfSection\n");
    int ssn = GetSsnByName((PCHAR)"NtMapViewOfSection");
    SetHwBp((ULONG_PTR)pNtMapViewOfSection, TRUE, ssn);
    return pNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

ULONG wrpNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    orgNtUnmapViewOfSection pNtUnmapViewOfSection = (orgNtUnmapViewOfSection)RetrieveSyscallAddress("NtUnmapViewOfSection");
    if (pNtUnmapViewOfSection == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtUnmapViewOfSection\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtUnmapViewOfSection\n");
    int ssn = GetSsnByName((PCHAR)"NtUnmapViewOfSection");
    SetHwBp((ULONG_PTR)pNtUnmapViewOfSection, TRUE, ssn);
    return pNtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

ULONG wrpNtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength) {
    orgNtAdjustPrivilegesToken pNtAdjustPrivilegesToken = (orgNtAdjustPrivilegesToken)RetrieveSyscallAddress("NtAdjustPrivilegesToken");
    if (pNtAdjustPrivilegesToken == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtAdjustPrivilegesToken\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtAdjustPrivilegesToken\n");
    int ssn = GetSsnByName((PCHAR)"NtAdjustPrivilegesToken");
    SetHwBp((ULONG_PTR)pNtAdjustPrivilegesToken, TRUE, ssn);
    return pNtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}

ULONG wrpNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    orgNtDeviceIoControlFile pNtDeviceIoControlFile = (orgNtDeviceIoControlFile)RetrieveSyscallAddress("NtDeviceIoControlFile");
    if (pNtDeviceIoControlFile == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtDeviceIoControlFile\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtDeviceIoControlFile\n");
    int ssn = GetSsnByName((PCHAR)"NtDeviceIoControlFile");
    SetHwBp((ULONG_PTR)pNtDeviceIoControlFile, TRUE, ssn);
    return pNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

ULONG wrpNtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    orgNtQueueApcThread pNtQueueApcThread = (orgNtQueueApcThread)RetrieveSyscallAddress("NtQueueApcThread");
    if (pNtQueueApcThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtQueueApcThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtQueueApcThread\n");
    int ssn = GetSsnByName((PCHAR)"NtQueueApcThread");
    SetHwBp((ULONG_PTR)pNtQueueApcThread, TRUE, ssn);
    return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

ULONG wrpNtWaitForMultipleObjects(ULONG Count, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    orgNtWaitForMultipleObjects pNtWaitForMultipleObjects = (orgNtWaitForMultipleObjects)RetrieveSyscallAddress("NtWaitForMultipleObjects");
    if (pNtWaitForMultipleObjects == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtWaitForMultipleObjects\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtWaitForMultipleObjects\n");
    int ssn = GetSsnByName((PCHAR)"NtWaitForMultipleObjects");
    SetHwBp((ULONG_PTR)pNtWaitForMultipleObjects, TRUE, ssn);
    return pNtWaitForMultipleObjects(Count, Handles, WaitType, Alertable, Timeout);
}

ULONG wrpNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {
    orgNtCreateUserProcess pNtCreateUserProcess = (orgNtCreateUserProcess)RetrieveSyscallAddress("NtCreateUserProcess");
    if (pNtCreateUserProcess == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtCreateUserProcess\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtCreateUserProcess\n");
    int ssn = GetSsnByName((PCHAR)"NtCreateUserProcess");
    SetHwBp((ULONG_PTR)pNtCreateUserProcess, TRUE, ssn);
    return pNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}

ULONG wrpNtAlertResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    orgNtAlertResumeThread pNtAlertResumeThread = (orgNtAlertResumeThread)RetrieveSyscallAddress("NtAlertResumeThread");
    if (pNtAlertResumeThread == NULL) {
        printf("[!] Unable to resolve ntdll.dll!NtAlertResumeThread\n");
        return -1;
    }
    printf("[*] Calling function ntdll.dll!NtAlertResumeThread\n");
    int ssn = GetSsnByName((PCHAR)"NtAlertResumeThread");
    SetHwBp((ULONG_PTR)pNtAlertResumeThread, TRUE, ssn);
    return pNtAlertResumeThread(ThreadHandle, PreviousSuspendCount);
}
