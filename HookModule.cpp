#pragma once 

#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <winternl.h>
#include "HookModule.h"

DllInfo NtdllInfo;
PCONTEXT SavedContext;
PVOID h1, h2;
ULONG_PTR SyscallEntryAddr;
BOOL ExtendedArgs = FALSE;
int IsSubRsp = 0;
int SyscallNo = 0;
int OPCODE_SYSCALL_OFF = 0;
int OPCODE_SYSCALL_RET_OFF = 0;

void demofunction() {

    MessageBox(
        NULL,
        (LPCWSTR)L"Resource not available\nDo you want to try again?",
        (LPCWSTR)L"Account Details",
        MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
    );
}

void InitializeDllInfo(DllInfo* obj, const char* DllName) {
    HMODULE hModuledll = GetModuleHandleA(DllName);

    MODULEINFO ModuleInfo;
    if (GetModuleInformation(GetCurrentProcess(), hModuledll, &ModuleInfo, sizeof(MODULEINFO)) == 0) {
        printf("[!] GetModuleInformation failed\n");
        return;
    }

    obj->DllBaseAddress = (ULONG64)ModuleInfo.lpBaseOfDll;
    obj->DllEndAddress = obj->DllBaseAddress + ModuleInfo.SizeOfImage;
}

LONG WINAPI AddHwBp(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

        SyscallEntryAddr = ExceptionInfo->ContextRecord->Rcx;

        for (int i = 0; i < 25; i++) {
            // find syscall ret opcode offset
            if (*(BYTE*)(SyscallEntryAddr + i) == 0x0F && *(BYTE*)(SyscallEntryAddr + i + 1) == 0x05) {
                OPCODE_SYSCALL_OFF = i;
                OPCODE_SYSCALL_RET_OFF = i + 2;
                break;
            }
        }

        // Set hwbp at the syscall opcode
        ExceptionInfo->ContextRecord->Dr0 = (SyscallEntryAddr);
        ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 0);

        // Set hwbp at the ret opcode
        ExceptionInfo->ContextRecord->Dr1 = (SyscallEntryAddr + OPCODE_SYSCALL_RET_OFF);
        ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 2);

        ExceptionInfo->ContextRecord->Rip += OPCODE_SZ_ACC_VIO;
        printf("\n[*] Hardware Breakpoint added at address: %#llx (syscall)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr0);
        printf("[*] Hardware Breakpoint added at address: %#llx (ret)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr1);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


LONG WINAPI HandlerHwBp(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        // handler for syscall hwbp
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)(SyscallEntryAddr)) {

            printf("[*] Hardware Breakpoint hit at %#llx (syscall)\n", ExceptionInfo->ContextRecord->Rip);
            printf("[*] Storing Context\n");

            // Clear hwbp
            ExceptionInfo->ContextRecord->Dr0 = 0;
            ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 0);


            // save the registers and clear hwbp
            memcpy_s(SavedContext, sizeof CONTEXT, ExceptionInfo->ContextRecord, sizeof CONTEXT);

            // change RIP to printf()
            ExceptionInfo->ContextRecord->Rip = (ULONG_PTR)demofunction;

            // Set the Trace Flag
            ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Handler for syscall ret opcode
        else if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)(SyscallEntryAddr + OPCODE_SYSCALL_RET_OFF)) {
            printf("[*] Hardware Breakpoint hit at %#llx (ret)\n", ExceptionInfo->ContextRecord->Rip);
            printf("[*] Restoring stack pointer\n\n");

            // Clear hwbp
            ExceptionInfo->ContextRecord->Dr1 = 0;
            ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 2);

            // change stack so that it can return back to our program
            ExceptionInfo->ContextRecord->Rsp = SavedContext->Rsp;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Handler for the Trace flag
        else if (ExceptionInfo->ContextRecord->Rip >= NtdllInfo.DllBaseAddress &&
            ExceptionInfo->ContextRecord->Rip <= NtdllInfo.DllEndAddress) {

            // Find sub rsp, x where x is greater than what you want
            if (IsSubRsp == 0) {
                for (int i = 0; i < 80; i++) {
                    if (*(UINT16*)(ExceptionInfo->ContextRecord->Rip + i) == OPCODE_RET_CC) break;

                    if ((*(UINT32*)(ExceptionInfo->ContextRecord->Rip + i) & 0xffffff) == OPCODE_SUB_RSP) {
                        if ((*(UINT32*)(ExceptionInfo->ContextRecord->Rip + i) >> 24) >= 0x58) {

                            // appropriate stack frame found
                            IsSubRsp = 1;
                            ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                        else break;
                    }
                }
            }

            // wait for a call to take place
            if (IsSubRsp == 1) {
                // function frame does not contain call instruction
                if (*(UINT16*)ExceptionInfo->ContextRecord->Rip == OPCODE_RET_CC || *(BYTE*)ExceptionInfo->ContextRecord->Rip == OPCODE_RET)
                    IsSubRsp = 0;
                // function proceds to perform a call operation
                else if (*(BYTE*)ExceptionInfo->ContextRecord->Rip == OPCODE_CALL) {
                    IsSubRsp = 2;
                    ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            // appropriate stack frame and function frame found
            if (IsSubRsp == 2) {
                IsSubRsp = 0;
                printf("[*] Inside ntdll after setting TF at %#llx (%#llx)\n", ExceptionInfo->ContextRecord->Rip, ExceptionInfo->ContextRecord->Rip - NtdllInfo.DllBaseAddress);
                printf("[*] Generating stack & changing RIP & invoking intended syscall (ssn: %#x)\n", SyscallNo);

                ULONG64 TempRsp = ExceptionInfo->ContextRecord->Rsp;
                memcpy_s(ExceptionInfo->ContextRecord, sizeof CONTEXT, SavedContext, sizeof CONTEXT);
                ExceptionInfo->ContextRecord->Rsp = TempRsp;

                // emulate syscall
                // mov r10, rcx
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                // mov rax, #ssn
                ExceptionInfo->ContextRecord->Rax = SyscallNo;
                // set RIP to syscall opcode
                ExceptionInfo->ContextRecord->Rip = SyscallEntryAddr + OPCODE_SYSCALL_OFF;

                // if >4 agrs
                if (ExtendedArgs) {
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + FIFTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + FIFTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + SIXTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + SIXTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + SEVENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + SEVENTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + EIGHTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + EIGHTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + NINTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + NINTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + TENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + TENTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + ELEVENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + ELEVENTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + TWELVETH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + TWELVETH_ARGUMENT);
                }


                // Clear Trace Flag
                ExceptionInfo->ContextRecord->EFlags &= ~TRACE_FLAG;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // continue tracing
        ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void IntializeHooks() {
    h1 = AddVectoredExceptionHandler(CALL_FIRST, AddHwBp);
    h2 = AddVectoredExceptionHandler(CALL_FIRST, HandlerHwBp);
    SavedContext = (PCONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof CONTEXT);
    InitializeDllInfo(&NtdllInfo, "ntdll.dll");

    printf("[*] Ntdll Start Address: %#llx\n", NtdllInfo.DllBaseAddress);
    printf("[*] Ntdll End Address: %#llx\n\n", NtdllInfo.DllEndAddress);
}

void DestroyHooks() {
    if (h1 != NULL)    RemoveVectoredExceptionHandler(h1);
    if (h2 != NULL)    RemoveVectoredExceptionHandler(h2);
}

void _SetHwBp(ULONG_PTR FuncAddress) {
    TRIGGER_ACCESS_VIOLOATION_EXCEPTION
}

void SetHwBp(ULONG_PTR FuncAddress, int flag, int ssn) {
    ExtendedArgs = flag;
    SyscallNo = ssn;
    _SetHwBp(FuncAddress);
}

// https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/
int GetSsnByName(PCHAR syscall) {
    auto Ldr = (PPEB_LDR_DATA)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
    auto Head = (PLIST_ENTRY)&Ldr->Reserved2[1];
    auto Next = Head->Flink;

    while (Next != Head) {
        auto ent = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
        Next = Next->Flink;
        auto m = (PBYTE)ent->DllBase;
        auto nt = (PIMAGE_NT_HEADERS)(m + ((PIMAGE_DOS_HEADER)m)->e_lfanew);
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) continue; // no export table? skip

        auto exp = (PIMAGE_EXPORT_DIRECTORY)(m + rva);
        if (!exp->NumberOfNames) continue;   // no symbols? skip
        auto dll = (PDWORD)(m + exp->Name);

        // not ntdll.dll? skip
        if ((dll[0] | 0x20202020) != 'ldtn') continue;
        if ((dll[1] | 0x20202020) != 'ld.l') continue;
        if ((*(USHORT*)&dll[2] | 0x0020) != '\x00l') continue;

        // Load the Exception Directory.
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (!rva) return -1;
        auto rtf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(m + rva);

        // Load the Export Address Table.
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        auto adr = (PDWORD)(m + exp->AddressOfFunctions);
        auto sym = (PDWORD)(m + exp->AddressOfNames);
        auto ord = (PWORD)(m + exp->AddressOfNameOrdinals);

        int ssn = 0;

        // Search runtime function table.
        for (int i = 0; rtf[i].BeginAddress; i++) {
            // Search export address table.
            for (int j = 0; j < exp->NumberOfFunctions; j++) {
                // begin address rva?
                if (adr[ord[j]] == rtf[i].BeginAddress) {
                    auto api = (PCHAR)(m + sym[j]);
                    auto s1 = api;
                    auto s2 = syscall;

                    // our system call? if true, return ssn
                    while (*s1 && (*s1 == *s2)) s1++, s2++;
                    int cmp = (int)*(PBYTE)s1 - *(PBYTE)s2;
                    if (!cmp) return ssn;

                    // if this is a syscall, increase the ssn value.
                    if (*(USHORT*)api == 'wZ') ssn++;
                }
            }
        }
    }
    return -1; // didn't find it.
}
