---
title: "Write-up FCSC 2023 : Contrôleur de licence"
date: 2023-04-30T22:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2023
---

# I - Intro

At first glace, *Contrôleur de licence* seems to be a classic Windows reverse challenge. We give an input in the arguments and we get a "Invalid serial" `MessageBox` in response.

After importing the binary in Ghidra, we can already spot a few suspicious imports, such as `CreateDecompressor` and `Decompress` from `CABINET.DLL` or `WriteProcessMemory` and `SetThreadContext` from `KERNEL32.DLL`.

It looks like the program will need to decompress data and modify the execution from other processes, this might be some kind of custom packer for the underlying input checking binary.

# II - Reversing the loader

By looking at the main function we can easily spot two stage, the decompression and the loading of the binary :

The decompression just looks for a `.etext` section and use `CABINET.DLL` for decompressing its content.

I didn't look that much into it since it's basicaly just parsing PE structures but it boils down to this pseudocode :
```c
for each sections {
    if (strncmp(section_name, ".etext", 6) == 0) {
        decompressed_data = VirtualAlloc(NULL, decompressed_data_buffer_size, 0x3000, 4);
        if (decompressed_data != NULL) {
            if ((CreateDecompressor(5, 0, &decompressor_handle) != 0) &&
                (Decompress(decompressor_handle,
                            compressed_data, compressed_data_size,
                            decompressed_data, decompressed_data_buffer_size, &decompressed_data_size) != 0)) {
                if (argc == 3) {
                    if (child_fn(&decompressed_data) != 0) {
                        (*(code *)entrypoint)();
                    }
                }
                else {
                    goto PARENT_PART;
                }
                break;
            }
        }
    }
}
```

By looking at [the documentation](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-createdecompressor#parameters) we can find that the algorithm used is LZMS. This seems to be a not that well-known compression method that is mostly used in Microsoft proprietary formats such as WIM archives.

The easiest way to get the decompressed data out is to debug the process and dump the content of the region allocated by `VirtualAlloc` right after the `Decompress` call. We indeed get a PE file :
```console
$ file controleur-de-licence_000001C822770000.bin
controleur-de-licence_000001C822770000.bin: PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 6 sections
```
Let's import it into Ghidra to look at it :

{{< image "Ghidra screenshot with meaningless disassembly" "img/20230430-FCSC-2023-Controleur-de-licence/Controleur-de-licence-001.png" >}}

Ugh, something is not *quite* right. I think we will need to dig deeper in the loader code.

In the previous pseudocode listing, before jumping to the entrypoint of the freshly decompressed PE, we check if we are called with 2 arguments and call `child_fn`. `child_fn` in it self is quite boring, it looks like a PE parser and probably just maps the sections according to the header. However we can spot a surpsing twist :
```c
do {
    if (current_section->name[i]) != ".text"[i])
        goto NOT_TEXT;
    i = i + 1;
} while (i != 6);
memset(current_section->data, 0xcc, current_section->size);
NOT_TEXT:
```
The loader fills the `.text` section with `0xcc` which corresponds at `int3` in x86 : a call to the debugger.
So the PE file we decompressed doesn't contain the code in itself, as its section will be overwritten by the loader anyway.

But this entier part is only relevant if `argc == 3`, when we call the binary with the input as an argument, `argc` is 2. Let's take a quick look at the `PARENT_PART` of `main` :
```c
snprintf(cmdline, sizeof(cmdline), "%s %s %d", *argv, argv[1], 1);
ret = CreateProcessA(NULL, cmdline, NULL,
                     NULL, 0, 0x12, NULL,
                     NULL, &startup_info, &process_info);
if (ret != 0) {
    CloseHandle(process_info.hThread);
    parent_fn(&decompressed_data, pcVar4, process_info.hProcess);
}
```
So the packer will first create a child process with an extra argument `1` that will lead to the code full of `int3`.

Looking at `parent_fn` might not be that surprising : we see calls to `WaitForDebugEvent`, `OpenThread`, `WriteProcessMemory`, `GetThreadContext` and `SetThreadContext`. We are probably in the situation where the child process is being supervised by the parent one and when it hits an `int3`, the parent process will replace it with an other instruction.

The function in itself seems quite complex but we can easily understand its structure :
```c
while (1) {
    WaitForDebugEvent(&debug_event_data, 0xffffffff);
    if (debug_event_data.dwDebugEventCode != 1 ||
        debug_event_data.u.Exception.ExceptionRecord.ExceptionCode != 0x80000003) {
        continue;
    }

    hThread = OpenThread(0x1a, 0, debug_event_data.dwThreadId);
    SuspendThread(hThread);

    VirtualProtectEx(hProcess, old_address, 0x10, 4, &old_protection);
    WriteProcessMemory(hProcess, old_address, "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", 0x10, &written),
    VirtualProtectEx(hProcess, old_address, 0x10, old_protection, &old_old_protection);

    GetThreadContext(hThread, &thread_context);
    old_address = thread_context.Rip - 1;
    thread_context.Rip = old_address;

    /* [[[ insert here some magic involving BCRYPT.DLL doing MD5 on thread_context.Rip ]]] */

    VirtualProtectEx(hProcess, old_address, 0x10, 4, &old_protection);
    WriteProcessMemory(hProcess, old_address, magic_output, 0x10, &written),
    VirtualProtectEx(hProcess, old_address, 0x10, old_protection, &old_old_protection);
    FlushInstructionCache(hProcess, old_address, 0x10);
    SetThreadContext(hThread, &thread_context);
    ResumeThread(hThread);
}
```
In the end, the parent process will wait for the child to hit an `int3`, will replace the instruction it's currently at and resume it while making sure to replace back the instruction with `int3` on the next call.

We could try to understand what magic lies in the middle and where the newly written instructions come from but by looking at it briefly we can already easily conclude on the nature of it : the value of `rip` is hashed in MD5 with `BCRYPT.DLL` and the hash is reduced with a huge mess of `xor`s.

This is probably some kind of hash table where the key is the current value of `rip` and the value is the instructions to write. As `parent_fn` also takes a pointer to the decompressed PE binary, we can assume that the hash table is stored in the `.text` section of the binary we extracted.

We could try to understand how this table works and manualy dump its content, but it looks like a huge pain. Let's not do that.

# III - *Not* reversing the hash table

In the end the binary knows how to get the values out of the hash table, so we will instrument it to dump it for us.

Since all the I/O we will need with this method is done through calls to `KERNEL32.DLL` functions, I had the idea to replace them with our own implementation that will mimick the execution of the child process.

Introducing... `KERNOL32.DLL` !
```c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

FILE *outfile = NULL;
__declspec(dllexport) BOOL CreateProcessA(
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
) {
    if (outfile == NULL) {
        outfile = fopen("Z:\\kernol32output.txt", "w");
    }
    return TRUE;
}

__declspec(dllexport) BOOL WaitForDebugEvent(
    LPDEBUG_EVENT lpDebugEvent,
    DWORD         dwMilliseconds
) {
    lpDebugEvent->dwDebugEventCode = 1;
    lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode = 0x80000003;
    return TRUE;
}

__declspec(dllexport) HANDLE OpenThread(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwThreadId
) {
    return 0x41414141;
}

__declspec(dllexport) DWORD SuspendThread(
    HANDLE hThread
) {
    return 0x1337;
}

__declspec(dllexport) BOOL VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
) {
    return TRUE;
}

__declspec(dllexport) BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
) {
    fprintf(outfile, "WPM %p ", lpBaseAddress);
    for (size_t i = 0; i < nSize; i++) {
        fprintf(outfile, "%02hhx", ((uint8_t*)lpBuffer)[i]);
    }
    fprintf(outfile, "\n");
    return TRUE;
}

uint64_t RIP = 0x180001000;
__declspec(dllexport) BOOL GetThreadContext(
    HANDLE    hThread,
    LPCONTEXT lpContext
) {
    lpContext->Rip = RIP;
    RIP++;
    if (RIP > 0x180003000) {
        fflush(outfile);
        fclose(outfile);
        exit(1);
    }
    return TRUE;
}
```
This simple DLL will simulate all the calls required by the packer without spawning the child process at any point.

However to be able to fully replace `KERNEL32.DLL` we need to let through most of the other imports required by the binary. This can be done with [export declaration pointing to an other module](https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170). On MinGW this can be achieved simply by putting strings in the `.drectve` section of an object :
```
.section .drectve
.ascii " -export:GetCurrentProcess=KERNEL32.GetCurrentProcess"
.ascii " -export:FlushInstructionCache=KERNEL32.FlushInstructionCache"
.ascii " -export:ReadFile=KERNEL32.ReadFile"
.ascii " -export:GetModuleFileNameA=KERNEL32.GetModuleFileNameA"
.ascii " -export:GetFileSizeEx=KERNEL32.GetFileSizeEx"
.ascii " -export:VirtualProtect=KERNEL32.VirtualProtect"
.ascii " -export:HeapFree=KERNEL32.HeapFree"
.ascii " -export:VirtualFree=KERNEL32.VirtualFree"
.ascii " -export:VirtualAlloc=KERNEL32.VirtualAlloc"
.ascii " -export:CreateFileA=KERNEL32.CreateFileA"
.ascii " -export:LoadLibraryA=KERNEL32.LoadLibraryA"
.ascii " -export:CloseHandle=KERNEL32.CloseHandle"
.ascii " -export:HeapAlloc=KERNEL32.HeapAlloc"
.ascii " -export:GetProcAddress=KERNEL32.GetProcAddress"
.ascii " -export:GetProcessHeap=KERNEL32.GetProcessHeap"
.ascii " -export:FreeLibrary=KERNEL32.FreeLibrary"
//.ascii " -export:WriteProcessMemory=KERNEL32.WriteProcessMemory"
//.ascii " -export:WaitForDebugEvent=KERNEL32.WaitForDebugEvent"
//.ascii " -export:SuspendThread=KERNEL32.SuspendThread"
.ascii " -export:ResumeThread=KERNEL32.ResumeThread"
.ascii " -export:ContinueDebugEvent=KERNEL32.ContinueDebugEvent"
.ascii " -export:GetLastError=KERNEL32.GetLastError"
//.ascii " -export:VirtualProtectEx=KERNEL32.VirtualProtectEx"
//.ascii " -export:GetThreadContext=KERNEL32.GetThreadContext"
.ascii " -export:GetModuleHandleW=KERNEL32.GetModuleHandleW"
.ascii " -export:TerminateProcess=KERNEL32.TerminateProcess"
//.ascii " -export:CreateProcessA=KERNEL32.CreateProcessA"
.ascii " -export:SetThreadContext=KERNEL32.SetThreadContext"
//.ascii " -export:OpenThread=KERNEL32.OpenThread"
.ascii " -export:SetUnhandledExceptionFilter=KERNEL32.SetUnhandledExceptionFilter"
.ascii " -export:UnhandledExceptionFilter=KERNEL32.UnhandledExceptionFilter"
.ascii " -export:IsProcessorFeaturePresent=KERNEL32.IsProcessorFeaturePresent"
.ascii " -export:QueryPerformanceCounter=KERNEL32.QueryPerformanceCounter"
.ascii " -export:GetCurrentProcessId=KERNEL32.GetCurrentProcessId"
.ascii " -export:GetCurrentThreadId=KERNEL32.GetCurrentThreadId"
.ascii " -export:GetSystemTimeAsFileTime=KERNEL32.GetSystemTimeAsFileTime"
.ascii " -export:IsDebuggerPresent=KERNEL32.IsDebuggerPresent"
.ascii " -export:InitializeSListHead=KERNEL32.InitializeSListHead"
```

Now we just have to throw the binary in a hexeditor and change `KERNEL32.DLL` to `KERNOL32.DLL` and start the binary. We obtain a text file in the following format :
```
WPM 0000000180000fff a29f51fa05b58372c7cccccccccccccc
WPM 0000000180001000 488d0539460000cccccccccccccccccc
WPM 0000000180001001 52cccccccccccccccccccccccccccccc
WPM 0000000180001002 5bcccccccccccccccccccccccccccccc
WPM 0000000180001003 cfcccccccccccccccccccccccccccccc
WPM 0000000180001005 190d36b309e5cccccccccccccccccccc
WPM 0000000180001006 a3a5e07f1e2db256aacccccccccccccc
WPM 0000000180001007 c3cccccccccccccccccccccccccccccc
WPM 0000000180001010 4889542410cccccccccccccccccccccc
WPM 0000000180001011 9dcccccccccccccccccccccccccccccc
...
```

However, we can't simply throw all of those into a PE file and reverse it independently as x86 has variable-length instructions, we don't know where `rip` will exactly go and a lot of those values from the hash table will probably never get used.

I tried different solutions to guess the length of the instructions but what worked the best was to not try to fill the entire file at once.

I wrote a simple Python script that place instructions one after the other in the file and will stops when it hits a `int3`. That way, I imported the binary in Ghidra, looked for empty functions, started the script with the address of the missing function in argument, reloaded and reanalysed the binary and ended up repeating that process a bunch of times until I was satisfied with the output.

# IV - Analysing the dumped binary

We now have a simple PE, that looks like a DLL, with the verification logic. Since the most difficult part of the challenge was the packer and its hash table, it should be fairly trivial to understand the key check.

In the end it boils down to the following checks :

 * Input is in the format "`KEY-XXX-YYYYYYY`"
 * `XXX != 222 && XXX != 333 && XXX < 999`
 * `(~(XXX & 777) & (input[4] ^ input[8] ^ (XXX | 777))) != 0`
 * `sum(digits of YYYYYYY) % 7 == 0`
 * `sha256(input) == 0a8e35559ba20ebbc7c4db37dda07dfd3e86cf2245796da12e0b66534515ae7f`

If the input matches all the checks, it is used as an AES key to decrypt the flag.

At the beginning, I was surprised by the number of possibilities for the first 4 checks and I ended up spending way too much time trying to find a mistake in my understanding of the binary or a bug in my bruteforcing logic.

After a while I just gave up and tried bruteforcing with a faster language than Python and the answer was found fast enough, I think I should try to be more confident in myself `:/`

# V - Conclusion

In the end the bruteforcing logic can be written pretty easily :
```c
#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

char expected_hash[] = "\x0a\x8e\x35\x55\x9b\xa2\x0e\xbb\xc7\xc4\xdb\x37\xdd\xa0\x7d\xfd\x3e\x86\xcf\x22\x45\x79\x6d\xa1\x2e\x0b\x66\x53\x45\x15\xae\x7f";
int main(void) {
    for (uint32_t KEY1 = 0; KEY1 < 1000; KEY1++) {
        if (KEY1 == 222) continue;
        if (KEY1 == 333) continue;
        for (uint32_t KEY2 = 0; KEY2 < 10000000; KEY2++) {
            char buffer[32];
            sprintf(buffer, "KEY-%03u-%07u", KEY1, KEY2);
            char ui4 = buffer[4];
            char ui8 = buffer[8];
            if ((((KEY1 & 777) ^ 0xffffffff) & (ui4 ^ ui8 ^ (KEY1 | 777))) == 0) continue;
            int u = 0;
            for (int i = 0; i < 7; i++) {
                u += buffer[8+i];
            }
            if (u % 7 != 0) continue;

            if ((KEY2 & 0x7fff) == 0)
                printf("%s...\n", buffer);

            char hash[SHA256_DIGEST_LENGTH];
            SHA256(buffer, 3+1+3+1+7, hash);

            if (memcmp(hash, expected_hash, SHA256_DIGEST_LENGTH) == 0) {
                printf("%s\n", buffer);
                printf("%s\n", buffer);
                printf("%s\n", buffer);
                exit(0);
            }
        }
    }
    return 0;
}
```

```console
$ time ./solve
KEY-644-5958868

real    10m4.940s
user    10m3.778s
sys     0m0.075s
```

We can give this input to the binary and get the flag :

{{< image "Windows MessageBox showing the flag : FCSC{W1ND0W5-95-r37411-Pr0DUC7-K3Y}" "img/20230430-FCSC-2023-Controleur-de-licence/Controleur-de-licence-002.png" >}}

After reading the flag, I instantly remembered where I have already seen this kind of checks. The `!= 222` and `!= 333` are pretty rememberable and I had already seen a [video on the Windows 95 key check](https://youtu.be/cwyH59nACzQ). This might have saved me all the time I spent reverifying my interpreation of the code.
