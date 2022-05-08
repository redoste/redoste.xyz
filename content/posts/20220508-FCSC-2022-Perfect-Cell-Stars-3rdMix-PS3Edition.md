---
title: "Write-up FCSC 2022 : Perfect Cell - Stars:3rdMix PS3Edition"
date: 2022-05-08T18:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2022
---

# I - Intro

The description of *Perfect Cell* states that a friend of us made an homebrew for an "amazing multiplayer fighting game". It's joined with a file with the `.self` extension.

We'll start with the first obvious thing
```console
$ file perfect-cell.self
perfect-cell.self: data
```
Oh.

That's a good start.

Binwalk is able to find an ELF header a little bit later in the file but even after removing the first 0x90 bytes the file reamains unusable.
```console
$ binwalk -E perfect-cell.self 

DECIMAL       HEXADECIMAL     ENTROPY
--------------------------------------------------------------------------------
0             0x0             Falling entropy edge (0.246619)
1024          0x400           Rising entropy edge (0.973705)
1528832       0x175400        Falling entropy edge (0.181855)
```
Well it definitly looks encrypted.

We can use the first few bytes to try to identify the file type.
```console
$ hd perfect-cell.self | head -n 2
00000000  53 43 45 00 00 00 00 02  00 01 00 01 00 00 03 f0  |SCE.............|
00000010  00 00 00 00 00 00 0a 80  00 00 00 00 00 37 53 e8  |.............7S.|
```
Searching for `SCE` seems to refer to the format [Signed ELF or SELF by Sony](https://www.psdevwiki.com/ps3/SELF_-_SPRX), this format was used on the PS Vita and the PS3. I'm going to guess it's a PS3 homebrew.

After installing [RPCS3](https://rpcs3.net/) and loading the file, we are greeted by an amazing title screen featuring [Cell](https://en.wikipedia.org/wiki/Cell_(Dragon_Ball)) from Drangon Ball. Here it refers to the [Cell BE](https://en.wikipedia.org/wiki/Cell_(microprocessor)) processor present in the PS3.

!["Please connect to network shell to play" screen](/img/20220508-FCSC-2022-Perfect-Cell-Stars-3rdMix-PS3Edition/Perfect-Cell-001.png)

> "Please connect to network shell to play"

Well it looks like it's waiting for an incomming connection.
```console
$ ss -tlupn
tcp     LISTEN   0        1        0.0.0.0:1337        0.0.0.0:*       users:(("rpcs3",pid=4857,fd=83))
$ ncat 127.0.0.1 1337
    ____            ____          __     ______     ____
   / __ \___  _____/ __/__  _____/ /_   / ____/__  / / /
  / /_/ / _ \/ ___/ /_/ _ \/ ___/ __/  / /   / _ \/ / / 
 / ____/  __/ /  / __/  __/ /__/ /_   / /___/  __/ / /  
/_/    \___/_/  /_/  \___/\___/\__/   \____/\___/_/_/   
                                                        
========================================================
Welcome to Pefect Cell!

Please provide a correct input ...
FCSC{AAAAA}
Please provide a correct input ...
```

!["Connected and Playing!" screen](/img/20220508-FCSC-2022-Perfect-Cell-Stars-3rdMix-PS3Edition/Perfect-Cell-002.png)

Now that we know how the binary behave, let's try to decrypt to SELF and reverse it. Looking arround I found [BreakSelf](https://www.psdevwiki.com/ps3/Dev_Tools#Break_N_Make_.28MakeSelf_.26_BreakSelf.29) capable of doing it. After getting a clean cleartext ELF we can import it into Ghidra to look arround.

# II - Reversing the PPU Binary

After analysing the binary there weren't a lot of code. Even after looking for the success and failure strings they didn't have any X-Refs. Looks like something went wrong. I tried the aggressive instruction finder but it complained that there were not enough functions (isn't finding new functions the goal of the AIF ?)

Let's look into the debugger : after enabling it in RPCS3 we get a new pane with disassembly and register views. After an awkward amount of time I understood that I needed to select a thread in the little menu on the top right to see the disassembly.

We can now select the main thread and look up in the backtrace. Since we are waiting for an incomming TCP connection on port 1337 we should be inside the accept syscall. After finding the first address that was in the address space of the homebrew I looked it up in ghidra and frantically pressed D to discover as much code as possible before relaunching an analysis.

Well now we should have enough code. Let's go take back a look at the strings. Still no X-Refs ?

After taking a look at the code we just disassembled, there were a lot of references to r2. This reminded me of a concept of PowerPC. The *Small Data Array* or SDA, I have already encourted it when I did some reversing on the [Wii 2 years ago](https://redoste.xyz/2020/04/21/modding-wii-sports-part-i-identifying-files-and-creating-a-debug-output/#ii---reverse-engineering-the-binary).

The quick version is that PowerPC is a RISC architecure and it requires multiple instrctions to load a global, so the compiler will put all the most used globals in the same area and set a register as constant for the entirety of the program. Now when the program needs to use one of those globals it can just reference it relative to the SDA register, this will only require one instruction.

Ghidra supports SDA but you need to declare it in the Register Manager. I copied the value of r2 from the debugger and declared it as constant for the entirety of the program. After a quick reanalysis all the accesses relative to r2 are decompiled as global variable accesses.

![Ghidra Register Manager](/img/20220508-FCSC-2022-Perfect-Cell-Stars-3rdMix-PS3Edition/Perfect-Cell-003.png)

We can now follow the strings we looked at earlier. They are referenced from a function with a lot of code. We will just ignore it because it's probably just some calls to PS3 APIs for displaying text on the screen. An intresting part of it is the read of a global variable that will decide if the success of failure text should be shown.
```c
void display_str(int *param_1, int param_2) {
  // [...]
  puVar1 = PTR_WIN_STATE_WANTS_2_0021c380;
  // [...]
  if (*(int *)puVar1 == 1) {
    // [...]
    local_b0 = *(undefined8 *)PTR_s_You_Lose!_0021c438;
    // [...]
  }
  if (*(int *)puVar1 == 2) {
    // [...]
    local_b0 = *(undefined8 *)PTR_s_You_Win!_0021c450;
    // [...]
  }
  // [...]
  return;
}
```
Let's follow the X-Refs on this one : only one function writes to it, looks like we found the intresting part.

```c
  lVar4 = 6;
  memcpy(processed_input, PTR_INPUT_BUFFER_0021c4c0 + 5, 0x60);
  piVar9 = piVar3;
  do {
    iVar11 = *piVar9;
    syscall();
    piVar9 = piVar9 + 8;
    if (iVar11 != 0)
      goto LAB_000113c8;
    bVar1 = lVar4 != 1;
    lVar4 = lVar4 + -1;
  } while (bVar1);
  piVar9 = piVar3 + 3;
  do {
    while (*piVar9 == 0) {
      sync(0);
    }
    piVar9 = piVar9 + 8;
  } while (piVar3 + 0x33 != piVar9);
  lVar4 = memcmp(processed_input, PTR_EXPECTED_0021c4e8, 0x60);
  if (lVar4 == 0) {
    // [...]
    *(undefined4 *)PTR_WIN_STATE_WANTS_2_0021c380 = 2;
    // [...]
  }
```
The global is set to 2 only if the earlier function returns 0. A quick look reveals that it's just a `memcmp`, the input proabably goes through some transformations before getting compared to hardcoded bytes.
The bytes that seems to be our input have been copied from an other global indexed by 5 (`FCSC{` is 5 charcters long).

Following the X-Refs once again we can see this global array was written by a loop that waits for a function to to return 0x67. It's probably `recv` so we should provide an input 102 characters long (-1 for the newline) to the program for the transformations to get applied.
```c
  buffer = PTR_INPUT_BUFFER_0021c4c0;
  if (-1 < sVar6) {
    uVar4 = *PTR_s_Please_provide_a_correct_input_._0021c4b8;
    uVar9 = *(PTR_s_Please_provide_a_correct_input_._0021c4b8 + 8);
    uVar10 = *(PTR_s_Please_provide_a_correct_input_._0021c4b8 + 0x10);
    uVar11 = *(PTR_s_Please_provide_a_correct_input_._0021c4b8 + 0x18);
    uVar1 = *(PTR_s_Please_provide_a_correct_input_._0021c4b8 + 0x20);
    do {
      do {
        local_b0 = uVar4;
        local_a8 = uVar9;
        local_a0 = uVar10;
        local_98 = uVar11;
        local_90 = uVar1;
        send(socket, &local_b0, 0x23, flags);
        memset(buffer, 0, 0x800);
        sVar6 = recv(socket, buffer, 0x7ff, flags);
        if (sVar6 < 1) {
          return -1;
        }
      } while (sVar6 != 0x67);
      // [...]
    } while ((bVar2) || (puVar3[0x65] != '}'));
    return (longlong)iVar5;
  }
```

That's cool : we have a whole lot of informations about the context but where is crypto ? The only other call beetween the `memcpy` and the `memcmp` is a syscall and I doubt the PS3 has a `mangle_flag_for_fcsc` syscall.

Let's take a look in the debugger :
```
[000115d8]  44 00 00 02: sc #sys_spu_thread_write_snr
```
Just reading the syscall name scared me. I knew about thoses. When I understood it was a PS3 challenge it was the only thing I didn't want to happen.

# III - SPUs

The Synergistic Processing Units or SPUs are small coprocessors that were designed to handle complex calculation pipelines. They run a custom 128-bit SIMD architecture making it quite different from the usual instruction sets we deal with everyday.

This setup is very similiar from last year challenge [*Stars:2ndMix CryptoEdition*](https://redoste.xyz/2021/05/03/fr-write-up-fcsc-2021-stars2ndmix-cryptoedition/) (thus the name of this write-up) but I'm pretty confident we won't be able to just debug on the correct XOR and extract a key that way.

Using the debugger of RPCS3 we can see that 6 SPUs are started. Since the relevant part of the flag is 102 - 5 - 1 = 96 charcters long, each SPUs can be responsible for processing 16 charcters. Coincidentally SPUs work on 128 bits numbers, that looks like a correct assumption.

First thing first, we need to extract the code for the SPUs. Last year for *Stars:2ndMix CryptoEdition* I made a debug build of FlyCast and attached GDB on it to dump the code. However here RPCS3 is not same kind of beast.

The build provided by the developpement team is an AppImage without any debugging features enabled. I tried attaching GDB and just dumping all the process address space but it resulted in huge files that are practically unsearchable.

So let's rebuild RPCS3 with `-g` or with some dumping code in here ? Well let's take a look at [the requirement for building RPCS3](https://github.com/RPCS3/rpcs3/blob/master/BUILDING.md#linux) :

* Clang 12+ or GCC 11+
* CMake 3.16.9+
* Qt 5.15.2
* **Vulkan SDK** 1.2.198+ (See "Install the SDK" here)
* SDL2 (for the FAudio backend)

Vulkan SDK doesn't sound fun to deal with so let's try an other route for now. (To be honest it might be fine but when it's not as easy as just installing a `-devel` package, I will first try other solutions - and the tarball is 220MB or 1.1GB extracted (which doesn't feel like a lot after solving [More Hello](data:text/plain,TBD))).

We've got one last option, there is a memory viewer, I have huge vertical secondary screen and the important part is about 6400 bytes. Well I just copy pasted the hex values in a file. Two times because of course the first time I missed some.

After unhexlifying the file we can start analysing the transformations.

# IV - Dissassembling SPU code

A quick search on Google later, there seems to be IDA modules for disassembling SPU code, after installing [this one by *Mr Wicked*](https://sourceforge.net/projects/ida-spu/) and importing our previoulsy obtained dump at address 0 we can start looking for the functions.

We can use the debugger to follow what code each SPU is executing. All of them seem to start at the same location but after some internal magic they seem to all go to different functions.

```
ROM:000001D0                 nop            r127
ROM:000001D4                 lqr            r25, 0x1B74
ROM:000001D8                 ila            r26, spu_list
ROM:000001DC                 lqr            r34, xmmword_1660
ROM:000001E0                 ilhu           r37, 0x301
ROM:000001E4                 lqr            r31, xmmword_1650
ROM:000001E8                 nop            r127
ROM:000001EC                 lqd            r27, 0x30(sp)
ROM:000001F0                 ori            r38, r37, 2
ROM:000001F4                 lqd            r28, 0x20(sp)
ROM:000001F8                 cdd            r32, 0(sp)
ROM:000001FC                 rotqby         r3, r25, r13
ROM:00000200                 cwd            r39, 0(sp)
ROM:00000204                 stqd           r34, 0x80(sp)
ROM:00000208                 shufb          r33, r31, r27, r32
ROM:0000020C                 shli           r29, r3, 2
ROM:00000210                 clgti          r30, r3, 5
ROM:00000214                 shufb          r40, r38, r28, r39
ROM:00000218                 a              r36, r26, r29
ROM:0000021C                 lqx            r35, r26, r29
ROM:00000220                 stqd           r33, 0x30(sp)
ROM:00000224                 stqd           r40, 0x20(sp)
ROM:00000228                 rotqby         r41, r35, r36
ROM:0000022C                 brnz           r30, loc_2D0
ROM:00000230                 bi             r41
ROM:00000234 spu_list:       .int spu0               ; DATA XREF: ROM:000001D8↑o
ROM:00000238                 .int spu1
ROM:0000023C                 .int spu2
ROM:00000240                 .int spu3
ROM:00000244                 .int spu4
ROM:00000248                 .int spu5
```
This code is the last part each SPUs have in common. The address loaded in r41 is read from the array `spu_list` and indexed by the number of the current SPU.

We can define functions at each of the SPU code (here named `spu0` to `spu5`) to be able to follow the assembly in the graph view. All the functions seems pretty simple but with a lot a operations to transcribe. They all converge at some point, probably to write the modified part of the flag back to the main processor memory.

We could do all of that by hand but it seems a bit tedious, I wanted to have some kind of execution trace to refer myself to instead of having to lookup every single arithmetic instruction. So I looked for an independent SPU emulator.

# V - Using a SPU emulator to speedup the reversing process

[anergistic](https://github.com/kraiskil/anergistic) is an emulator developped by [fail0verflow](https://fail0verflow.com/blog/), a hacking group known for researching homebrew on multiple plaforms, including the PS3. Here we are using a "modern" fork from 2011 since the original repo was taken down.

After fixing a few lines in the Makefile for supporting python2.7 instead of python2.6, the project can be built with a simple `make`.

We can launch the emulator by passing a path to an ELF file in parameter. It seems complex to implement raw binary loading so I just wrote a simple ELF header by hand :
```
$ readelf -a dumpspu.elf
ELF Header:
  Magic:   7f 45 4c 46 01 02 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, big endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           None
  Version:                           0x1
  Entry point address:               0x420
  Start of program headers:          52 (bytes into file)
  Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           0 (bytes)
  Number of section headers:         0
  Section header string table index: 0

There are no sections in this file.

There are no sections to group in this file.

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000054 0x00000000 0x00000000 0x01900 0x01900 RWE 0x1000

There is no dynamic section in this file.

There are no relocations in this file.

The decoding of unwind sections for machine type None is not currently supported.

Dynamic symbol information is not available for displaying symbols.

No version information found in this file.
```
Here the entry point is set to the beginning of the `spu5` function.

Launching the emulator seems to work but it still needs some modifictions :

First we will enable the intructions and memory accesses debugging as they will be very helpful when reading the traces.
```patch
diff --git a/config.h b/config.h
index 9cd886b..87c73aa 100644
--- a/config.h
+++ b/config.h
@@ -6,10 +6,10 @@
 #define CONFIG_H__
 
 #define DEBUG
-//#define DEBUG_INSTR
+#define DEBUG_INSTR
 //#define DEBUG_GDB
 
-//#define DEBUG_INSTR_MEM
+#define DEBUG_INSTR_MEM
 #define DEBUG_TRACE
 
 //#define FAIL_DUMP_REGS
```
We will also set a stop address as everything after this is just resposible to write back the transformed data. I've checked with RPCS3 debugger that all the SPUs finished their work when coming at this address. This will make the traces way shorter and easier to work with.
```patch
diff --git a/emulate.c b/emulate.c
index a1dd5e8..c19707f 100644
--- a/emulate.c
+++ b/emulate.c
@@ -187,6 +187,9 @@ u32 emulate(void)
	if ((ctx->pc & 3) != 0)
		fail("pc is not aligned: %08x", ctx->pc);
 
+	if(ctx->pc == 0x2B4)
+		return 1;
+
 //	dbgprintf("\n\n", count);
	return 0;
 }
```
Finally we will initialize the stack pointer (r1) and write the flag input from a file. This will allow us to generate traces for different test patterns.
```patch
diff --git a/main.c b/main.c
index f85547b..f033ffd 100644
--- a/main.c
+++ b/main.c
@@ -124,6 +124,18 @@ int main(int argc, char *argv[])
	wbe32(ctx->ls + 0x3f008, 0x10000);
	wbe32(ctx->ls + 0x3e000, 0xff);
 #endif
+	ctx->reg[1][0] = 0x3FF00;
+	ctx->reg[1][1] = 0x3FF00;
+	ctx->reg[1][2] = 0x3FF00;
+	ctx->reg[1][3] = 0x3FF00;
+
+	u_int64_t flag[12];
+	FILE* inp = fopen("inp", "r");
+	fread(flag, sizeof(u_int64_t), sizeof(flag) / sizeof(u_int64_t), inp);
+	for(size_t idx = 0; idx < sizeof(flag) / sizeof(u_int64_t); idx++) {
+		wbe64(ctx->ls + 0x3FF00 + 0x30 + (idx * 8), __builtin_bswap64(flag[idx]));
+	}
+	fclose(inp);
 
	if (gdb_port < 0) {
		ctx->paused = 0;
```
The input is a little bit bigger than required because the flag portion is present multiple times and some other constants are loaded with it from the main CPU.

I changed the entry point of the ELF to test different SPUs code but two of them failed. With some single stepping in the debugger I was able to identify a faulty instruction, `andhi` was not reading from `ra`. On the other hand `shlhi` was simply not implemented.
```patch
diff --git a/instrs b/instrs
index b77d65a..fa169bd 100644
--- a/instrs
+++ b/instrs
@@ -681,11 +681,11 @@
 
 00010101,ri10,andhi,half,signed
 {
	int i;
	for (i = 0; i < 8; ++i)
-		rth[i] &= i10;
+		rth[i] = rah[i] & i10;
 }
 
 00010100,ri10,andi,signed
 {
	int i;
@@ -1005,10 +1005,23 @@
		else
			rtw[i] = raw[i] << shift_count;
	}
 }
 
+00001111111,ri7,shlhi,half
+{
+	int i;
+	int shift_count = i7 & 0x1f;
+	for (i = 0; i < 8; ++i)
+	{
+		if (shift_count > 15)
+			rth[i] = 0;
+		else
+			rth[i] = rah[i] << shift_count;
+	}
+}
+
 00001011011,rr,shl
 {
	int i;
	for (i = 0; i < 4; ++i)
	{
```

Now that we can produce clear traces and have an interactive disassembler, we sit down, focus for 2 hours and transcribe the whole code.

# VI - Conclusion

I won't go through all the details since it's mostly understanding every instructions and writing the inverse operation in a python script so here is the solve script, it describes pretty well what each SPUs does.
```python
import sys
import struct

c1730 = bytes.fromhex(
"32 A5 2B DF AC D9 CD C1 EF 3A 84 2C 53 3C FF 9A" +
"EB 16 D3 3F BC C4 31 47 12 96 75 90 8A C5 BF 43" +
"7A 64 B5 C6 AA A1 22 48 F9 99 08 34 65 A3 98 44" +
"A0 E0 6B B6 BE CE FC 03 A6 A4 35 5E 11 D7 76 05" +
"0E F4 A2 AE 70 6F 78 9C 09 4C 17 F0 D8 56 FD 15" +
"71 F3 FB 1D B7 A7 66 9F B3 79 C3 B4 5D 5B AB D6" +
"94 1E C0 0C 9D 04 7F E4 6A 4B 9B E8 0D 86 82 EA" +
"52 DB 51 D4 B0 B9 A8 61 6D E6 97 7C AD CB DA 88" +
"68 1C 07 00 30 6C 50 59 3E 40 20 DE F1 F5 0F A9" +
"5C 4D 89 21 BD E2 57 0B 67 C7 87 C2 D2 DC 18 93" +
"8E 36 77 8C E5 4E 9E 39 60 80 73 FA FE 0A 81 ED" +
"B1 2F F6 BA 58 EE 85 45 38 D5 4A E7 5F 2E F7 91" +
"2D 95 7D B8 7E 1F 49 02 63 E3 2A E1 10 CA 06 27" +
"37 69 3B 83 8F 92 13 55 CC 29 54 26 14 1A 1B 41" +
"D1 42 46 EC 62 74 D0 28 3D 8B F8 CF 7B B2 4F 6E" +
"C8 DD 33 23 F2 AF 72 24 E9 01 19 8D BB 25 C9 5A"
)

def rol_byte(inp, x):
    x = x % 16
    assert len(inp) == 16
    out = b""
    for i in range(16):
        out += struct.pack("B", inp[(i + x) % 16])
    return out

def ror_bit(inp, x):
    assert x < 64
    a, b = struct.unpack("!QQ", inp)
    ab = a << 64 | b
    ab = (ab >> x) | (ab << (128 - x)) & (2**128)-1
    return struct.pack("!QQ", ab >> 64, ab & (2**64)-1)

def sbox_inverse(inp):
    out = bytearray([0] * 16)
    for i in range(0x10):
        s = -1
        for j in range(len(c1730)):
            if c1730[j] == inp[i]:
                s = j
                break
        assert s != -1
        out[i] = s
    return out

def spu0(inp):
    r15 = bytearray(sbox_inverse(inp))
    for i in range(0x10):
        r15[i] = (r15[i] + 0xef) & 0xff
    r79 = bytearray(ror_bit(r15, 5))

    out = bytearray([0] * 16)
    for i, c in enumerate([0x5, 0x9, 0x8, 0x4,
                           0x1, 0x0, 0xa, 0xc,
                           0xb, 0xf, 0xe, 0x7,
                           0xd, 0x2, 0x3, 0x6]):
        out[i] = r79[c]
    return out

def spu1(inp):
    r3 = struct.unpack("!IIII", sbox_inverse(inp))
    cFEED = [0xFEEDBABE, 0xDEADBEEF, 0xFEEDBABE, 0xDEADBEEF]
    r63 = [0] * 4
    for i, a, b in zip(range(4), r3, cFEED):
        r63[i] = (a + b + (i%2 ^ 1)) & 0xffffffff
    r63 = struct.pack("!IIII", *r63)

    out = rol_byte(ror_bit(r63, 6), -9)
    return out

def spu2(inp):
    r3 = sbox_inverse(inp)
    out = b""
    for a, b in zip(r3, bytes.fromhex("AABBCCDDEEFF1122AABBCCDDEEFF1122")):
        out += struct.pack("B", a ^ b)
    return out

def spu3(inp):
    r78 = struct.unpack("!QQ", sbox_inverse(inp))
    r77 = struct.pack("!QQ", r78[0] ^ (2**64)-1, r78[1] ^ (2**64)-1)

    r72 = struct.unpack("!HHHHHHHH", rol_byte(ror_bit(r77, 3), -5))
    out = [0] * 8
    for i, c in enumerate([7,6,3,1,0,2,4,5]):
        out[i] = r72[c]
    return struct.pack("!HHHHHHHH", *out)

def spu4(inp):
    r3 = struct.unpack("!IIII", sbox_inverse(inp))
    r44 = struct.pack("!IIII", r3[3], r3[1], r3[0], r3[2])

    out = b""
    for a, b in zip(r44, bytes.fromhex("87934520")*4):
        out += struct.pack("B", a ^ b)
    return out

def spu5(inp):
    r11 = struct.unpack("!HHHHHHHH", sbox_inverse(inp))
    r26 = [0] * 8
    for i, c in enumerate([7,6,3,1,0,2,4,5]):
        r26[i] = r11[c]

    out = b""
    for h in r26:
        out += struct.pack("!h", (h - 0xfaaf) & 0xffff)
    return out

expected = bytes.fromhex("05d25acb9f61242e2490c30ec3dc1ba6" +
                         "92dc2166bba13c99920a2175249d5d6a" +
                         "c9b2580f30875b474607fa45384de84c" +
                         "ab9dbe5ba7cda77b1f04fe86785dcb49" +
                         "1b8bd3825a7ecba72a2a52bc7377b979" +
                         "783aaec46b19e8a5a775fb4605d382b5")

flag = b""
for i, f in enumerate([spu0, spu1, spu2, spu3, spu4, spu5]):
    flag += f(expected[i*16:(i+1)*16])
print("FCSC{%s}" % flag.decode())
```
Please note that it is the cleaned up version of the script. At the beginning I wrote one file per SPU without noticing their similarities. It took me up to SPU3 or SPU4 to notice that they all ended with the same s-box.

```console
$ python3 solve.py
FCSC{30gbt9RzIif5L_s70cRm7gXHm_R-8WkKTVxSjeL5H9gjVnzkSJBg3y4prWG4tU_5-10yxW8uYzWNMY54ssDcpRHfKZ8KZkX3}
$ ncat 127.0.0.1 1337
    ____            ____          __     ______     ____
   / __ \___  _____/ __/__  _____/ /_   / ____/__  / / /
  / /_/ / _ \/ ___/ /_/ _ \/ ___/ __/  / /   / _ \/ / / 
 / ____/  __/ /  / __/  __/ /__/ /_   / /___/  __/ / /  
/_/    \___/_/  /_/  \___/\___/\__/   \____/\___/_/_/   
							
========================================================
Welcome to Pefect Cell!

Please provide a correct input ...
FCSC{30gbt9RzIif5L_s70cRm7gXHm_R-8WkKTVxSjeL5H9gjVnzkSJBg3y4prWG4tU_5-10yxW8uYzWNMY54ssDcpRHfKZ8KZkX3}
Well done, this is a win! :-)
```

!["You Win!" screen](/img/20220508-FCSC-2022-Perfect-Cell-Stars-3rdMix-PS3Edition/Perfect-Cell-004.png)
