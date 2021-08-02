---
title: "Write-up UIUCTF 2021 : ropfuscated"
date: 2021-08-03T00:00:00+02:00
draft: false
tags:
- CTF
- UIUCTF
- UIUCTF 2021
---

# I - Intro

*ropfuscated* is composed of a single but huge (4.1MiB, that's about half of the Linux kernel installed on my laptop) x86-64 Linux binary.
Running it for the first time, we are greated by a message asking us to draw a patern with the mouse in a way that mimic the Android lockscreen.
Some ANSI terminal magic allows the program to follow the mouse and draw the pattern with tildes. After releasing the left click, the program checks the pattern and awnsers `Sorry, try again!`.

Throwing the executable into Ghidra reveals next to nothing, there is a `main()` function that initialize the terminal stuff and then a simple function `rop()` is called :
```
         rop
00401310 LEA        RSP,[rop_chain]
00401318 RET
```
That's where the fun part begins, all the logic of the program is made using a rop chain. The stack is now hardcoded and tons of return pointers will be poped for executing gadgets. This is like programming in the weirdest instruction set you can think of.

We can extract the rop chain by first determining its size, with a quick look at the end of the `.data` section we can determine where all zeroes begin and the rop chain ends. It's then trivial to extract the 2.6MiB of return addresses.

# II - Extracting gadgets and building the pseudocode

First we'll determine the list of gadgets used by the rop chain. For that I wanted to differentiate the data from the pointers to code. It's easly done by a python script with the sections of the ELF hardcoded :
```python
import struct

text_start = 0x04010c0
text_end = text_start + 0x0395

data_start = 0x0404060
data_end = data_start + 0x0410010

with open("rop_chain", "rb") as f:
    while True:
        try:
            addr = struct.unpack("<Q", f.read(8))[0]
        except struct.error:
            break
        if addr >= text_start and addr < text_end:
            print("gadget : 0x%08X" % addr)
        elif addr >= data_start and addr < data_end:
            print("data @ 0x%08X" % addr)
        else:
            print("data : 0x%08X" % addr)
```
```console
$ python3 code_vs_data.py | grep gadget | sort -u | wc -l
118
```
So we got 118 gadgets, that's not a lot, we can probably identify them by hand.
For that we'll need the code of said gadgets, I used `pwntools` because it includes an ELF parser with an easy to use disassembler :
```python
from pwn import *

e = ELF("./ropfuscated")

while True:
    g_addr = int(input(), 16)
    s = e.disasm(g_addr, 128).split("ret    \n")
    if len(s) <= 1:
        raise Exception("ret not found !")
    print("Gadget @ 0x%08X : " % g_addr, end="")
    d = s[0] + "ret"
    outs = ""
    for l in d.split("\n"):
        ls = l[len("  40132a:       c3                      "):].strip()
        if ls != "":
            outs += ls + ";"
    print(outs)
```
`pwntools` produces a disassembly meant for humans with whitespaces making it easier to read. So if you're wondering what's all those weird strings manipulations, it's only for dealing with that.
```console
$ python3 code_vs_data.py | grep gadget | sort -u | cut -d ":" -f 2 | python3 gadget_disass.py > gadgets.txt
```
After cleaning the file, I wrote some form of pseudocode for each gadgets. It's not really consistent but it should be good enough for our purpose :
```
Gadget @ 0x004010EF : nop;endbr64;ret;                                     # endbr64
Gadget @ 0x004010F0 : endbr64;ret;                                         # endbr64
Gadget @ 0x0040111E : xchg   ax, ax;ret;                                   # nop
Gadget @ 0x00401160 : ret;                                                 # nop
Gadget @ 0x0040118E : ret;                                                 # nop
Gadget @ 0x0040118F : nop;ret;                                             # nop
Gadget @ 0x00401303 : add    eax, 0xfffd57e8;dec    ecx;ret;               # eax += 0xfffd57e8 && ecx--
Gadget @ 0x0040130A : ret;                                                 # nop
Gadget @ 0x00401313 : and    eax, 0x414070;ret;                            # eax &= 0x414070
Gadget @ 0x0040131C : ret;                                                 # nop
Gadget @ 0x00401325 : syscall;cmp    rax, rbx;ret;                         # syscall && cmp rax, rbx
Gadget @ 0x00401326 : add    eax, 0xc3d83948;cmp    rcx, rbx;ret;          # eax += 0xc3d83948 && cmp rax, rbx
Gadget @ 0x00401327 : cmp    rax, rbx;ret;                                 # cmp rax, rbx
Gadget @ 0x00401328 : cmp    eax, ebx;ret;                                 # cmp eax, ebx
Gadget @ 0x0040132A : ret;                                                 # nop
Gadget @ 0x0040132B : cmp    rcx, rbx;ret;                                 # cmp rcx, rbx
Gadget @ 0x0040132C : cmp    ecx, ebx;ret;                                 # cmp ecx, ebx
Gadget @ 0x0040132F : xor    rax, rax;ret;                                 # rax ^= rax
Gadget @ 0x00401330 : xor    eax, eax;ret;                                 # eax ^= eax
Gadget @ 0x00401331 : rol    bl, 0x48;sub    eax, ebx;ret;                 # rol bl, 0x48 && eax -= ebx
Gadget @ 0x00401334 : sub    eax, ebx;ret;                                 # eax -= ebx
Gadget @ 0x00401336 : ret;                                                 # nop
Gadget @ 0x00401337 : xchg   rbx, rax;ret;                                 # rbx, rax = rax, rbx
Gadget @ 0x00401338 : xchg   ebx, eax;ret;                                 # ebx, eax = eax, ebx
Gadget @ 0x00401339 : ret;                                                 # nop
Gadget @ 0x0040133A : xchg   rcx, rax;ret;                                 # rcx, rax = rax, rcx
Gadget @ 0x0040133B : xchg   ecx, eax;ret;                                 # ecx, eax = eax, ecx
Gadget @ 0x0040133C : ret;                                                 # nop
Gadget @ 0x0040133D : xchg   rcx, rbx;ret;                                 # rbx, rcx = rcx, rbx
Gadget @ 0x0040133E : xchg   ecx, ebx;ret;                                 # ebx, ecx = ecx, ebx
Gadget @ 0x00401340 : ret;                                                 # nop
Gadget @ 0x00401341 : mov    rax, rsp;ret;                                 # rax = rsp
Gadget @ 0x00401342 : mov    eax, esp;ret;                                 # eax = esp
Gadget @ 0x00401344 : ret;                                                 # nop
Gadget @ 0x0040134E : pop    rax;pop    rax;pop    rax;ret;                # rax = {pop} && rax = {pop} && rax = {pop}
Gadget @ 0x00401350 : pop    rax;ret;                                      # rax = {pop}
Gadget @ 0x00401351 : ret;                                                 # nop
Gadget @ 0x00401352 : xchg   rsi, rax;ret;                                 # rsi, rax = rax, rsi
Gadget @ 0x00401353 : xchg   esi, eax;ret;                                 # esi, eax = eax, esi
Gadget @ 0x00401354 : ret;                                                 # nop
Gadget @ 0x00401355 : mov    rcx, rax;ret;                                 # rcx = rax
Gadget @ 0x00401357 : rol    ebx, 0x48;mov    ebx, ecx;ret;                # rol ebx, 0x48 && ebx = ecx
Gadget @ 0x00401358 : ret;                                                 # nop
Gadget @ 0x00401359 : mov    rbx, rcx;ret;                                 # rbx = rcx
Gadget @ 0x0040135A : mov    ebx, ecx;ret;                                 # ebx = ecx
Gadget @ 0x0040135D : mov    rax, QWORD PTR [rbx];ret;                     # rax = *rbx
Gadget @ 0x00401361 : mov    rbx, QWORD PTR [rax];ret;                     # rbx = *rax
Gadget @ 0x00401363 : sbb    bl, al;mov    rcx, QWORD PTR [rax];ret;       # bl -= al (borrow) && rcx = *rax
Gadget @ 0x00401364 : ret;                                                 # nop
Gadget @ 0x00401365 : mov    rcx, QWORD PTR [rax];ret;                     # rcx = *rax
Gadget @ 0x00401367 : or     bl, al;mov    QWORD PTR [rax], rcx;ret;       # bl |= al && *rax = rcx
Gadget @ 0x00401368 : ret;                                                 # nop
Gadget @ 0x00401369 : mov    QWORD PTR [rax], rcx;ret;                     # *rax = rcx
Gadget @ 0x0040136C : ret;                                                 # nop
Gadget @ 0x0040136D : mov    QWORD PTR [rax], rbx;ret;                     # *rax = rbx
Gadget @ 0x00401370 : ret;                                                 # nop
Gadget @ 0x00401371 : mov    QWORD PTR [rbx], rax;ret;                     # *rbx = rax
Gadget @ 0x00401374 : ret;                                                 # nop
Gadget @ 0x00401375 : sete   al;ret;                                       # al = ZF
Gadget @ 0x00401376 : xchg   esp, eax;rol    bl, 0x48;cmove  eax, ebx;ret; # esp, eax = eax, esp && rol bl, 0x48 && if ZF : eax = ebx
Gadget @ 0x00401377 : rol    bl, 0x48;cmove  eax, ebx;ret;                 # rol bl, 0x48 && if ZF : eax = ebx
Gadget @ 0x00401378 : ret;                                                 # nop
Gadget @ 0x00401379 : cmove  rax, rbx;ret;                                 # if ZF : rax = rbx
Gadget @ 0x0040137B : rex.R ret;ret;                                       # nop
Gadget @ 0x0040137C : ret;                                                 # nop
Gadget @ 0x0040137D : ret;                                                 # nop
Gadget @ 0x0040137E : setl   al;ret;                                       # al = LESS
Gadget @ 0x00401380 : rol    bl, 0x48;cmovl  eax, ebx;ret;                 # rol bl, 0x48 && if LESS : eax = ebx
Gadget @ 0x00401382 : cmovl  rax, rbx;ret;                                 # if LESS : rax = rbx
Gadget @ 0x00401383 : cmovl  eax, ebx;ret;                                 # if LESS : eax = ebx
Gadget @ 0x00401384 : rex.WR ret;ret;                                      # nop
Gadget @ 0x00401385 : ret;                                                 # nop
Gadget @ 0x00401386 : ret;                                                 # nop
Gadget @ 0x00401387 : sets   al;ret;                                       # al = SIGN
Gadget @ 0x00401389 : rol    bl, 0x48;cmovs  eax, ebx;ret;                 # rol bl, 0x48 && if SIGN : eax = ebx
Gadget @ 0x0040138A : ret;                                                 # nop
Gadget @ 0x0040138D : rex.W ret;ret;                                       # nop
Gadget @ 0x0040138E : ret;                                                 # nop
Gadget @ 0x0040138F : ret;                                                 # nop
Gadget @ 0x00401391 : xchg   edx, eax;rol    bl, 0x48;cmovb  eax, ebx;ret; # edx, eax = eax, edx && rol bl, 0x48 && if BELOW : eax = ebx
Gadget @ 0x00401393 : ret;                                                 # nop
Gadget @ 0x00401394 : cmovb  rax, rbx;ret;                                 # if BELOW : rax = rbx
Gadget @ 0x00401396 : rex.X ret;ret;                                       # nop
Gadget @ 0x00401398 : ret;                                                 # nop
Gadget @ 0x0040139C : ret;                                                 # nop
Gadget @ 0x004013A1 : ret;                                                 # nop
Gadget @ 0x004013A5 : ret;                                                 # nop
Gadget @ 0x004013A8 : add    eax, ebx;add    rax, rbx;ret;                 # eax += ebx && rax += rbx
Gadget @ 0x004013A9 : ret;                                                 # nop
Gadget @ 0x004013AA : add    rax, rbx;ret;                                 # rax += rbx
Gadget @ 0x004013AB : add    eax, ebx;ret;                                 # eax += ebx
Gadget @ 0x004013AE : xor    rax, rbx;ret;                                 # rax ^= rbx
Gadget @ 0x004013AF : xor    eax, ebx;ret;                                 # eax ^= ebx
Gadget @ 0x004013B1 : ret;                                                 # nop
Gadget @ 0x004013B4 : ret;                                                 # nop
Gadget @ 0x004013B6 : ret;                                                 # nop
Gadget @ 0x004013B7 : pop    rbx;ret;                                      # rbx = {pop}
Gadget @ 0x004013B9 : pop    rcx;ret;                                      # rcx = {pop}
Gadget @ 0x004013BA : ret;                                                 # nop
Gadget @ 0x004013BE : ret;                                                 # nop
Gadget @ 0x004013C0 : ret;                                                 # nop
Gadget @ 0x004013C1 : pop    rsi;ret;                                      # rsi = {pop}
Gadget @ 0x004013C2 : ret;                                                 # nop
Gadget @ 0x004013C3 : pop    rdi;ret;                                      # rdi = {pop}
Gadget @ 0x004013C4 : ret;                                                 # nop
Gadget @ 0x004013C7 : ret;                                                 # nop
Gadget @ 0x004013CA : ret;                                                 # nop
Gadget @ 0x004013CC : pop    rdx;ret;                                      # rdx = {pop}
Gadget @ 0x004013D0 : ret;                                                 # nop
Gadget @ 0x004013D3 : ret;                                                 # nop
Gadget @ 0x004013DF : ret;                                                 # nop
Gadget @ 0x0040143E : pop    r13;pop    r14;pop    r15;ret;                # r13 = {pop} && r14 = {pop} && r15 = {pop}
Gadget @ 0x0040143F : pop    rbp;pop    r14;pop    r15;ret;                # rbp = {pop} && r14 = {pop} && r15 = {pop}
Gadget @ 0x00401444 : ret;                                                 # nop
Gadget @ 0x00401445 : data16 nop WORD PTR cs:[rax+rax*1+0x0];endbr64;ret;  # endbr64
Gadget @ 0x00401446 : nop    WORD PTR cs:[rax+rax*1+0x0];endbr64;ret;      # endbr64
Gadget @ 0x00401447 : nop    DWORD PTR cs:[rax+rax*1+0x0];endbr64;ret;     # endbr64
Gadget @ 0x00401450 : endbr64;ret;                                         # endbr64
```
Now we can combine those cleaned gadgets with our previous dump of the rop chain for having some form of pseudocode :
```python
import struct
import sys

g = {}

with open("gadgets.txt","r") as g_f:
    gadgets = g_f.read().split("\n")
    for l in gadgets:
        if l == "":
            continue
        addr = int(l.split("@")[1].split(":")[0].strip(), 16)
        dissas = l.split("#")[1].strip()
        dissas = [d.strip() for d in dissas.split("&&")]
        g[addr] = dissas

stack = []

with open("rop_chain.txt", "r") as r_f:
    r_txt = r_f.read().split("\n")
    for l in r_txt:
        if l == "":
            continue
        if "gadget" in l:
            addr = int(l.split(":")[1].strip(), 16)
            stack.append((False, addr))
        else:
            stack.append((True, l.strip()))

current_pc = 0
def pop():
    global current_pc
    global stack
    v = stack[0]
    stack = stack[1:]
    current_pc += 8
    return v

while True:
    print("0x%08X : " % current_pc, end="")
    if current_pc & 0xfff == 0:
        print(hex(current_pc), file=sys.stderr)
    p = pop()
    if p[0]:
        print(p[1])
    else:
        d = g[p[1]]
        first = True
        for i in d:
            if "{pop}" in i:
                a = pop()
                i = i.replace("{pop}", f"{a}")
            if first:
                print(i)
                first = False
            else:
                print(" " * 13 + i)
```
Okay, I admit it's hideous, but it's only for a single use and it should get the work done.
```console
$ time python3 disass_rop.py > /dev/null
real	9m23.878s
user	9m22.004s
sys	0m0.067s
```
Well not only it's hideous, it's also slow. There are probably way better ways to do this but I'm lazy and I was doing something else when I ran this. We shouldn't have to reuse it anyway.
(Notice that for the purpose of the WU I wrote to `/dev/null`, writing in a file was probably way slower).

Just for the sake of it I rewrote `pop` properly :
```python
def pop():
    global current_pc
    v = stack[current_pc // 8]
    current_pc += 8
    return v
```
```console
$ time python3 disass_rop.py > /dev/null
real	0m0.599s
user	0m0.577s
sys	0m0.020s
```
I'm still wondering how I'm able to solve that challenge when I don't even have basic algorithmic skills.

The output we got is huge (around 25k lines long) and should probably not be analyzed manually.
The first place I went to was the few uses of the gadget with the `syscall` instruction. This is where our I/O should be handled. Only 3 syscalls are used `read`, `write` and `exit` moreover `read` and `write` always uses a buffer that is 1 byte long.
Poking around in this mess reveal something quite interesting, the same addresses are used over and over again, it's like it had been compiled from an other instruction set and these addresses correspond to where the registers are stored.

We ~~should~~ could write an other disassembler, but I didn't want to, why not go the dynamic route ?

# III - Emulating and tracing the binary

I used [Unicorn](https://www.unicorn-engine.org/) for emulating the binary. Because the only real interactions the code has with the kernel are these simple syscalls, it's quite easy to do :
```python
import sys
import tty
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
# mu.mem_map(0x004010c0, 0x00395) # text
mu.mem_map(0x00401000, 0x01000)   # text
# mu.mem_map(0x00404060, 0x00410010) # data
mu.mem_map(0x00404000, 0x00411000)   # data
# mu.mem_map(0x00814080, 0x060) # bss

with open("ropfuscated", "rb") as f:
    f.seek(0x000010c0)
    mu.mem_write(0x004010c0, f.read(0x00395))
    f.seek(0x00003060)
    mu.mem_write(0x00404060, f.read(0x00410010))


log_file = open("unicorn.log", "w")

def hook_syscall(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 1:
        b = mu.mem_read(mu.reg_read(UC_X86_REG_RSI), 1)
        sys.stdout.buffer.write(b)
        sys.stdout.buffer.flush()
    elif rax == 0:
        b = sys.stdin.buffer.read(1)
        mu.mem_write(mu.reg_read(UC_X86_REG_RSI), b)
    else:
        print("syscall", rax)

def hook_ret(mu, address, size, user_data):
    if size != 1:
        return
    if mu.mem_read(address, 1) != b"\xc3":
        return

    rsp = mu.reg_read(UC_X86_REG_RSP)
    rip = mu.reg_read(UC_X86_REG_RIP)
    rax = mu.reg_read(UC_X86_REG_RAX)
    rbx = mu.reg_read(UC_X86_REG_RBX)
    rcx = mu.reg_read(UC_X86_REG_RCX)
    rdx = mu.reg_read(UC_X86_REG_RDX)
    rsi = mu.reg_read(UC_X86_REG_RSI)
    rdi = mu.reg_read(UC_X86_REG_RDI)
    log_file.write(("%016X " * 8 % (rip, rax, rbx, rcx, rdx, rsi, rdi, rsp - 0x00414070)) + "\n")

mu.reg_write(UC_X86_REG_RSP, 0x00414070)

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
mu.hook_add(UC_HOOK_CODE, hook_ret)

tty.setraw(0)
mu.emu_start(0x00401318, 0x402000)
```
The details about the ELF file were hardcoded after being extracted with the `readelf` tool from `binutils`. Because x86 uses pages of 4KiB, the sections had to be expanded to be aligned.

We can now run the script, painfully draw a pattern with the program running a hundred times slower and get 300MiB of traces !

# IV - The length check

I ran the emulation multiple times with different patterns, with only 1 dot in each, and used `vim -d` for diffing them. No differences between the traces stand out.
This is when I started using traces of patterns with different lengths, now something interesting is visible at the end of the diff.

```diff
 0000000000401351 000000000040409C 00000000004040B4 000000000000048C 0000000000000001 0000000000404094 0000000000000001 000000000023E508
 0000000000401368 000000000040409C 0000000000404018 000000000000000A 0000000000000001 0000000000404094 0000000000000001 000000000023E510
 00000000004013B8 000000000040409C 0000000000404094 000000000000000A 0000000000000001 0000000000404094 0000000000000001 000000000023E520
-                 0000000000000003
-                                  0000000000000003
-                                  0000000000000003
-                                  0000000000000003
-                                  0000000000000003
+                 0000000000000007
+                                  0000000000000007
+                                  0000000000000007
+                                  0000000000000007
+                                  0000000000000007
 00000000004013B8 0000000000000000 0000000000404094 000000000000000A 0000000000000001 0000000000404094 0000000000000001 000000000023E560
 0000000000401374 0000000000000000 0000000000404094 000000000000000A 0000000000000001 0000000000404094 0000000000000001 000000000023E568
 0000000000401351 0000000000000000 0000000000404094 000000000000000A 0000000000000001 0000000000404094 0000000000000001 000000000023E578
```
(It's difficult to make things stand out in markdown so I edited all the diffs to only keep the registers that are different.)

Looks like the length of the input is used in some way here. Let's take a look at the pseudocode between 0x23E508 and 0x23E578.
```
0x0023E508 : bl -= al (borrow)
             rcx = *rax
0x0023E510 : rbx = (True, 'data @ 0x00404094')
0x0023E520 : rax = *rbx
0x0023E528 : rbx, rax = rax, rbx
0x0023E530 : cmp rcx, rbx
0x0023E538 : rax = (True, 'data : 0x00000000')
0x0023E548 : al = ZF
0x0023E550 : rbx = (True, 'data @ 0x00404094')
0x0023E560 : *rbx = rax
0x0023E568 : rax = (True, 'data : 0x00000000')
0x0023E578 : rbx = (True, 'data @ 0x00404074')
```
`cmp rcx, rbx` looks interesting. When `rsp` is 0x0023E530 `rbx` is our input length and `rcx` is 0xA. Let's try inputting a pattern of length 10.

Running it with the emulator makes it quite obvious because now we have to wait way longer before obtaining the message of failure. We can assume the check is only performed after this comparaison when the input is 10 dot long.

To make it easier to manipulate the traces, we can reduce them by recording only after rsp hit `0x0023E530`. Simply edit the emulation script :
```python
log_file = open("uni_test.log", "w")
is_recording = False

...

def hook_ret(mu, address, size, user_data):
    global is_recording

    if size != 1:
        return
    if mu.mem_read(address, 1) != b"\xc3":
        return

    rsp = mu.reg_read(UC_X86_REG_RSP)
    if rsp == 0x06525A0:
        is_recording = True
    if not is_recording:
        return

...
```

# V - The part where I guess way to much

So now is the part where I guess a lot of stuff. I spent hours on this.

I will talk about the important parts because I just can't talk about everything I tried and even if I could, I can't remember and didn't note what was useless.

## V.I - Input packing

The first easy to spot part is the "packing" of our inputs :
```diff
 0000000000401351 0000000000404074 0000000000404070 FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3C0
 0000000000401364 0000000000404074 FFFFFFFFFFA08D5C FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3C8
 0000000000401351 0000000000404094 FFFFFFFFFFA08D5C FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
-                                                   0000000000000001
-                                                   0000000000000001
-                                  0000000000000001 0000000000000001
-                 FFFFFFFFFFA08D5D 0000000000000001 0000000000000001
-                 FFFFFFFFFFA08D5D                  0000000000000001
-                 FFFFFFFFFFA08D5D                  0000000000000001
-                                                   0000000000000001
-                                                   0000000000000001
-                                                   0000000000000001
-                                                   0000000000000001
-                                                   0000000000000001
-                                                   0000000000000001
-                                                   FFFFFFFFFFA08D5D
-                                                   FFFFFFFFFFA08D5D
-                                  FFFFFFFFFFA08D5D FFFFFFFFFFA08D5D
-                 FFFFFFFFFFA08D5E FFFFFFFFFFA08D5D FFFFFFFFFFA08D5D
-                 FFFFFFFFFFA08D5E                  FFFFFFFFFFA08D5D
-                 FFFFFFFFFFA08D5E                  FFFFFFFFFFA08D5D
-                                                   FFFFFFFFFFA08D5D
+                                                   0000000000000003
+                                                   0000000000000003
+                                  0000000000000003 0000000000000003
+                 FFFFFFFFFFA08D5F 0000000000000003 0000000000000003
+                 FFFFFFFFFFA08D5F                  0000000000000003
+                 FFFFFFFFFFA08D5F                  0000000000000003
+                                                   0000000000000003
+                                                   0000000000000003
+                                                   0000000000000003
+                                                   0000000000000003
+                                                   0000000000000003
+                                                   0000000000000003
+                                                   FFFFFFFFFFA08D5F
+                                                   FFFFFFFFFFA08D5F
+                                  FFFFFFFFFFA08D5F FFFFFFFFFFA08D5F
+                 FFFFFFFFFFA08D60 FFFFFFFFFFA08D5F FFFFFFFFFFA08D5F
+                 FFFFFFFFFFA08D60                  FFFFFFFFFFA08D5F
+                 FFFFFFFFFFA08D60                  FFFFFFFFFFA08D5F
+                                                   FFFFFFFFFFA08D5F
 0000000000401368 00000000004040B4 0000000000404094 000000000000048C 0000000000000001 00000000000005C6 0000000000000001 000000000024B4B0
 000000000040133C 000000000000048C 0000000000404094 00000000004040B4 0000000000000001 00000000000005C6 0000000000000001 000000000024B4B8
 00000000004013B8 000000000000048C 00000000004040AC 00000000004040B4 0000000000000001 00000000000005C6 0000000000000001 000000000024B4C8
```
So it looks like our input is added to that `0xFFFFFFFFFFA08D5C` constant and incremented.

We can use grep to check that this part is repeated for each input :
```console
$ grep 000000000024B3D8 unicorn.log
0000000000401351 0000000000404094 FFFFFFFFFFCF05EA FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFA08D5C FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFF81811E FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFF8D5624 FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFD04FD8 FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFDA47C6 FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFC045C7 FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFCF865C FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFCB2A45 FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
0000000000401351 0000000000404094 FFFFFFFFFFBC2C2F FFFFFFFFFFFFFFFF 0000000000000001 00000000000005C6 0000000000000001 000000000024B3D8
```
So it is repeated 10 times, one per dot in our input, with different constants.

## V.II - The unique check

So this is the part where I wasted most of my time, finding that needle in this entire farm is nearly impossible.
I figured this out by starting my input with a 5 in one trace and not a 5 (or a 6) in the second. This is the condition for that needle to become a huge metal pillar.
Now the trace that doesn't begin with a 5 is way bigger, looks like we went further in the check.

A few diff blocks before the new part, we find this block that have values we know very well :
```diff
 0000000000401351 000000000040409C 00000000000004BD 000000000000048A 0000000000000001 0000000000404094 0000000000000001 0000000000259800
 0000000000401368 000000000040409C 0000000000000421 000000000030FA15 0000000000000001 0000000000404094 0000000000000001 0000000000259808
 0000000000401351 0000000000404094 0000000000000421 000000000030FA15 0000000000000001 0000000000404094 0000000000000001 0000000000259818
-                                  FFFFFFFFFFCF05EB
-                                  FFFFFFFFFFCF05EB
-                 0000000000000000 FFFFFFFFFFCF05EB
-                 0000000000000000 FFFFFFFFFFCF05EB 0000000000000000
-                 0000000000000000 0000000000000000 0000000000000000
-                                  0000000000000000 0000000000000000
-                                  0000000000000000 0000000000000000
-                                                   0000000000000000
-                 0000000000000000                  0000000000000000
-                 0000000000000000                  0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
-                                                   0000000000000000
+                                  FFFFFFFFFFCF05F0
+                                  FFFFFFFFFFCF05F0
+                 0000000000000005 FFFFFFFFFFCF05F0
+                 0000000000000005 FFFFFFFFFFCF05F0 0000000000000005
+                 0000000000000005 0000000000000005 0000000000000005
+                                  0000000000000005 0000000000000005
+                                  0000000000000005 0000000000000005
+                                                   0000000000000005
+                 0000000000000005                  0000000000000005
+                 0000000000000005                  0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
+                                                   0000000000000005
 0000000000401368 0000000000404094 000000000000048A 000000000000048A 0000000000000001 0000000000404094 0000000000000001 00000000002598F0
 0000000000401339 000000000000048A 0000000000404094 000000000000048A 0000000000000001 0000000000404094 0000000000000001 00000000002598F8
 000000000040135C 000000000000048A 000000000000048A 000000000000048A 0000000000000001 0000000000404094 0000000000000001 0000000000259900
```
Looks like our transformed input is added to 0x30FA15 and it, somehow, ended the check when we used a 5.
Let's repeat what we did earlier and grep it :
```console
$ grep -n 0000000000259828 -A 1 unicorn_starts_with_5.log
333253:000000000040133C 000000000048B310 FFFFFFFFFFB74CF6 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
333254-00000000004013AD 0000000000000006 FFFFFFFFFFB74CF6 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
336557:000000000040133C 0000000000792F08 FFFFFFFFFF86D0FD 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
336558-00000000004013AD 0000000000000005 FFFFFFFFFF86D0FD 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
339861:000000000040133C 000000000030FA15 FFFFFFFFFFCF05F0 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
339862-00000000004013AD 0000000000000005 FFFFFFFFFFCF05F0 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
$ grep -n 0000000000259828 -A 1 unicorn_doesnt_start_with_5.log
333253:000000000040133C 000000000048B310 FFFFFFFFFFB74CF6 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
333254-00000000004013AD 0000000000000006 FFFFFFFFFFB74CF6 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
336557:000000000040133C 0000000000792F08 FFFFFFFFFF86D0FD 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
336558-00000000004013AD 0000000000000005 FFFFFFFFFF86D0FD 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
339861:000000000040133C 000000000030FA15 FFFFFFFFFFCF05EB 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
339862-00000000004013AD 0000000000000000 FFFFFFFFFFCF05EB 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
343165:000000000040133C 000000000002378E FFFFFFFFFFFDC874 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
343166-00000000004013AD 0000000000000002 FFFFFFFFFFFDC874 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
346469:000000000040133C 000000000006596D FFFFFFFFFFF9A69A 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
346470-00000000004013AD 0000000000000007 FFFFFFFFFFF9A69A 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
349773:000000000040133C 0000000000135198 FFFFFFFFFFECAE6C 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
349774-00000000004013AD 0000000000000004 FFFFFFFFFFECAE6C 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
--
353077:000000000040133C 0000000000375CCC FFFFFFFFFFC8A334 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259828
353078-00000000004013AD 0000000000000000 FFFFFFFFFFC8A334 0000000000404094 0000000000000001 0000000000404094 0000000000000001 0000000000259830
```
Interesting... Looking at the results it looks like our packed input (and some constants ?) are added with other constants and the program will stop checking when the result is not unique.

## V.III - The constants

We now need two kinds of constants :
- The ones that are inserted between our inputs
- The ones that unpacks our inputs

Using grep on traces makes it quite trivial :
```console
$ grep FFFFFFFFFFB74CF6  unicorn.log | head -n 1
00000000004013AD FFFFFFFFFFB74CF6 FFFFFFFFFFB74CF5 FFFFFFFFFFB74CF5 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
$ grep 0000000000246EC0 unicorn.log
00000000004013AD FFFFFFFFFFB74CF6 FFFFFFFFFFB74CF5 FFFFFFFFFFB74CF5 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF86D0FD FFFFFFFFFF86D0FC FFFFFFFFFF86D0FC 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFFDC874 FFFFFFFFFFFDC873 FFFFFFFFFFFDC873 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFF9A69A FFFFFFFFFFF9A699 FFFFFFFFFFF9A699 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFECAE6C FFFFFFFFFFECAE6B FFFFFFFFFFECAE6B 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFC8A334 FFFFFFFFFFC8A333 FFFFFFFFFFC8A333 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD0C0F0 FFFFFFFFFFD0C0EF FFFFFFFFFFD0C0EF 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF984DF1 FFFFFFFFFF984DF0 FFFFFFFFFF984DF0 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD34318 FFFFFFFFFFD34317 FFFFFFFFFFD34317 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFFCBE0D FFFFFFFFFFFCBE0C FFFFFFFFFFFCBE0C 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFA4C236 FFFFFFFFFFA4C235 FFFFFFFFFFA4C235 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFFC531B FFFFFFFFFFFC531A FFFFFFFFFFFC531A 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE66F57 FFFFFFFFFFE66F56 FFFFFFFFFFE66F56 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE5E8B2 FFFFFFFFFFE5E8B1 FFFFFFFFFFE5E8B1 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFDDC62E FFFFFFFFFFDDC62D FFFFFFFFFFDDC62D 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFEE0254 FFFFFFFFFFEE0253 FFFFFFFFFFEE0253 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF92BC54 FFFFFFFFFF92BC53 FFFFFFFFFF92BC53 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFF65ECF FFFFFFFFFFF65ECE FFFFFFFFFFF65ECE 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFCDA8F7 FFFFFFFFFFCDA8F6 FFFFFFFFFFCDA8F6 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE3EEB2 FFFFFFFFFFE3EEB1 FFFFFFFFFFE3EEB1 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF978665 FFFFFFFFFF978664 FFFFFFFFFF978664 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF8D5933 FFFFFFFFFF8D5932 FFFFFFFFFF8D5932 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFEF446C FFFFFFFFFFEF446B FFFFFFFFFFEF446B 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFDB926B FFFFFFFFFFDB926A FFFFFFFFFFDB926A 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD3AF2C FFFFFFFFFFD3AF2B FFFFFFFFFFD3AF2B 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF84F415 FFFFFFFFFF84F414 FFFFFFFFFF84F414 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFC78F9D FFFFFFFFFFC78F9C FFFFFFFFFFC78F9C 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFB873A9 FFFFFFFFFFB873A8 FFFFFFFFFFB873A8 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF8E2A65 FFFFFFFFFF8E2A64 FFFFFFFFFF8E2A64 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE448C1 FFFFFFFFFFE448C0 FFFFFFFFFFE448C0 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE2A717 FFFFFFFFFFE2A716 FFFFFFFFFFE2A716 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD0B42F FFFFFFFFFFD0B42E FFFFFFFFFFD0B42E 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFFB7BA8 FFFFFFFFFFFB7BA7 FFFFFFFFFFFB7BA7 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE5E788 FFFFFFFFFFE5E787 FFFFFFFFFFE5E787 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF869AD0 FFFFFFFFFF869ACF FFFFFFFFFF869ACF 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD34331 FFFFFFFFFFD34330 FFFFFFFFFFD34330 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFAFDA36 FFFFFFFFFFAFDA35 FFFFFFFFFFAFDA35 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFA4B86D FFFFFFFFFFA4B86C FFFFFFFFFFA4B86C 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFCF06F5 FFFFFFFFFFCF06F4 FFFFFFFFFFCF06F4 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFB7934D FFFFFFFFFFB7934C FFFFFFFFFFB7934C 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFC6F2EB FFFFFFFFFFC6F2EA FFFFFFFFFFC6F2EA 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFBF96E8 FFFFFFFFFFBF96E7 FFFFFFFFFFBF96E7 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE0138E FFFFFFFFFFE0138D FFFFFFFFFFE0138D 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFABF475 FFFFFFFFFFABF474 FFFFFFFFFFABF474 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF98F0F3 FFFFFFFFFF98F0F2 FFFFFFFFFF98F0F2 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFB1F608 FFFFFFFFFFB1F607 FFFFFFFFFFB1F607 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF881780 FFFFFFFFFF88177F FFFFFFFFFF88177F 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF9AB5C2 FFFFFFFFFF9AB5C1 FFFFFFFFFF9AB5C1 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFED3CE7 FFFFFFFFFFED3CE6 FFFFFFFFFFED3CE6 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFF046A4 FFFFFFFFFFF046A3 FFFFFFFFFFF046A3 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE61E5A FFFFFFFFFFE61E59 FFFFFFFFFFE61E59 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF9C263B FFFFFFFFFF9C263A FFFFFFFFFF9C263A 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE69F2C FFFFFFFFFFE69F2B FFFFFFFFFFE69F2B 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD1A346 FFFFFFFFFFD1A345 FFFFFFFFFFD1A345 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD6E424 FFFFFFFFFFD6E423 FFFFFFFFFFD6E423 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFE1DCF1 FFFFFFFFFFE1DCF0 FFFFFFFFFFE1DCF0 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFA18DC4 FFFFFFFFFFA18DC3 FFFFFFFFFFA18DC3 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFA42D7B FFFFFFFFFFA42D7A FFFFFFFFFFA42D7A 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF88F859 FFFFFFFFFF88F858 FFFFFFFFFF88F858 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFF615FE FFFFFFFFFFF615FD FFFFFFFFFFF615FD 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFCF4A92 FFFFFFFFFFCF4A91 FFFFFFFFFFCF4A91 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF8A7906 FFFFFFFFFF8A7905 FFFFFFFFFF8A7905 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFC76188 FFFFFFFFFFC76187 FFFFFFFFFFC76187 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF95AAD9 FFFFFFFFFF95AAD8 FFFFFFFFFF95AAD8 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFC8B150 FFFFFFFFFFC8B14F FFFFFFFFFFC8B14F 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFDB4CEC FFFFFFFFFFDB4CEB FFFFFFFFFFDB4CEB 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFD08478 FFFFFFFFFFD08477 FFFFFFFFFFD08477 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF8945B4 FFFFFFFFFF8945B3 FFFFFFFFFF8945B3 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFC9E461 FFFFFFFFFFC9E460 FFFFFFFFFFC9E460 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFFA10DDC FFFFFFFFFFA10DDB FFFFFFFFFFA10DDB 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
00000000004013AD FFFFFFFFFF8951C6 FFFFFFFFFF8951C5 FFFFFFFFFF8951C5 0000000000000001 0000000000000050 0000000000000001 0000000000246EC0
```

We can repeat the same process for the other constants :
```console
$ grep 000000000048B310 unicorn.log | head -n 1
0000000000401364 0000000000407174 000000000048B310 0000000000407174 0000000000000001 0000000000404094 0000000000000001 0000000000243220
$ grep 0000000000243220 unicorn.log
0000000000401364 0000000000407174 000000000048B310 0000000000407174 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040716C 0000000000792F08 000000000040716C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407164 000000000030FA15 0000000000407164 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040715C 000000000002378E 000000000040715C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407154 000000000006596D 0000000000407154 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040714C 0000000000135198 000000000040714C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407144 0000000000375CCC 0000000000407144 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040713C 00000000005F72A3 000000000040713C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407134 00000000002F3F18 0000000000407134 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040712C 000000000067B216 000000000040712C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407124 00000000002CBCEB 0000000000407124 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040711C 00000000000341FB 000000000040711C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407114 00000000005B3DCA 0000000000407114 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040710C 000000000003ACE6 000000000040710C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407104 00000000001990AE 0000000000407104 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070FC 00000000001A1754 00000000004070FC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070F4 00000000002239D6 00000000004070F4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070EC 000000000011FDAE 00000000004070EC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070E4 00000000006D43AC 00000000004070E4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070DC 00000000007E7EE1 00000000004070DC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070D4 000000000009A133 00000000004070D4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070CC 000000000032570C 00000000004070CC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070C4 00000000001C1154 00000000004070C4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070BC 00000000006879A3 00000000004070BC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070B4 000000000072A6D4 00000000004070B4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070AC 000000000010BB95 00000000004070AC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 00000000004070A4 0000000000246D9A 00000000004070A4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040709C 00000000002C50D9 000000000040709C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407094 00000000007B0BF1 0000000000407094 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040708C 0000000000387063 000000000040708C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407084 0000000000478C5E 0000000000407084 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040707C 000000000071D5A3 000000000040707C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407074 00000000001BB740 0000000000407074 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040706C 00000000001D58EC 000000000040706C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407064 00000000002F4BD3 0000000000407064 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040705C 000000000004845C 000000000040705C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407054 00000000001A1880 0000000000407054 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040704C 0000000000796532 000000000040704C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407044 00000000002CBCD2 0000000000407044 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040703C 00000000005025CE 000000000040703C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407034 00000000005B4793 0000000000407034 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040702C 000000000030F911 000000000040702C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407024 000000000072A9DB 0000000000407024 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040701C 0000000000486CB8 000000000040701C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407014 0000000000390D1C 0000000000407014 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 000000000040700C 00000000002FB027 000000000040700C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000407004 0000000000406919 0000000000407004 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FFC 00000000001FEC79 0000000000406FFC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FF4 0000000000540B90 0000000000406FF4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FEC 0000000000670F10 0000000000406FEC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FE4 00000000004E09FA 0000000000406FE4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FDC 000000000077E888 0000000000406FDC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FD4 0000000000654A3E 0000000000406FD4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FCC 000000000012C31F 0000000000406FCC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FC4 00000000000FB95F 0000000000406FC4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FBC 000000000025B839 0000000000406FBC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FB4 000000000019E1AB 0000000000406FB4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FAC 00000000003FBA38 0000000000406FAC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406FA4 000000000063D9C7 0000000000406FA4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F9C 00000000001960D4 0000000000406F9C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F94 00000000002E5CBE 0000000000406F94 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F8C 0000000000291BE4 0000000000406F8C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F84 00000000001E2310 0000000000406F84 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F7C 00000000005E723E 0000000000406F7C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F74 00000000005BD28D 0000000000406F74 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F6C 00000000007707AD 0000000000406F6C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F64 000000000009EA03 0000000000406F64 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F5C 000000000030B572 0000000000406F5C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F54 00000000007586FD 0000000000406F54 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F4C 0000000000389E7D 0000000000406F4C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F44 00000000003079A3 0000000000406F44 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F3C 00000000006A5527 0000000000406F3C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F34 0000000000374EB1 0000000000406F34 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F2C 000000000024B314 0000000000406F2C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F24 00000000002F7B8C 0000000000406F24 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F1C 000000000034D5BA 0000000000406F1C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F14 000000000076BA51 0000000000406F14 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F0C 000000000043D3D0 0000000000406F0C 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406F04 0000000000361BA1 0000000000406F04 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406EFC 00000000005EF22A 0000000000406EFC 0000000000000001 0000000000404094 0000000000000001 0000000000243220
0000000000401364 0000000000406EF4 000000000076AE3D 0000000000406EF4 0000000000000001 0000000000404094 0000000000000001 0000000000243220
```

However we need to know which ones are added to our input and which ones to the constants. While looking for those constants I also tried using the pseudocode we produced earlier. It looks like the values used with our input appear two times instead of one :
```console
$ grep 48B310 rop_chain.s
0x001F35A0 : rcx = (True, 'data @ 0x0048B310')
$ grep 792F08 rop_chain.s
0x001F3270 : rcx = (True, 'data @ 0x00792F08')
$ grep 30FA15 rop_chain.s
0x001F2F30 : rax = (True, 'data : 0x0030FA15')
0x002036F0 : rax = (True, 'data : 0x0030FA15')
$ grep 5F72A3 rop_chain.s
0x001F1F50 : rax = (True, 'data @ 0x005F72A3')
0x002070B0 : rax = (True, 'data @ 0x005F72A3')
```

## V.IV - Grouping

Now we need to identify the input that pass the *"unique test"*. First we'll unpack all the constants and insert our input in it :
```
6, 5, X, 2, 7, 4, 0, X, 8, 7, 3, 8, 0, 1, 5, 6, 4, 2, 0, X, 2, 3, 6, 8, 7, 1, 5, 5, 6, 0, 7, 8, 1, 3, 2, 4, 8, 2, 3, 4, 0, 6, X, 5, 7, X, 1, 7, 5, 3, 2, 8, 0, 6, 3, X, 5, X, 2, 0, 4, 8, 1, 2, 8, 6, 1, 4, 3, 5, X, 0, 1, 0, 4, X, 5, X, 2, 6, 3
```

Uhh, it looks like the rule we defined earlier will not work. The program probably forgets its state at one point or another, we can look at the hardcoded values to determine where it does. There are two consecutive 5s at offset 27. When thinking about 27, the first thing that came to my mind was 3*9=27, let's divide in groups of 9 :
```
6, 5, X, 2, 7, 4, 0, X, 8
7, 3, 8, 0, 1, 5, 6, 4, 2
0, X, 2, 3, 6, 8, 7, 1, 5
5, 6, 0, 7, 8, 1, 3, 2, 4
8, 2, 3, 4, 0, 6, X, 5, 7
X, 1, 7, 5, 3, 2, 8, 0, 6
3, X, 5, X, 2, 0, 4, 8, 1
2, 8, 6, 1, 4, 3, 5, X, 0
1, 0, 4, X, 5, X, 2, 6, 3
```
That looks really good, some of our inputs have two possible solutions but if you keep in mind the original situtaion, there are some moves that are impossible with a pattern.

# VI - Conclusion

After using `1 3 4 1 4 7 6 7 8 7` which draws a nice flag, we get rewarded with another flag.
```
Draw pattern with mouse to get flag



         #         #         #
                 ~ ~
               ~   ~
             ~     ~
           ~       ~
         # ~~~~~~~ #         #
                   ~
                   ~
                   ~
                   ~
         # ~~~~~~~ # ~~~~~~~ #
```
```
uiuctf{which_shows_that_rop_is_turing_complete_QED}
```

Just before I solved the challenge (at 0514 CEST on the 1st) a hint was released (at 0205 CEST) about how the challenge was built. The challenge authors used [elvm](https://github.com/shinh/elvm), so my first theory was right, maybe building a proper disassembler would have been faster.

In the end I spent nearly 24 hours on this challenge and wasn't really able to solve any other ones (except for a few really easy reverse) because I wasn't available the second day.

Donc gros GG à tout le reste de l'équipe pour nous avoir propulsé aussi haut dans le classement !
