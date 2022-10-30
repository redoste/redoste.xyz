---
title: "Modding Wii Sports : Part I : Identifying files and creating a debug output"
date: 2020-04-21T16:00:00+02:00
draft: false
tags:
- Wii
- Wii Modding
- Wii Sports
---

A few months ago I saw someone playing *Wii Sports* doing some Golf. This reminded me I always wanted to create custom golf tracks. After a little bit of search, I found out that nobody really did it. [Some people were asking if someone did it](https://www.reddit.com/r/WiiHacks/comments/ec5829/looking_for_wii_sports_golf_mods/) and they were a few attempts on *Wii Sport Resort* ([here](https://youtu.be/aQiqRE5HbYI), [here](https://www.reddit.com/r/WiiHacks/comments/f2lq45/fully_custom_wii_sports_golf_course/) or [here](https://www.reddit.com/r/WiiHacks/comments/f0kt3z/custom_wii_sports_golf_course_poc/)) but I found no real public source code or walkthrough of how to do your own custom golf track on the original *Wii Sports*.

After struggling for multiples weeks now I will show you my current (slow) progress and I hope I will be able to continue this series of blog posts up until a complete usable mod. The best would be an easy to use tool that allow a conversion of any 3D models into a golf course and a user interface on the Wii that allow loading custom tracks from the SD card. For the moment I'm not skilled enough nor I have enough time but maybe writing blog posts will encourage me to continue...

# I - Identifying existing files

The first easy step was to rip the original disc. I own an original *Wii Sports* European disc, it is the second revision that have some bug patched. I used [USBLoaderGX](https://sourceforge.net/projects/usbloadergx/), it's a backup loader that allow to copy discs to an USB drive. It produces a WBFS file, it is a custom file format that only contain useful part of the ISO, by removing all the padding an image can shrink from 4GiB to a few hundreds of MiB (it, of course, depends of the game).

To extract and rebuild WBFS images I used the [*Wiimms ISO Tools* suite](https://wit.wiimm.de/).
```bash
$ # We can easily extract the content of the original image
$ wit X RSPP01.wbfs RSPP01/
*****  wit: Wiimms ISO Tool v3.02a r0 x86_64 - Dirk Clemens - 2020-03-07  *****
wit: EXTRACT 1/1 WBFS:RSPP01.wbfs/#0 -> RSPP01/
$ # And rebuild the modded one after some work
$ wit CP RSPP01.modded/ RSPP01.modded.wbfs
*****  wit: Wiimms ISO Tool v3.02a r0 x86_64 - Dirk Clemens - 2020-03-07  *****
* COPY/SCRUB 1/1 FST:RSPP01.modded/ -> WBFS:RSPP01.modded.wbfs
```

After a little bit of search, we can identify two important things:
* The `sys/main.dol` file, it is the main game binary in the [DOL format](https://wiibrew.org/wiki/DOL) (the executable format for the Wii and the GameCube)
* The `files/Stage/RPGolScene/` folder, it contains a file per golf track. The name of most of the file is in the form `glf_course_fcX.carc` where `fc` is for *Family Computer* or *Famicom* (the Japanese version of the NES) and the number identify the number of the track it corresponds to in the [1984 *Golf* NES game](https://en.wikipedia.org/wiki/Golf_(1984_video_game)).
```bash
total 17M
1,8M glf_course_E3.carc
258K glf_course_angle.carc
1,6M glf_course_fc1.carc
1,3M glf_course_fc11.carc
1,1M glf_course_fc12.carc
1,8M glf_course_fc13.carc
1,3M glf_course_fc14.carc
1,8M glf_course_fc16.carc
367K glf_course_fc18.carc
1,1M glf_course_fc3.carc
1,6M glf_course_fc5.carc
1,9M glf_course_fc8.carc
1,3M glf_course_fc9.carc
212K glf_course_survey.carc
```

These `carc` files are in fact [*Yaz0*](http://wiki.tockdom.com/wiki/Yaz0) compressed [*U8*](http://wiki.tockdom.com/wiki/U8) archives. Another *Wiimms* tool suite can be used to extract these files: the [*Wiimms SZS Toolset*](https://szs.wiimm.de/).

Here is the content of `glf_course_fc1.carc`:
```bash
$ wszst LL glf_course_fc1.carc

* Files of YAZ0.U8:glf_course_fc1.carc

size/dec  magic file or directory
-------------------------------------------------------------------------------
  687202  ...<  glf_course_fc1.kcl
   10600  PMPF  glf_course_fc1.pmp
       -  -     G3D/
  999424  bres  G3D/glf_course_fc1.brres
  179712  bres  G3D/glf_map_fc1.brres
       -  -     glf_scene_fc1/
     164  PBLM  glf_scene_fc1/glf_scene_fc1.pblm
    1352  LGHT  glf_scene_fc1/glf_scene_fc1.plight
     408  LMAP  glf_scene_fc1/glf_scene_fc1.plmap
```

## 1 - The `glf_course_fc1.kcl` file

[The `kcl` file format](http://wiki.tockdom.com/wiki/KCL) is the same used in the *Mario Kart Wii* game to describe the collision of a the track. We can suppose this one also describe the collision of the golf track. Using `wkclt` from the *Wiimms SZS Toolset*, we can convert the `kcl` into a simple [Wavefront `obj` file](https://en.wikipedia.org/wiki/Wavefront_.obj_file)
```bash
$ wkclt DEC glf_course_fc1.kcl
DECODE KCL:glf_course_fc1.kcl -> KCLTXT:./glf_course_fc1.obj
* CHECK KCL:glf_course_fc1.kcl
    - HINT: 1 of 8398 drivable triangles is face down => --kcl=RM-FACEDOWN
    - HINT: 1 of 8398 drivable triangles is face down (>30°).
 => No warnings and 2 hints for KCL:glf_course_fc1.kcl
 => see https://szs.wiimm.de/cmd/wkclt/check#desc for more info.

$ ll glf_course_fc1.*
-rw-r--r-- 1 redoste redoste 672K 1970-01-01 00:00 glf_course_fc1.kcl
-rw-r--r-- 1 redoste redoste  19K 1970-01-01 00:00 glf_course_fc1.mtl
-rw-r--r-- 1 redoste redoste 911K 1970-01-01 00:00 glf_course_fc1.obj
```
And of course the opposite is possible
```bash
$ wkclt ENC glf_course_fc1.obj
ENCODE KCLTXT:glf_course_fc1.obj -> KCL:./glf_course_fc1.kcl
* CHECK KCLTXT:glf_course_fc1.obj
    - HINT: 1 of 8398 drivable triangles is face down => --kcl=RM-FACEDOWN
    - HINT: 1 of 8398 drivable triangles is face down (>30°).
 => No warnings and 2 hints for KCLTXT:glf_course_fc1.obj
 => see https://szs.wiimm.de/cmd/wkclt/check#desc for more info.

  - create octree: rshift=10, n_bcube=256, cube_size=512..1048576, blow=400, max_tri=30, max_depth=10, fast=0
```

Here is what `glf_course_fc1.obj` looks like imported into Blender :
{{< image "glf_course_fc1.obj imported in Blender" "img/20200421-wii-sports-modding-1/fc1_imported_in_blender.png" >}}

Since `wkclt` have been thought for *Mario Kart Wii* the objects are not correctly named but they correspond to the different kind of ground available in the game (Green, Bunker, etc.) :
{{< image "List of objects in Blender" "img/20200421-wii-sports-modding-1/fc1_imported_in_blender_objects_list.png" >}}

## 2 - The `G3D/*.brres` files

The [`brres` files](http://wiki.tockdom.com/wiki/BRRES_(File_Format)) are some sort of archives that describe a 3D model. This archive is split in sections each one represents a specific part of the object (Model, Texture, Animations...). Since `brres` files are common to *Mario Kart Wii* and *Super Smash Bros. Brawl*, we can use the [*BrawlBox* tool](https://github.com/libertyernie/brawltools).

*BrawlBox* is a huge Windows tool that allow easy manipulation of `brres` archives and its different sections. Because I use GNU/Linux I had to do a little bit of tinkering to run *BrawlBox* with *Wine*. Installing `dotnet48` using `winetricks` seems to do the job.

Here is what `G3D/glf_course_fc1.brres` looks like in BrawlBox :
{{< image "glf_couse_fc1.brres opened in BrawlBox" "img/20200421-wii-sports-modding-1/fc1_course_brres.png" >}}

The other `brres` file: `G3D/glf_map_fc1.brres` corresponds to the minimap visible in game in the bottom left corner. The map in it self is at the exact same scale as the original, it is only scaled down at the final rendering, making the creation of the map from the original course really easy.

Here is what `G3D/glf_map_fc1.brres` looks like in BrawlBox :
{{< image "glf_map_fc1.brres opened in BrawlBox" "img/20200421-wii-sports-modding-1/fc1_map_brres.png" >}}

## 3 - The `glf_scene_fc1/*.p*` files

These three files seem to be used to polish the rendering of the map, but I was able to identify only one of them. The `plight` file seems to match the [BLIGHT format](http://wiki.tockdom.com/wiki/BLIGHT_(File_Format)) since its magic number is the same (`LGHT`). However leaving the folder empty seems to do the trick since the map loads without any problem.

## 4 - The `glf_course_fc1.pmp` file

I was unable to clearly identify the format of the `pmp` file but I think it contains things such as the starting point, the ending point of the course and the position of trees. Its format should be similar to the [KMP format of *Mario Kart Wii*](http://wiki.tockdom.com/wiki/KMP_(File_Format)) since it is its purpose.

## 5 - Demo

The first easy demo I can do is making the map flat. For this I converted the KCL file to an OBJ file and set the Y value of every vertices to 0.

Then I used the scripting feature of BrawlBox to export every objects vertices from the model. The script is based on the builtin one made to export textures.

```python
# Script to export or import objects vertices from brres files
from BrawlBox.API import bboxapi
from BrawlLib.SSBB.ResourceNodes import *

def search(node):
	if isinstance(node, MDL0VertexNode):
		return [node]
	list = []
	for child in node.Children:
		list += search(child)
	return list

if bboxapi.RootNode != None:
	root = bboxapi.RootNode
	for item in search(root):
		print item.Name
		# Use Replace to import and Export to export
		item.Export("C:\\inp\\vec\\" + item.Name + ".vec")
		#item.Replace("C:\\inp\\vec\\" + item.Name + ".vec")
	print("Done!")
else:
	bboxapi.ShowMessage('Cannot find Root Node (is a file open?)','Error')
```

Then I made a (extremely ugly and unreadable) Python script to flatten the object before reimporting them to the `brres`.

```python
import struct
import sys

wo_offset = 0
def wo(b):
    global wo_offset
    wo_offset += len(b)
    sys.stderr.buffer.write(b)

inf = open(sys.argv[1], "rb")

file_length = struct.unpack(">I", inf.read(4))[0]
mdl0_offset = struct.unpack(">I", inf.read(4))[0]
data_offset = struct.unpack(">I", inf.read(4))[0]
name_offset = struct.unpack(">I", inf.read(4))[0]
index       = struct.unpack(">I", inf.read(4))[0]
comp_count  = struct.unpack(">I", inf.read(4))[0]
vec_format  = struct.unpack(">I", inf.read(4))[0]
divisor     = struct.unpack(">B", inf.read(1))[0]
stride      = struct.unpack(">B", inf.read(1))[0]
n_vec       = struct.unpack(">H", inf.read(2))[0]
min_x, min_y, min_z = struct.unpack(">fff", inf.read(12))
max_x, max_y, max_z = struct.unpack(">fff", inf.read(12))

# Check and write the header
wo(struct.pack(">I", file_length))
wo(struct.pack(">I", mdl0_offset))
wo(struct.pack(">I", data_offset))
wo(struct.pack(">I", name_offset))
wo(struct.pack(">I", index))

if comp_count != 0x1:
    print("comp_count != 1")
    sys.exit(1)
wo(struct.pack(">I", comp_count))

if vec_format != 0x4:
    print("vec_format != 4")
    sys.exit(1)
wo(struct.pack(">I", vec_format))

if divisor != 0:
    print("divisor != 0")
    sys.exit(1)
wo(struct.pack(">B", divisor))

if stride != 0xc:
    print("stride != 0xc")
    sys.exit(1)
wo(struct.pack(">B", stride))
print("n_vec = {}".format(n_vec))
wo(struct.pack(">H", n_vec))

print("min = {},{},{}".format(min_x, min_y, min_z))
print("max = {},{},{}".format(max_x, max_y, max_z))
min_y = 0
max_y = 0
print("min = {},{},{}".format(min_x, min_y, min_z))
print("max = {},{},{}".format(max_x, max_y, max_z))
wo(struct.pack(">fff", min_x, min_y, min_z))
wo(struct.pack(">fff", max_x, max_y, max_z))

for _ in range(8):
    wo(b"\x00")
inf.seek(data_offset)

for n in range(n_vec):
    x, y, z = struct.unpack(">fff", inf.read(12))
    print("n = {} : {},{},{}".format(n, x, y, z))
    y = 0
    wo(struct.pack(">fff", x, y, z))

for _ in range(file_length - wo_offset):
    wo(b"\x00")

sys.stderr.buffer.flush()
```

After packing everything back up, we can rebuild the game image and admire this amazing flat golf course with flying trees, starting point and ending point !

{{< image "Screenshot of the first golf course but flat 1" "img/20200421-wii-sports-modding-1/fc1_flat_screenshot_1.png" >}}
{{< image "Screenshot of the first golf course but flat 2" "img/20200421-wii-sports-modding-1/fc1_flat_screenshot_2.png" >}}

# II - Reverse-engineering the binary

The main game binary is in the [DOL format](https://wiibrew.org/wiki/DOL), it's a pretty simple format and was able to open it in Ghidra pretty easily. I'm far from being skilled enough to completely reverse-engineer the binary but using simple string searches and X-refs I was able to identify important functions : reading files, reading archives, loading maps and I think I even identified the one responsible of parsing the unknown `pmp` file.

Here is the list of function identified (for the second European version I own : `sha1sum main.dol : 0328a87d999995f95592f91c8d948d9995bb06bd`)

* `crash` : `0x8010ab58`
* `get_lang_code` : `0x80186410`
* `golf_get_fc_string` : `0x8029db44`
* `golf_load_kcl_pmp` : `0x80293d5c`
* `golf_load_stage_common_carc` : `0x8028eb84`
* `golf_process_kcl?` : `0x802a7414`
* `golf_process_pmp?` : `0x801bf824`
* `golf_process_pmp?2` : `0x801bf890`
* `heap_alloc` : `0x800a2e38`
* `heap_alloc_wraper` : `0x800a3250`
* `load_from_carc` : `0x80187a44`
* `load_from_carc_in_filelist` : `0x8028eb68`
* `load_locales` : `0x801877d0`
* `print_serial` : `0x801840dc`
* `sprintf` : `0x802aaf00`
* `strcat` : `0x800b8e40`

What made the process really hard and sometimes impossible for me is that I don't know a lot PowerPC assembly so I generally blindly trusted Ghidra decompiler and only looked at the manual when required but most importantly this is C++ code, so we have to deal with all the C++ annoying stuff. To make this thing even more hard, Nintendo should use some weird custom compiler because it uses `r13` to store the `this` pointer instead of using the first function argument like any other compilers but most importantly `r13` point to the **end** of the structure ! Ghidra doesn't seem to support looking at structure from the end and having to subtract offsets from the pointer so it just decompiles it to unreadable garbage pointer arithmetic.

Here is my favorite one (from `golf_get_fc_string`) :
```c
return (&PTR_s_fc1_803e1fe0)[*(int *)(*(int *)((int)local_r13_-1 + -0x5abc) + 0x98) * 9];
```

---

**Edit : 2020-04-22 23:20 +0200 :** [u/Leseratte10 mentioned on reddit](https://www.reddit.com/r/WiiHacks/comments/g5nl9j/just_finished_to_write_my_first_blog_post_on_wii/fo5up0d) that `r13` is used for the *Small Data Area*. Because PowerPC is a [RISC](https://en.wikipedia.org/wiki/Reduced_instruction_set_computer) architecture there is a really small number of instructions, something as simple as accessing a global variable can take 2 instructions. To compensate, the compiler put all frequently accessed globals in this *Small Data Area* (here it is 64KiB large) and makes `r13` constant by initialising it in the entry point function. Now globals in the *Small Data Area* can be accessed with only one instruction.

This problem was already discussed in a [Ghidra Github issue](https://github.com/NationalSecurityAgency/ghidra/issues/325). After installing a [custom language definition for the *Gekko* and *Broadway* CPUs](https://github.com/aldelaro5/ghidra-gekko-broadway-lang) and reanalysing the whole binary, the `r13` register is now considered constant. Using the *Register Manager* of Ghidra, we can set the value of `r13` (here it is `0x804df900`) and now decompilation makes way more sense.

Here is the previous snippet of `golf_get_fc_string` correctly decompiled :
```c
return (&PTR_DAT_803e1fe0)[*(int *)(DAT_804d9e44 + 0x98) * 9];
```

The `this` pointer is correctly passed as the first argument of functions (via `r3`).

---

To finish this part on a positive note, some of the code is shared with *Mario Kart Wii* (yes, again) so here is this amazing decompilation project of *Mario Kart Wii* by *riidefi* that helped me a lot : [https://github.com/riidefi/MKWDecompilation](https://github.com/riidefi/MKWDecompilation)

# III - Adding a custom debug output

While working on custom maps, the game crashed, a lot. So to understand why it crashed I generally enabled the Dolphin debugger and followed the backtrace, looking at what functions it corresponds in Ghidra. A lot of this crashes where due to failed `assert`s and the `assert`s called `print_serial` before calling `crash`. This `print_serial` just seems to backup some registers to locals before returning. I think they removed the debug output in the final release.

```asm
print_serial
    stwu       r1,local_70(r1)
    bne        cr1,LAB_80184104
    stfd       f1,local_48(r1)
    stfd       f2,local_40(r1)
    stfd       f3,local_38(r1)
    stfd       f4,local_30(r1)
    stfd       f5,local_28(r1)
    stfd       f6,local_20(r1)
    stfd       f7,local_18(r1)
    stfd       f8,local_10(r1)
LAB_80184104
    stw        r3,local_68(r1)
    stw        r4,local_64(r1)
    stw        r5,local_60(r1)
    stw        r6,local_5c(r1)
    stw        r7,local_58(r1)
    stw        r8,local_54(r1)
    stw        r9,local_50(r1)
    stw        r10,local_4c(r1)
    addi       r1,r1,0x70
    blr
```

To get this debug output working I didn't want to patch the binary since I don't know how to easily output the strings so I just modified the code of the emulator instead !

Since [Dolphin is open source](https://github.com/dolphin-emu/dolphin), it was really easy. I edited the code of the branch instruction to print strings when the destination address is the one of `print_serial`. Because `print_serial` should behave like `printf` and that the memory of the emulated console is only available via functions emulating the memory bus, the easiest thing to do was to create a simple and incomplete `printf` implementation.

```c
// In Source/Core/Core/PowerPC/Interpreter/Interpreter_Branch.cpp
void Interpreter::bx(UGeckoInstruction inst)
{
  if (inst.LK)
    LR = PC + 4;

  if (inst.AA)
    NPC = SignExt26(inst.LI << 2);
  else
    NPC = PC + SignExt26(inst.LI << 2);

  // Here is my incomplete ugly printf implementation
  if (NPC == 0x801840dc) {
    uint32_t gpr3 = PowerPC::ppcState.gpr[3];
    int r = 4;
    char c, t;
    do {
      c = PowerPC::Read_U8(gpr3);
      gpr3++;
      if(c != '%'){
        putc(c, stdout);
        continue;
      }

      t = PowerPC::Read_U8(gpr3);
      gpr3++;
      if(t == 's') {
        uint32_t ptr = PowerPC::ppcState.gpr[r];
        r++;
        char cBis;
        do {
          cBis = PowerPC::Read_U8(ptr);
          ptr++;
          putc(cBis, stdout);
        } while (cBis != 0);
      }
      else if (t == '%'){
        putc('%', stdout);
      }
      else if (t == '0'){
        // Padded format strings : "%08x"
        char formatStr[] = {'%', t, PowerPC::Read_U8(gpr3), PowerPC::Read_U8(gpr3+1)};
        gpr3 += 2;
        printf(formatStr, PowerPC::ppcState.gpr[r]);
        r++;
      }
      else {
        char formatStr[] = {'%', t};
        printf(formatStr, PowerPC::ppcState.gpr[r]);
        r++;
      }

    } while(c != 0);
  }

  m_end_block = true;
}
```

Because I edited the PowerPC interpreter, I had to disable the JIT but the Wii is a pretty modern console, my 7-year-old Intel CPU was pretty slow while trying to interpret the 729 Mhz PowerPC CPU of the Wii. It was unusable. I was not confident while trying to understand the JIT code so I just added a line to disable JIT on branch instruction to `print_serial` :

```c
// In Source/Core/Core/PowerPC/Jit64/Jit_Branch.cpp
void Jit64::bx(UGeckoInstruction inst)
{
  //...
  FALLBACK_IF(js.op->branchTo == 0x801840dc);
  //...
}
```

There are some slowdowns when the game tries to print a lot of stuff but at least it works !

```markdown
<< RVL_SDK - EXI 	release build: Nov 30 2006 03:26:56 (0x4199_60831) >>
<< RVL_SDK - SI 	release build: Nov 30 2006 03:31:44 (0x4199_60831) >>

Revolution OS
Kernel built : Apr 24 2007 11:50:47
Console Type : NDEV 2.1
Firmware     : 21.4.15 (3/3/2010)
Memory 88 MB
MEM1 Arena : 0x804f0fa0 - 0x817fcda0
MEM2 Arena : 0x90000800 - 0x933e0000
<< RVL_SDK - OS 	release build: Apr 24 2007 11:50:47 (0x4199_60831) >>
<< RVL_SDK - SC 	release build: Nov 30 2006 03:33:00 (0x4199_60831) >>
<< RVL_SDK - NAND 	release build: Nov 30 2006 03:32:57 (0x4199_60831) >>
<< RVL_SDK - NWC24 	release build: May 10 2007 17:58:59 (0x4199_60831) >>
<< RVL_SDK - DVD 	release build: Apr 24 2007 11:44:29 (0x4199_60831) >>
<< NW4R    - EF 	final   build: Jun  8 2007 11:16:29 (0x4199_60831) >>
<< RVL_SDK - GX 	release build: Nov 30 2006 03:30:39 (0x4199_60831) >>
<< RVL_SDK - VI 	release build: Nov 30 2006 03:31:49 (0x4199_60831) >>
<< RVL_SDK - WPAD 	release build: May 17 2007 01:52:03 (0x4199_60831) >>
<< RVL_SDK - KPAD 	release build: Jun  5 2007 11:27:45 (0x4199_60831) >>
<< NW4R    - G3D 	final   build: Jun  8 2007 11:16:25 (0x4199_60831) >>
<< NW4R    - LYT 	final   build: Jun  8 2007 11:17:26 (0x4199_60831) >>
<< RVL_SDK - AI 	release build: Nov 30 2006 03:26:11 (0x4199_60831) >>
<< RVL_SDK - AX 	release build: Dec 18 2006 15:43:48 (0x4199_60831) >>
<< RVL_SDK - DSP 	release build: Nov 30 2006 03:26:46 (0x4199_60831) >>
<< NW4R    - SND 	final   build: Jun  8 2007 11:17:15 (0x4199_60831) >>
<< RVL_SDK - RFL 	release build: Jun  9 2007 17:25:33 (0x4199_60831) >>
eggAudioArcPlayerMgr:Sound Archive is already opened
```

# IV - Conclusion

This blog post summarize how far I have been able to mod *Wii Sports*, I hope it will be useful to someone else but a least it useful for me to note my progress and maybe, one day, later, try to do something more complete.

# Comments :
**[Reddit](https://www.reddit.com/user/reDOSte/comments/g5gcao/modding_wii_sports_part_i_identifying_files_and/) or [Twitter](https://twitter.com/redoste/status/1252606484770435072)**
