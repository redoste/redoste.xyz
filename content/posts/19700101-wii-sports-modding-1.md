---
title: "Modding Wii Sports : Part I : Identifying files and creating a debug output"
date: 2020-04-04T00:00:00+02:00
draft: true
tags:
- Wii
- Wii Modding
- Wii Sports
---

A few months ago I saw someone playing *Wii Sports* doing some Golf. This reminded me I always wanted to create custom golf tracks. After a little bit of search, I found out that nobody really did it. [Some people were asking if someone did it](https://www.reddit.com/r/WiiHacks/comments/ec5829/looking_for_wii_sports_golf_mods/) and they were a few attempts on *Wii Sport Resort* ([here](https://youtu.be/aQiqRE5HbYI), [here](https://www.reddit.com/r/WiiHacks/comments/f2lq45/fully_custom_wii_sports_golf_course/) or [here](https://www.reddit.com/r/WiiHacks/comments/f0kt3z/custom_wii_sports_golf_course_poc/)) but I found no real public source code or walkthrought of how to do your own custom golf track on the original *Wii Sports*.

After strugguling for multiples weeks now I will show you my current (slow) progress and I hope I will be able to continue this series of blog posts up until a complete usable mod. The best would be an easy to use tool that allow a convertion of any 3D models into a golf course and an interface on the Wii that allow loading custom tracks from the SD card. For the moment I'm not skilled enough nor I have enough time but maybe writing blog posts will encourage me to continue...

# I - Identifying existing files

The first easy step was to rip the original disc. I own an original *Wii Sports* European disc, it is the second revision that have some bug patched. I used [USBLoaderGX](), it's a custom backup loader that allow to copy discs to an USB drive. It produce a WBFS file, it is a custom file format that only contain usefull part of the ISO, by removing all the padding an image can shrink from 4GiB to a few hundreds MiB (it, of course, depends of the game).

To extract and rebuild WBFS images I used the [*Wiimms ISO Tools* suite](https://wit.wiimm.de/).
```bash
$ # We can easly extract the content of the original image
$ wit X RSPP01.wbfs RSPP01/
*****  wit: Wiimms ISO Tool v3.02a r0 x86_64 - Dirk Clemens - 2020-03-07  *****
wit: EXTRACT 1/1 WBFS:RSPP01.wbfs/#0 -> RSPP01/
$ # And rebuild the modded one after some work
$ wit CP RSPP01.modded/ RSPP01.modded.wbfs
*****  wit: Wiimms ISO Tool v3.02a r0 x86_64 - Dirk Clemens - 2020-03-07  *****
* COPY/SCRUB 1/1 FST:RSPP01.modded/ -> WBFS:RSPP01.modded.wbfs
```

After a little bit of search we can identify two important things:
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

These `carc` files are in fact [*Yaz0*](http://wiki.tockdom.com/wiki/Yaz0) compressed [*U8*](http://wiki.tockdom.com/wiki/U8) archives. An other *Wiimms* tool suite can be used to extract these files: the [*Wiimms SZS Toolset*](https://szs.wiimm.de/).

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

[The `kcl` file format](http://wiki.tockdom.com/wiki/KCL) is same used in the *Mario Kart Wii* game to describe the collision of a the track. We can suppose this one also describe the collision of the golf track. Using `wkclt` from the *Wiimms SZS Toolset*, we can convert the `kcl` into a simple [Wavefront `obj` file](https://en.wikipedia.org/wiki/Wavefront_.obj_file)
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
![glf_course_fc1.obj imported in Blender](/img/19700101-wii-sports-modding-1/fc1_imported_in_blender.png)

Since `wkclt` have been tought for *Mario Kart Wii* the objects are not correctly named but they corresponds to the different kind of ground avaliable in the game (Green, Bunker, etc...) :
![List of objects in Blender](/img/19700101-wii-sports-modding-1/fc1_imported_in_blender_objects_list.png)

## 2 - The `G3D/*.brres` files

## 3 - The `glf_scene_fc1/*.p*` files

## 4 - The `glf_course_fc1.pmp` file

# II - Reverse-engineering the binary

# III - Adding a custom debug output
