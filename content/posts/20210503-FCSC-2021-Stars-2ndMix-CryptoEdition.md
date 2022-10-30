---
title: "[FR] Write-up FCSC 2021 : Stars:2ndMix CryptoEdition"
date: 2021-05-03T18:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2021
---

# I - Intro

*Stars:2ndMix CryptoEdition* se compose d'une image d'un disque de *Dreamcast* au format *DiscJuggler*. Ce challenge me semblait intéressant, car j'ai comme une attirance pour les architectures bizares et mal documentées, j'ai notamment précedemment travaillé sur [un debuggeur pour calculatrices Casio](https://github.com/redoste/fx-CG50_Manager_PLUS-gdbserver) qui ont la particularité d'utiliser la même architecuture que la Dreamcast (SuperH 4).

Il nous est indiqué dans la description du challenge que celui avait été testé avec [Flycast](https://github.com/flyinghead/flycast), on télécharge donc le code source et on utilise `cmake` pour le compiler. On peut ensuite l'executer et ouvrir l'image disque fournie.

{{< image "Zone de texte du flag" "img/20210503-FCSC-2021-Stars-2ndMix-CryptoEdition/Stars-2ndMix-CryptoEdition-001.png" >}}

Après nous avoir accueilli (sous fond de superbe chiptune), on nous invite alors à rentrer un flag au format `FCSC{0123456789ABCDEF}` et le programme nous indique si celui-ci est valide ou non.

# II - Extraction de `1ST_READ.bin`

Tout d'abbord, il faut extraire l'executable de l'image. Après un peu de recherche on trouve *[GDRom Explorer](https://www.romhacking.net/utilities/1459/)* qui permet notament de naviguer dans les images au format *DiscJuggler*. On extrait alors `1ST_READ.BIN`, il s'aggit du binaire principal du programme, celui-ci est precedemment chargé par `IP.BIN` à l'adresse `0x8c010000` avant de simplement sauter au debut de celui-ci.

Après l'avoir extrait, on l'importe comme un binaire brut dans Ghidra en indiquant l'adresse de base, l'architecuture (SuperH 4) et l'endianness (petit). On indique que l'entry point est à `0x8c010000` et on lance l'analyse. Le problème c'est que celle-ci est extremement rapide et ne semble avoir trouvé que quelques fonctions. Les strings sont lisibles et le code semble avoir du sens, mais les instructions au debut du binaire ne semblent pas appropriées. Comme si le binaire était mélangé.

Après un peu de recherche sur les problèmes d'extractions de `1ST_READ.bin`, je tombe sur un mot qui me rappelle quelque chose. "*scramble*". En effet j'avais vu [une vidéo sur YouTube de *Modern Vintage Gamer*](https://youtu.be/rj56VU_VmWg) à propos de la protection anti-copie de la Dreamcast et il y est expliqué que lorsque le jeu est chargé depuis un CD-ROM et non un GD-ROM, `1ST_READ.BIN` est mélangé lors de son chargement en mémoire.

On trouve alors *[Binary Checker](https://github.com/sizious/binary-checker)* qui a la capacité de remettre en ordre `1ST_READ.BIN`. On peut ensuite le réimporter dans Ghidra, relancer une analyse et y trouver un déassemblage qui a du sens.

# III - Reverse engineering du binaire

Comme dans toute bonne rétro-ingénierie, il faut commencer par la fin. On recherche donc les strings `"YOU FAILED"` et `"YOU WIN!"`. D'après les XREFs, celles-ci ne sont utilisées que par une fonction.

Ghidra nous donne une plutôt bonne décompilation de celle-ci et on peut se concentrer sur la partie responsable du choix de l'une ou de l'autre chaine.
```c
if (current_step == 0x12) {
  *current_step_ptr = 0x13;
  iVar5 = (*(code *)send_flag_to_ARM)(0x10,user_input_ptr);
  if (iVar5 == 0) {
    iVar14 = (int)DAT_8c010ef2;
    iVar5 = (int)DAT_8c010ef4;
    *current_step_ptr = *current_step_ptr + 1;
    choosen_message = PTR_s_Checking..._8c010f08;
    (*(code *)PTR_send_ARM_order_1_8c010f34)(DAT_8c010f38,iVar5,iVar14);
    goto LAB_8c010dea;
  }
}
else {
  choosen_message = PTR_s_YOU_FAILED_8c010f24;
  if ((current_step == 0x13) || (choosen_message = PTR_s_YOU_WIN!_8c010f20, current_step == 0x14))
    goto LAB_8c010dea;
}
```
Le message de succès sera donc choisi si la fonction que j'ai nommée `send_flag_to_ARM` renvoie 0. Celle-ci prend en paramètre un entier et un pointeur, avec le contexte on peut deviner que 0x10 correspond à la taille du flag et que le pointeur correspond à l'entrée de l'utilisateur.

```c
int send_flag_to_ARM(int len,char *buf) {
  char cVar1;
  char *pcVar3;
  char *iVar4;

  iVar4 = 0xa080ff00;
  *(int *)(iVar4 + 0xc) = len;
  pcVar3 = iVar4 + 0x10;
  if (len != 0) {
    do {
      cVar1 = *buf;
      buf = buf + 1;
      len = len + -1;
      *pcVar3 = cVar1;
      pcVar3 = pcVar3 + 1;
    } while (len != 0);
    iVar4 = 0xa080ff00;
  }
  *(undefined4 *)(iVar4 + 8) = 4;
  do {
  } while (*(int *)(iVar4 + 8) != 0);
  return *(int *)(iVar4 + 0xc);
}
```
Suite à mon experience passée avec SuperH, l'utilisation d'une adresse qui commence par `0xa`, qui signifie que l'accès à la mémoire ne passe pas par le cache, me fait penser à l'utilisation d'un periphérique. De plus, après avoir écrit `4` à `0xa080ff08`, on boucle en attendant que celle-ci repasse à `0`, cela semble être l'action d'un autre bout de silicium.

Après m'être perdu dans les tréfonds de Google, je n'ai pas réussi à mettre la main sur une liste des périphériques de la Dreamcast. Donc comme dit le vieil adage :

> La meilleure documentation est le code source lui-même

Donc j'ai commencé à grepper plusieurs termes dans le code source de Flycast. Après un peu de recherche je tombe sur cette table dans `core/hw/mem/_vmem.cpp` :
```c
const vmem_mapping mem_mappings[] = {
  // P0/U0
  {0x00000000, 0x00800000,                       0,         0, false},  // Area 0 -> unused
  {0x00800000, 0x01000000,    MAP_ARAM_START_OFFSET, ARAM_SIZE, true},  // Aica
  {0x01000000, 0x02800000,                       0,         0, false},  // unused
  {0x02800000, 0x03000000,    MAP_ARAM_START_OFFSET, ARAM_SIZE, true},  // Aica mirror
  {0x03000000, 0x04000000,                       0,         0, false},  // unused
  {0x04000000, 0x05000000,    MAP_VRAM_START_OFFSET, VRAM_SIZE, true},  // Area 1 (vram, 16MB, wrapped on DC as 2x8MB)
  {0x05000000, 0x06000000,                       0,         0, false},  // 32 bit path (unused)
  {0x06000000, 0x07000000,    MAP_VRAM_START_OFFSET, VRAM_SIZE, true},  // VRAM mirror
  {0x07000000, 0x08000000,                       0,         0, false},  // 32 bit path (unused) mirror
  {0x08000000, 0x0C000000,                       0,         0, false},  // Area 2
  {0x0C000000, 0x10000000,    MAP_RAM_START_OFFSET,  RAM_SIZE,  true},  // Area 3 (main RAM + 3 mirrors)
  {0x10000000, 0x80000000,                       0,         0, false},  // Area 4-7 (unused)
};
```
Si on ignore le `0xa` de l'adresse indiquée precedemment (qui ne sert qu'à indiquer que l'on écrit dans P2 sans cache), on écrirait donc à `0xff00` dans la RAM de l'AICA.

# IV - l'AICA

L'AICA est le sous-système sonore de la Dreamcast développé par Yamaha, il est principalement composé d'un processeur ARM v7 et de 2MiB de RAM. Ces 2MiB de RAM sont donc accessibles par le processeur SuperH de `0x00800000` à `0x00a00000`.

Pour comprendre comment cette comparaison est faite, il faudrait pouvoir dump le contenu de cette RAM pour pouvoir déassembler et décompiler le code ARM. Celui-ci devrait être écrit par le code SuperH mais pour cela il faut identifier où et quand cela ce passe. Pour être honnête je sens arriver de la crypto complexe à grands pas et je n'ai pas du tout l'envie de chercher à comprendre ça, j'ai donc sorti GDB.

En effet, en ayant compilé Flycast avec les options par défaut de cmake, le binaire produit possède les informations de debug DWARF, on peut donc utiliser GDB avec le confort de pouvoir lire les variables avec leur vrai nom et non leur adresse (entre autres).
```c
// core/hw/aica/aica_if.cpp
VArray2 aica_ram;

// core/stdclass.h
class VArray2 {
public:
  u8* data;
  unsigned size;

  // ...
};
```

```
$ gdb ./build/flycast
gef>  handle SIGSEGV noprint nostop
Signal        Stop	Print	Pass to program	Description
SIGSEGV       No	No	Yes		Segmentation fault
gef>  run ../Stars2ndMix_CryptoEdition.cdi
^C
Thread 1 "flycast" received signal SIGINT, Interrupt.
0x00007ffff74c71b7 in ioctl () at ../sysdeps/unix/syscall-template.S:120
gef>  print aica_ram
'aica_ram' has unknown type; cast it to its declared type
gef>  print &aica_ram
$1 = (<data variable, no debug info> *) 0x555556b741f0 <aica_ram>
gef>  x/2gx 0x555556b741f0
0x555556b741f0 <aica_ram>:	0x00007fff5c7f0000	0x0000000000200000
gef>  dump memory ../aica.bin 0x00007fff5c7f0000 (0x00007fff5c7f0000+0x0000000000200000)
```
Pour des raisons qui me sont inconnues, GDB a refusé de completement coopérer et n'a pas voulu parser le `VArray2`. Cette structure étant extremement simple, je l'ai donc interprétée moi-même. Après avoir trouvé l'adresse de la RAM de l'AICA, on peut utiliser `dump memory` pour écrire dans un fichier le contenu de celle-ci.

On peut maintenant importer le fichier `aica.bin` dans Ghidra, de la même manière que pour `1ST_READ.BIN`, on l'importe comme un binaire brut, chargé à l'adresse `0` en ARM v7 little-endian.

Après analyse, on peut se rendre à l'adresse où le résultat de la verification est écrit, `0xa080ff0c` pour le SuperH correspond à `0xff0c` dans l'espace d'adresse de l'ARM. En suivant les XREFs, on voit que celle-ci peut être écrite à deux endroits, en fonction de la valeur écrite en `0xa080ff08`, une fonction ou une autre est appelée et son résultat est écrit en `0xa080ff0c`. On peut donc supposer que `0xa080ff08` est utilisée pour communiquer un numéro d'action à effectuer.
```c
char *SH_registers = 0xff00;
switch(*(int *)(SH_registers + 8)) {
case 0:
  break;
case 1:
  // ...
  break;
case 2:
  SH_order_2();
  *(int *)(SH_registers + 8) = 0;
  break;
case 3:
  uVar4 = SH_order_3();
  *(int *)(SH_registers + 0xc) = uVar4;
  *(int *)(SH_registers + 8) = 0;
  break;
case 4:
  bVar3 = SH_flag_solve(*(size_t *)(SH_registers + 0xc),(char *)(SH_registers + 0x10));
  *(int *)(SH_registers + 0xc) = (uint)bVar3;
  *(int *)(SH_registers + 8) = 0;
  break;
default:
  *(int *)(SH_registers + 8) = 0;
}
```

`SH_flag_solve` prend donc en paramètre la taille du flag ainsi qu'un pointeur vers le buffer.
```c
char SH_flag_solve(size_t len,char *buf) {
  char bVar1;
  char *iter;
  char *inner_check_iter;
  char abStack32 [20];

  SH_flag_solve_SUB(PTR_DAT_00002004,abStack32,PTR_DAT_00002008,0x10);
  if (len == 0x10) {
    bVar1 = 0;
    iter = buf + -1;
    inner_check_iter = abStack32;
    do {
      iter = iter + 1;
      bVar1 = bVar1 | *inner_check_iter ^ *iter;
      inner_check_iter = inner_check_iter + 1;
    } while (iter != (buf + 0xf));
  }
  else {
    bVar1 = 1;
  }
  return bVar1;
}
```

Il s'aggit donc d'une simple constant time comparaison entre le flag tel qu'envoyé par le SuperH et un buffer interne. Celui-ci semble être constamment modifié et les fonctions qui en sont responsables sont plutôt *conséquantes*.

{{< image "Une de ces fonctions *conséquantes*" "img/20210503-FCSC-2021-Stars-2ndMix-CryptoEdition/Stars-2ndMix-CryptoEdition-002.png" >}}

# V - Modification de Flycast

Une des solutions pour ne pas avoir à comprendre ce genre d'horreur, c'est tout simplement de logguer les opérandes du XOR lors de la comparaison. Pour cela il suffit de modifier l'émulateur de [la même manière que j'avais fait auparavant pour rajouter une sortie de debug dans Wii Sport]({{< relref "20200421-wii-sports-modding-1#iii---adding-a-custom-debug-output" >}}).


```c
diff --git a/core/hw/arm7/arm7.cpp b/core/hw/arm7/arm7.cpp
index ac1289bc..dfaec903 100644
--- a/core/hw/arm7/arm7.cpp
+++ b/core/hw/arm7/arm7.cpp
@@ -58,16 +58,20 @@ static int clockTicks;
 static void runInterpreter(u32 CycleCount)
 {
        if (!Arm7Enabled)
                return;

        clockTicks -= CycleCount;
        while (clockTicks < 0)
        {
                if (reg[INTR_PEND].I)
                        CPUFiq();

                reg[15].I = armNextPC + 8;
                #include "arm-new.h"
+               if(reg[15].I == 0x01ff0)
+                       printf("SH_flag_solve : %02X ^ %02X\n", reg[3].I, reg[14].I);
+               if(reg[15].I == 0x01ff8)
+                       printf("SH_flag_solve : == %02X\n", reg[3].I);
        }
 }
```

Cependant, nous venons de changer l'interpreteur ARM or un JIT est disponible, il ne faut donc pas oublier de le désactiver :

```c
diff --git a/core/build.h b/core/build.h
index b36264f1..b790caf9 100755
--- a/core/build.h
+++ b/core/build.h
@@ -194,7 +194,7 @@

 #ifndef FEAT_AREC
 	#if HOST_CPU == CPU_ARM || HOST_CPU == CPU_ARM64 || HOST_CPU == CPU_X64
-		#define FEAT_AREC DYNAREC_JIT
+		#define FEAT_AREC DYNAREC_NONE
 	#else
 		#define FEAT_AREC DYNAREC_NONE
 	#endif
```

Il faut bien faire attention à ajouter nos `printf`s *après* l'incrementation de PC et l'exécution de l'instruction. J'ai fait l'erreur de les mettre au mauvais endroit au début, ce qui me donnait des résultats qui n'avaient aucun sens et m'a fait perdre énormement de temps. J'ai même songé à commencer à reverse la crypto.

# VI - Conclusion

On peut maintenant essayer plein de combinaisons pour essayer de comprendre sous quelle forme le flag est envoyé de la part du SuperH et si la partie comparée dans l'ARM est constante.

```
// Test avec 0000000000000000
SH_flag_solve : CD ^ CF
SH_flag_solve : == 02
SH_flag_solve : E3 ^ E7
SH_flag_solve : == 04
SH_flag_solve : E5 ^ 94
SH_flag_solve : == 71
SH_flag_solve : EB ^ EA
SH_flag_solve : == 01
SH_flag_solve : B7 ^ C6
SH_flag_solve : == 71
SH_flag_solve : 92 ^ 9A
SH_flag_solve : == 08
SH_flag_solve : 25 ^ 21
SH_flag_solve : == 04
SH_flag_solve : 05 ^ 07
SH_flag_solve : == 02
SH_flag_solve : CD ^ CD
SH_flag_solve : == 00
SH_flag_solve : F1 ^ F3
SH_flag_solve : == 02
SH_flag_solve : EA ^ EA
SH_flag_solve : == 00
SH_flag_solve : 5C ^ 5C
SH_flag_solve : == 00
SH_flag_solve : 90 ^ 93
SH_flag_solve : == 03
SH_flag_solve : 6A ^ 19
SH_flag_solve : == 73
SH_flag_solve : E9 ^ EA
SH_flag_solve : == 03
SH_flag_solve : AF ^ A8
SH_flag_solve : == 07
// Test avec 0123456789ABCDEF
SH_flag_solve : CD ^ CF
SH_flag_solve : == 02
SH_flag_solve : E3 ^ E6
SH_flag_solve : == 05
SH_flag_solve : E5 ^ 96
SH_flag_solve : == 73
SH_flag_solve : EB ^ E9
SH_flag_solve : == 02
SH_flag_solve : B7 ^ C2
SH_flag_solve : == 75
SH_flag_solve : 92 ^ 9F
SH_flag_solve : == 0D
SH_flag_solve : 25 ^ 27
SH_flag_solve : == 02
SH_flag_solve : 05 ^ 00
SH_flag_solve : == 05
SH_flag_solve : CD ^ C5
SH_flag_solve : == 08
SH_flag_solve : F1 ^ FA
SH_flag_solve : == 0B
SH_flag_solve : EA ^ 9B
SH_flag_solve : == 71
SH_flag_solve : 5C ^ 2E
SH_flag_solve : == 72
SH_flag_solve : 90 ^ E0
SH_flag_solve : == 70
SH_flag_solve : 6A ^ 6D
SH_flag_solve : == 07
SH_flag_solve : E9 ^ 9F
SH_flag_solve : == 76
SH_flag_solve : AF ^ DE
SH_flag_solve : == 71
```

En comparant ces deux résultats, on peut facilement en déduire que la partie provenante de l'ARM est constante et que la partie provenante du SuperH est xorée avant d'être envoyée. Si on suppose que le flag `0000000000000000` est bien encodé sous forme de 0, on peut obtenir la clé `CFE794EAC69A2107CDF3EA5C9319EAA8`. En utilisant cette clé sur le second test, on peut obtenir l'alphabet dans lequel le flag est écrit.

On a donc bien un octet par carractère avec `0x00` à `0x09` pour `0` à `9` et `0x71` à `0x76` pour `A` à `F`.

Pour obtenir le flag, il ne suffit plus qu'a xorer la clé avec la partie constante provenant de l'ARM. Cela à même déjà été fait pour nous lors de la comparaison du flag `0000000000000000`. On obtient donc :
```
      02 04 71 01 71 08 04 02 00 02 00 00 03 73 03 07
FCSC{  2  4  A  1  A  8  4  2  0  2  0  0  3  C  3  7  }
```

{{< image "Message de réussite" "img/20210503-FCSC-2021-Stars-2ndMix-CryptoEdition/Stars-2ndMix-CryptoEdition-003.png" >}}
