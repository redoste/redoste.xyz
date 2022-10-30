---
title: "[FR] Write-up FCSC 2022 : More Hello"
date: 2022-05-08T18:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2022
---

# I - Intro

*More Hello* se compose d'un simple binaire FreeBSD AArch64 qui semble abordable.
```console
$ file more_hello
more_hello: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /libexec/ld-elf.so.1, for FreeBSD 14.0 (1400046), FreeBSD-style, stripped
```
Premier reflexe, on importe le binaire dans Ghidra pour avoir une idée de ce qu'il fait.

{{< image "Capture d'écran de Ghidra comportant des erreurs de désassemblage" "img/20220508-FCSC-2022-More-Hello/More-Hello-001.png" >}}

Oh non.

Ca risque de ne pas être aussi simple que prévu.

En relisant la description du challenge on remarque un détail assez spécial :

> Peut-être que je devrais arrêter de regarder l'exposé de S. Amar et N. Joly à la dernière BlackHat USA et me concentrer davantage.

Une simple recherche nous permet de retourver le nom de cette conférence : *"Security Analysis of CHERI ISA"*. Il semblerait donc que ce binaire ARM utilise [*Arm Morello*](https://www.arm.com/architecture/cpu/morello), une extension des instructions ARM de base ajoutant des fonctionnalités de sécurité suplémentaires. Une des plus notables est la possibilité à un pointeur d'être en permanence accompagné d'une taille empéchant les accès out of bounds.

# II - Installation de la toolchain

Pour pouvoir exécuter ce binaire il va nous faloir une build de FreeBSD pour Morello. Une petite recherche plus tard et il semblerait que la solution officielle soit de compiler *CheriBSD* (la variante de FreeBSD pour les instruction sets CHERI) à l'aide d'un LLVM que nous devons aussi compiler nous même.

LLVM est réputé pour être assez difficile à compiler car il nécessite beaucoup de RAM et d'espace disque. J'ai donc d'abord essayé de rechercher une version précompilée de *CheriBSD*.

Après un peu de recherche j'ai trouvé [cette page](https://morello-dist.cl.cam.ac.uk/releases/2020.10/arm64.aarch64c/relnotes.html) qui semble proposer une version précompilée de *CheriBSD* et d'un émulateur. Le seul désavantage serait que l'émulateur n'est pas QEMU mais on devrait pouvoir faire avec.

Après l'avoir téléchargé et installé à l'aide de [*cheribuild*](https://github.com/CTSRD-CHERI/cheribuild), l'émulateur semble fonctionner sans problème, il est juste un peu lent (Spoiler : plus lent que QEMU). On copie `more_hello` en SSH, on le lance et...

Il crash.

Comme la prebuilt a 1 an et demi et que l'architecture est encore très nouvelle j'ai supposé que le binaire utilisait un nouvelle feature qui n'avait pas encore était implémentée dans cet émulateur et j'ai donc cherché d'autre solutions. Vous comprendrez l'ironie de la situation assez vite.

Très bien donc on va compiler *CheriBSD* et QEMU nous même. J'ai donc trouvé une [prebuilt du LLVM pour Morello](https://git.morello-project.org/morello/llvm-project-releases), cela devrait nous économiser pas mal de temps. Après avoir réussi à forcer *cheribuild* à utiliser mon LLVM ajouté à la main, le compilateur semblait trop vieux pour compiler les derniers commits de *CheriBSD*.

Bon retour à la case départ et j'imagine qu'il va faloir que j'utilise la solution officielle, après tous ce n'est pas pour rien que c'est ce qui est recommandé de faire de partout. Après avoir fait un maximum de place sur mon pauvre SSD, je lance la compilation de LLVM via *cheribuild*, et quelques minutes plus tard, il crash sur le link d'un assez gros binaire. Bizarement Discord a crashé lui aussi. Très bien, allons faire un tour sur `htop` :
```
  Mem[||||||||||||||||||||||||||||||||                                                                     1.02G/15.0G]
  Swp[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||   23.3G/24.0G]
```
(les chiffres sont inventés, je ne me souviens pas exactement)

Un petit coup de `dmesg` plus tard on apprend que le linker a utilisé tellement de mémoire que toutes mes applications ont été déplacée sur la swap et il a quand même réussi à remplir toute ma RAM. L'OOM Killer a été déclenché et Linux a décidé de tuer Discord et le linker qui posait problème. (Heureusement que *cheribuild* a lancé la compilation avec un `nice` de 10, je pense que ca a pas mal limité la casse)

Bon tout compiler devrait être la bonne solution mais pas sur mon PC, j'ai un VPS avec 2 coeurs, vu la petite charge qu'il a je pense qu'en dédier un à la tâche devrait être possible.

Après avoir crée un nouveau user pour éviter les potentiels problèmes et avoir vérifié qu'il y a assez de place sur le disque, on peut télécharger *cheribuild* et lancer la compilation.
```console
$ ./cheribuild.py --make-jobs 1 sdk-morello-purecap
$ ./cheribuild.py --make-jobs 1 cheribsd-morello-purecap
$ ./cheribuild.py --make-jobs 1 gdb-morello-hybrid-for-purecap-rootfs
$ ./cheribuild.py --make-jobs 1 disk-image-morello-purecap
```
L'avantage de cette solution est que, malgré la lenteur de n'avoir qu'un seul coeur, j'ai pu le laisser tourner dans un `tmux` détaché durant la nuit sans avoir l'impression de dormir à coté d'un moteur d'avion pour me réveiller à un `No space left on device` le lendemin.

On obtient alors un LLVM, un QEMU et une image disque de CheriBSD avec GDB, tous ce dont on devrait avoir besoin pour solve le challenge. Après avoir téléchargé du serveur le résultat et installé les libraries manquantes ou d'une version différente sur mon PC, tous semble fonctionnel.

# III - Reverse engineering du binaire

Très bien maintenant essayons de lancer le binaire dans QEMU.

Il crash aussi.

Hein ? Retournons lire la description du challenge :

> J'ai besoin d'aide !
>
> Je veux atteindre ce print flag dans le programme, mais je n'arrive pas à comprendre ce qui m'en empêche ! Il n'y a même pas un seul saut conditionnel dans le flot de contrôle ! Peut-être que je devrais arrêter de regarder l'exposé de S. Amar et N. Joly à la dernière BlackHat USA et me concentrer davantage.

Est-ce que le crash est volontaire ? (oui.) Aurais-je pu éviter tous ca et utiliser l'émulateur que j'ai mentionné au début ? (probablement.)

Bon maintenant on a un émulateur plus rapide au moins, voyons le bon coté des choses.

On peut exécuter le binaire avec GDB de manière à trouver l'endoit du crash. GDB ne semble pas pouvoir désassembler les instructions Morello, j'ai donc dû faire tous le challenge avec un fichier contenant la sortie de `llvm-objdump` à coté.
```
Breakpoint 1, 0x0000000000111a20 in ?? ()
(gdb) x/15i $pc
=> 0x111a20:      .inst   0x0286c3ff ; undefined
   0x111a24:      .inst   0x428c7bfd ; undefined
   0x111a28:      .inst   0xc2006bfc ; undefined
   0x111a2c:      .inst   0x020603fd ; undefined
   0x111a30:      .inst   0xc2c1d024 ; undefined
   0x111a34:      mov     w9, w0
   0x111a38:      .inst   0x028013a0 ; undefined
   0x111a3c:      .inst   0xc2c23806 ; undefined
   0x111a40:      .inst   0x028023a0 ; undefined
   0x111a44:      .inst   0xc2c23805 ; undefined
   0x111a48:      .inst   0x028083a0 ; undefined
   0x111a4c:      .inst   0xc2c83800 ; undefined
   0x111a50:      .inst   0x028243a1 ; undefined
   0x111a54:      .inst   0xc2c3f821 ; undefined
   0x111a58:      .inst   0xc2001be1 ; undefined
```

Globalement on peut très vite identifier que notre paramètre d'entrée est passé à `strtoul` puis se fait transformer lors de l'appel de 3 fonctions avant le check.
```
  111adc: 00 00 40 c2  	ldr	c0, [c0, #0]
  111ae0: 00 04 40 c2  	ldr	c0, [c0, #16]
  111ae4: e1 03 1f aa  	mov	x1, xzr
  111ae8: 02 02 80 52  	mov	w2, #16
  111aec: 55 00 00 94  	bl	0x11c40 <strtoul@plt>
  111af0: e2 13 40 c2  	ldr	c2, [csp, #64]
  111af4: e1 17 40 c2  	ldr	c1, [csp, #80]
  111af8: e3 03 00 aa  	mov	x3, x0
  111afc: e0 1b 40 c2  	ldr	c0, [csp, #96]
  111b00: e8 03 03 2a  	mov	w8, w3
  111b04: 48 00 00 b9  	str	w8, [c2]
  111b08: 48 00 40 b9  	ldr	w8, [c2]
  111b0c: 28 00 00 39  	strb	w8, [c1]
  111b10: 48 00 40 b9  	ldr	w8, [c2]
  111b14: 08 7d 08 53  	lsr	w8, w8, #8
  111b18: 28 04 00 39  	strb	w8, [c1, #1]
  111b1c: 48 04 40 79  	ldrh	w8, [c2, #2]
  111b20: 28 08 00 39  	strb	w8, [c1, #2]
  111b24: 48 0c 40 39  	ldrb	w8, [c2, #3]
  111b28: 28 0c 00 39  	strb	w8, [c1, #3]
  111b2c: ad fd ff 97  	bl	0x111e0 <.text+0x7d0>
  111b30: e1 17 40 c2  	ldr	c1, [csp, #80]
  111b34: e0 1b 40 c2  	ldr	c0, [csp, #96]
  111b38: 88 00 80 52  	mov	w8, #4
  111b3c: e2 03 08 2a  	mov	w2, w8
  111b40: d8 fd ff 97  	bl	0x112a0 <.text+0x890>
  111b44: e0 1b 40 c2  	ldr	c0, [csp, #96]
  111b48: e1 1f 40 c2  	ldr	c1, [csp, #112]
  111b4c: 21 fe ff 97  	bl	0x113d0 <.text+0x9c0>
  111b50: e0 23 40 c2  	ldr	c0, [csp, #128]
  111b54: e8 97 40 b9  	ldr	w8, [csp, #148]
  111b58: 08 00 00 b9  	str	w8, [c0]
  111b5c: 01 00 00 14  	b	0x11b60 <.text+0x1150>
```

Regardons donc comment est implémenté le check :
```
  111b60: e0 0f 40 c2  	ldr	c0, [csp, #48]
  111b64: 08 00 40 b9  	ldr	w8, [c0]
  111b68: 08 35 00 71  	subs	w8, w8, #13
  111b6c: 2c 02 00 54  	b.gt	0x11bb0 <.text+0x11a0>
  111b70: 01 00 00 14  	b	0x11b74 <.text+0x1164>

  111b74: e0 07 40 c2  	ldr	c0, [csp, #16]
  111b78: e1 03 40 c2  	ldr	c1, [csp, #0]
  111b7c: e2 0f 40 c2  	ldr	c2, [csp, #48]
  111b80: 48 00 80 b9  	ldrsw	x8, [c2]
  111b84: 28 68 68 38  	ldrb	w8, [c1, x8]
  111b88: 01 68 68 38  	ldrb	w1, [c0, x8]

  111b8c: 80 00 80 90  	adrp	c0, 0x21000 <.text+0x11bc>
  111b90: 00 2c 43 c2  	ldr	c0, [c0, #3248]
  111b94: 27 00 00 94  	bl	0x11c30 <printf@plt>
  111b98: 01 00 00 14  	b	0x11b9c <.text+0x118c>

  111b9c: e0 0f 40 c2  	ldr	c0, [csp, #48]
  111ba0: 08 00 40 b9  	ldr	w8, [c0]
  111ba4: 08 05 00 11  	add	w8, w8, #1
  111ba8: 08 00 00 b9  	str	w8, [c0]
  111bac: ed ff ff 17  	b	0x11b60 <.text+0x1150>
```
On pourrait décompiler ce code de cette manière :
```c
  while (i <= 13) {
    printf("%d", buf1[buf2[i]]);
    i++;
  }
```
Le programme semble crasher à 0x111b88 ce qui correspond à la lecture de `buf1`. Ce qui est plutôt intriguant est le message d'erreur :
```
Program received signal SIGPROT, CHERI protection violation
```
Il semblerait donc que la protection CHERI de `buf1` sert de vérification. Allons regarder de plus près :
```
Breakpoint 2, 0x0000000000111b88 in ?? ()
(gdb) x/13bx $c1
0xfffffff7febc:   0xdf    0x3f    0x61    0x98    0x04    0xa9    0x2f    0xdb
0xfffffff7fec4:   0x40    0x57    0x19    0x2d    0xc4
(gdb) info register $w8
w8             0xdf                223
(gdb) x/1bx $c0 + 223
0xfffffff7ff6f:   0x00
```
Donc le `buf2` pointé par `c1` semble contenir des données qui dérivent de notre input, on peut le confirmer en réeffectuant la même procédure mais en changeant l'entrée. Cependant `buf1[0xdf]` semble bien mappé et ne pas poser de problèmes.
```
(gdb) info register $c0
c0             0xdc5d40007ebafe900000fffffff7fe90 0xfffffff7fe90 [rwRW,0xfffffff7fe90-0xfffffff7feba]
```
En revanche `buf1` utilise un pointeur protégé qui limite la lecture à +0x2a, il s'aggirait donc du check, les 13 premiers octets de notre input transformée doivent être inférrieurs à 0x2a de manière à ne pas faire crasher le binaire.

J'ai d'abord essayer de m'attaquer manuellement aux fonctions de transformations mais j'ai très vite abandonné, je n'ai juste pas l'habitude de l'assembleur ARM et l'impossibilité d'avoir ne serait-ce qu'une vue graphique en bloc rend la chose assez fastidieuse.

Si on oublie les features de sécurité, on est quand même très proche de l'ARM, ce serait plutôt pratique si on pouvait le "traduire". J'ai donc sorti chaque fonctions importantes et à coup de gros rechercher-remplacer j'ai substitué les registres CHERI par des registres ARM qui n'étaient pas utilisés dans la fonction. Après avoir noppé l'instruction spécifique à CHERI `scbnds`, qui semble permettre de régler la longeur de la protection du pointeur, le code s'assemble sans problème.

On peut maintenant importer les fichiers produits dans Ghidra pour essayer d'obtenir une décompilation qui a du sens.

Mon utilisation assez abusive et innadapté de certain registres semble désorrienter le decompilateur mais on peut comprendre ce qui se passe sans trop de problèmes.

Par exemple voici la première fonction appelée du main :
```c
void FUN_111e0(void) {
  long unaff_x29;

  *(undefined4 *)(unaff_x29 + 0x40) = 0;
  *(undefined8 *)(unaff_x29 + 0x48) = 0;
  *(undefined4 *)(unaff_x29 + 0x50) = 0x6a09e667;
  *(undefined4 *)(unaff_x29 + 0x54) = 0xbb67ae85;
  *(undefined4 *)(unaff_x29 + 0x58) = 0x3c6ef372;
  *(undefined4 *)(unaff_x29 + 0x5c) = 0xa54ff53a;
  *(undefined4 *)(unaff_x29 + 0x60) = 0x510e527f;
  *(undefined4 *)(unaff_x29 + 100) = 0x9b05688c;
  *(undefined4 *)(unaff_x29 + 0x68) = 0x1f83d9ab;
  *(undefined4 *)(unaff_x29 + 0x6c) = 0x5be0cd19;
  return;
}
```
Malgré l'utilisation d'un registre non affecté on comprend très bien qu'il initialise une structure à une adresse probablement passée par la fonction appelante.

# IV - Identification de l'algorithme

S'en suit une période assez longue ou j'essaye de reverse l'algorithme implémenté alors que certains d'entre vous sont probablement déjà en train de crier en ayant vu la fonction précédente.

En effet j'ai perdu le reflexe de Googler les constantes à force de résoudre des challenges qui implémentent des algorithmes custom ou sans constantes pour éviter de rendre le reverse "trop facile". J'ai donc passé facilement une heure à essayer de comprendre ce qui se passait et essayer de trouver comment j'étais censé déterminer l'input qui aurrait les 13 premiers octets inférrieurs à 0x2a.

J'ai quand même eu l'idée de rechercher les valeurs d'un tableau de constantes utilisé au milieu l'algorithme mais je n'avais pas remarqué que le pointeur était 2 fois déréférencé, j'ai donc Googler un pointeur. Très utile.

Après pas mal de temps à step dans GDB je retombe sur ce même tableau et me rends compte de mon erreur, après une nouvelle recherche avec les bonnes valeurs, je me suis détesté pendant les 6 heures suivantes en lisant le premier résultat :

{{< image "Résultat d'une recherche Google avec la page Wikipedia de SHA-2 en tête" "img/20220508-FCSC-2022-More-Hello/More-Hello-002.png" >}}

3 fonctions : init, update, final : les 3 fonctions de (quasi-)tous les algorithmes de hash.

# V - Conclusion

Le solve est donc plutôt simple, je l'ai d'abord tenté en Python mais il était bien évidemment trop lent, j'ai donc fini par opter pour le C (avec un petit coup de `-Os`):
```c
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  SHA256_CTX sha256;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  for (uint64_t i = 0; i < 0x100000000; i++) {
    if ((i & 0x7fff) == 0)
      printf("%lX...\n", i);
    uint32_t d = i & 0xffffffff;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &d, 4);
    SHA256_Final(hash, &sha256);

    bool good = true;
    for (size_t idx = 0; idx < 13; idx++) {
      if (hash[idx] > 0x2a) {
        good = false;
        break;
      }
    }
    if (good) {
      printf("%lX\n", i);
      return 0;
    }
  }
  return 1;
}
```
```console
$ time ./solve
...
27180000...
27188000...
2718D310

real	0m42.767s
user	0m42.510s
sys	0m0.102s
```
On peut alors confirmer que cela fonctionne dans l'émulateur :
```console
$ ./more_hello 2718D310
00000000000000FLAG: FCSC{CHERI_COCO_MORELLO_2718d310}
```

Je sais qu'on a souvent tendence à dire que le plus important c'est de flag, mais je tennais beaucoup à faire ce write-up pour documenter les raisons stupides de ma perte de temps, que ce soit au niveau de la toolchain ou de l'identification de SHA-256. (J'aurais pu continuer à chercher un bug dans la crypto pendant longtemps, je ne pense pas que j'aurais trouvé).

Je pense que c'est l'un des challenges que j'ai le "moins bien" réussi de ce FCSC 2022.
