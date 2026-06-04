# TP1 - Margaux

## 1.Can't be easier:

flag: COOKIE{CantBeEasierRight?!}
trouvé avec Ghidra 

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3390d32f450cbb7ef5447d8505e65ca0cf0075b8, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- symbole de debug : non
- main (adresse) : 0x00101159
- Libs avec ldd :
```
linux-vdso.so.1 (0x00007ffc4df74000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x000075afc5000000)
/lib64/ld-linux-x86-64.so.2 (0x000075afc53a7000)
```

Flag directement visible dans Ghidra à 0x00101192

Commande pour tester le flag : ./1.cantBeEasier COOKIE{CantBeEasierRight?\!}
PS: Si je mets pas "\!", j'avais cette erreur : "-bash: !}: event not found"

## 2.couldBeEasier

flag: COOKIE{C0uldBe4asIerR1ght1!}

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a561a1c7573524b58b86f82097283f5340d36910, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- symbole de debug : non
- main (adresse) : 0x001011ce
- Libs avec ldd :
```
linux-vdso.so.1 (0x00007ffda8335000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ed1ecc00000)
/lib64/ld-linux-x86-64.so.2 (0x00007ed1ecf55000)
```

Dans Ghidra on voit le flag inversé : 

```
1thg1h.ReIsa4eH
a4eBdluC
OH.C{EIKOOC
```

Cmd : ./2.couldBeEasier COOKIE{C0uldBe4asIerR1ght1\!}

## 3.NotToughEnoughYet

flag: COOKIE{MMhTh1sC0Uldb3W4yMoreT0ugher!!}

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5dbe17887c69303198c84f789f65a8c7a3773e23, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- symbole de debug : non
- main (adresse) : 0x00101251
- Libs avec ldd :
```
linux-vdso.so.1 (0x00007ffd22db1000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007a84eac00000)
/lib64/ld-linux-x86-64.so.2 (0x00007a84eae71000)
```

A l'adresse 0x001011ad il y a la chaine de caractères "AreWeHackersOrNot?!"

Ensuite, la fonction parcourt chaque caractère du flag entré par l'utilisateur et applique un XOR avec la chaine au dessus.

Puis la chaine créée est comparée à une suite d'octet et il faudra faire l'opération inverse d'un XOR pour trouver le flag.

Cmd: ./3.NotToughEnoughYet COOKIE{MMhTh1sC0Uldb3W4yMoreT0ugher\!\!}

## 4.GettingToughHeh

flag: COOKIE{RandomIsntSoRandomHeh..?}

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f5345046fb7be33baa7d31e79bc87be8b297483f, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- main (adresse) : 0x001012ef
- Libs avec ldd :
```
linux-vdso.so.1 (0x00007ffd31d96000)
libmcrypt.so.4 => not found
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x000073ffb5800000)
/lib64/ld-linux-x86-64.so.2 (0x000073ffb5adf000)
```

Utilisation de la bibliothèque libmcrypt, de rand (mais pas srand, donc toujours la même seed, donc toujours les mêmes valeurs).

Reconstruire la clé et l’IV pour retrouver le flag correspondant à la valeur chiffrée stockée dans le programme.

Le programme chiffre le flag fourni par le user avec rijndael-128 cbc puis compare le résultat à une valeur codée en dur.

## 5.WaitIsItThatEasy

flag: COOKIE{Wait?_It_W4s_43sy}

- type de fichier : ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9a005406b92d3c36db4262fab447f1a64de6231b, for GNU/Linux 4.4.0, stripped
- compilation dynamique ou statique : dynamique avec gcc
- binaire stripped, le main n'est plus directement visible
- main (adresse) :
- Libs avec ldd :
```
linux-vdso.so.1 (0x00007ffe835de000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007d1c7b600000)
/lib64/ld-linux-x86-64.so.2 (0x00007d1c7b86f000)
```

Dans mon terminal : strings 5.WaitIsItThatEasy

On voit le flag
