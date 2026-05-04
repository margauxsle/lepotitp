# TP1 - Margaux

## 1.Can't be easier:
flag: COOKIE{CantBeEasierRight?!}
trouvé avec Ghidra 

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3390d32f450cbb7ef5447d8505e65ca0cf0075b8, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- symbole de debug : 
- trace des lib : puts("usage: ./chall <flag>"usage: ./chall <flag>
)                                                                   = 22
exit(1 <no return ...>
+++ exited (status 1) +++
- main (adresse) : 00101150

## 2.couldBeEasier
flag: COOKIE{C0uldBe4asIerR1ght1!}

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a561a1c7573524b58b86f82097283f5340d36910, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- symbole de debug : 
- trace des lib : puts("usage: ./chall <flag>"usage: ./chall <flag>
)                                                                   = 22
exit(1 <no return ...>
+++ exited (status 1) +++
- main (adresse) : 001011c0

## 3.
flag: COOKIE{MMhTh1sC0Uldb3W4yMoreT0ugher!!}

- type de fichier : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5dbe17887c69303198c84f789f65a8c7a3773e23, for GNU/Linux 4.4.0, not stripped
- compilation dynamique ou statique : dynamique avec gcc
- symbole de debug : 
- trace des lib : puts("usage: ./chall <flag>"usage: ./chall <flag>
)                                                                   = 22
exit(1 <no return ...>
+++ exited (status 1) +++
- main (adresse) : 00101250
