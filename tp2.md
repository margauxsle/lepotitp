# TP2
## Questions

### À quelle(s) famille(s) ce malware peut être rattaché ?

Ransomware ? (présence de lib de crypto, analyse du main, présence de fonction de chiffrement/déchiffrement)
ou vers (appel dans le main à une fonction de propagation latérale)

### Est-ce qu’il interagit avec le système ? Comment ?

Oui vu qu'il chiffre et déchiffre des fichiers, il interagit donc avec les permissions. Pendant son exécution, il va aussi se déplacer dans le répertoire /root/

### Est-ce qu’il communique avec l’extérieur ?

Oui, communication avec un serveur extérieur (NotifyRemoteServer())

### Est-ce qu’il y a une logique de persistance ou de dissimulation ?

Dissumulation surtout (fonction hideYouself()), mais aussi de persistance car lors de l'exécution du malware, il change de répertoire et de nom, pour passer inaperçu.

### Est-ce qu’il exploite quelque chose ?

Non, je n'ai pas trouvé de preuve

### Quels sont les impacts sur une machine infectée ?

Indisponibilité des fichiers présents sur le système, on touche donc ici au A de CIA

### Comment on le détecte ?

Modifications des permissions des fichiers, communication avec un serveur exterieur non connu

### Est-ce qu'il y a un kill switch, aka un moyen d'inverser ses dégats ?

Oui en ajoutant l'argument 'decrypt' lors de l'appel du malware

## Méthodologie

### Reconnaissance :

```
nezuko@nezuko-vm:~/Downloads$ file linux_amd64_malware 
linux_amd64_malware: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=_6iA4trwIcpJ4DM0Cc8p/Mn5Tk_MKEoTSI4b4dDSx/s3JVePkoe1zS7GdRKttJ/mZqisb3LqzZoIinLo5Cj, BuildID[sha1]=050762d40c406f7625291493285212c4f4f511f4, with debug_info, not stripped

nezuko@nezuko-vm:~/Downloads$ ldd linux_amd64_malware 
	linux-vdso.so.1 (0x00007b2662f7d000)
	libresolv.so.2 => /lib/x86_64-linux-gnu/libresolv.so.2 (0x00007b2662f53000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007b2662c00000)
	/lib64/ld-linux-x86-64.so.2 (0x00007b2662f7f000)

nezuko@nezuko-vm:~/Downloads$ strings linux_amd64_malware  | less
[...]
getaddrinfo
[...]
net.dnsReadConfig
[...]
resolveAddrList
[...]
o:itab.*encoding/asn1.taggedEncoder,encoding/asn1.encoder
go:itab.encoding/asn1.StructuralError,error
go:itab.encoding/asn1.bitStringEncoder,encoding/asn1.encoder
[...]
go:itab.*crypto/internal/fips140/hmac.HMAC,hash.Cloner
go:itab.*crypto/sha3.SHA3,hash.Cloner
crypto/internal/fips140/hkdf..dict.Expand[*crypto/internal/fips140/sha256.Digest]
crypto/internal/fips140/ecdsa..
[...]
```
### Analyse statique avec Ghidra :
```
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void main.main(void)

{
  uint8 *puVar1;
  int unaff_R14;
  
  while (&stack0x00000000 <= *(undefined1 **)(unaff_R14 + 0x10)) {
    runtime.morestack_noctxt();
  }
  if ((((1 < os.Args.len) && (os.Args.array[1].len == 7)) &&
      (puVar1 = os.Args.array[1].str, *(sdword *)puVar1 == 0x72636564)) &&
     ((*(short *)(puVar1 + 4) == 0x7079 && (puVar1[6] == 0x74)))) {
    malware/cmd/app.DecryptFiles();
    os.Exit(0);
  }
  main.hideYouself();
  malware/cmd/app.EncryptFiles();
  malware/cmd/app.NotifyRemoteServer();
  malware/cmd/app.Latteralize();
  return;
}
```
### Analyse dynamique :

```
nezuko@nezuko-vm:~/Downloads/test_malware$ echo 'test1' > test1.txt
nezuko@nezuko-vm:~/Downloads/test_malware$ echo 'test2' > test2.txt
nezuko@nezuko-vm:~/Downloads/test_malware$ ls -lah
total 8.9M
drwxrwxr-x 2 nezuko nezuko 4.0K Jun  6 16:02 .
drwxr-xr-x 5 nezuko nezuko 4.0K Jun  6 16:01 ..
-rw-rw-r-- 1 nezuko nezuko 8.9M Jun  6 14:44 linux_amd64_malware
-rw-rw-r-- 1 nezuko nezuko    6 Jun  6 16:02 test1.txt
-rw-rw-r-- 1 nezuko nezuko    6 Jun  6 16:02 test2.txt
nezuko@nezuko-vm:~/Downloads/test_malware$ chmod +x linux_amd64_malware 
nezuko@nezuko-vm:~/Downloads/test_malware$ sudo strace -f -o malware_log.txt ./linux_amd64_malware
nezuko@nezuko-vm:~/Downloads/test_malware$ ls -lah
total 19M
drwxrwxr-x 2 nezuko nezuko 4.0K Jun  6 16:05 .
drwxr-xr-x 5 nezuko nezuko 4.0K Jun  6 16:01 ..
-rw-rw-r-- 1 nezuko nezuko  19M Jun  6 16:06 malware_log.txt
-rw-rw-r-- 1 nezuko nezuko    6 Jun  6 16:02 test1.txt
-rw-rw-r-- 1 nezuko nezuko    6 Jun  6 16:02 test2.txt
```

Recherche de mots clé suspects dans le fichier malware_log.txt :
```
renameat(AT_FDCWD, "./linux_amd64_malware", AT_FDCWD, "/root/.bashrc.bak" <unfinished ...>
nezuko@nezuko-vm:~/Downloads/test_malware$ sudo ls -la /root/
[...]
-rwxrwxr-x  1 nezuko nezuko 9299822 Jun  6 14:44 .bashrc.bak
[...]
```

## Observations

Malware écrit en GO (on voit écrit "go" dans la sortie de la commande "strings", écrit aussi dans les infos données par Ghidra)

Beaucoup le terme "crypto" et "encoding" quand on analyse avec "strings" (sha256, HMAC, sha3, ecdsa)

Utilisation du package net de go et d'autres fonctions permettant de faire du repérage

Présence de symboles de debug

main address: 0x0065a900

Dans le main, comparaison de l'argument passé en paramètre aux chaînes en hexa 0x72636564, 0x7079 et 0x74. On traduit en txt, ca donne 'rced', 'py' et 't'.

Comparaison donc avec "decrypted".

Appel dans le main des fonctions "EncryptFiles()" et "DecryptFiles()", "Latteralize();", "NotifyRemoteServer();" et "hideYouself()"

Pendant l'analyse dynamique, on peut voir que le malware s'est déplacé dans le dossier /root et s'est renommé en .bashrc.bak, pour faire genre que c'est une backup et passer inaperçu.
