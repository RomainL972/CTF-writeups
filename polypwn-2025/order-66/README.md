# Order 66

Ce writeup est à propos du challenge "Order 66" de l'édition 2025 du PolyPwn CTF.

## Recréation du challenge

Pour tester ce challenge à la maison, téléchargez l'exécutable à exploiter [order66](order66). Le code source correspondant était aussi fourni: [order66.c](order66.c).

## Analyse du code source

En lisant le code source dans [order66.c](order66.c), on voit directement des définitions pour l'utilisation de syscalls, un payload de nombres hexadécimaux, et des fonctions pour surveiller / contrôler l'exécution d'un child process (`handle_syscall_child`, `init_tracee_child`).

On peut mettre `hidden_payload` dans un désassembleur pour voir un code exécutable qui fait plusieurs syscalls. C'est ce que fait le script [decompile.py](decompile.py), le résultat est dans [hidden-payload.txt](hidden-payload.txt).

Avec un petit programme C pour exécuter du shellcode dans `exec-shellcode.c`, on peut voir quels sont les syscalls exécutés par le shellcode:

```bash
python decompile.py
make
strace ./exec-shellcode < hidden-payload.bin > /dev/null
```

On obtient ces syscalls intéressants:

```
read(0, "H1\300\270\n\0\0\0PH\270rder 66:PH\270nd the oPH"..., 200) = 147
write(1, "Congrate, you find the order 66:"..., 33) = 33
open("flag.txt", O_RDONLY)              = -1 ENOENT (No such file or directory)
read(-2, 0x7ffec71f67b0, 32)            = -1 EBADF (Bad file descriptor)
write(1, "flag.txt\0\0\0\0\0\0\0\0Congrate, you fi", 32) = 32
exit(0)                                 = ?
```

Le premier correspond à notre code dans `exec-shellcode.c` qui lit stdin pour trouver le code à exécuter. Ensuite, on a une écriture sur stdout pour nous dire félicitations, suivi de l'ouverture du fichier `flag.txt`, qui ne fonctionne pas localement car le fichier n'existe pas. Enfin, on suppose que les derniers `read` et `write` permettent de lire le contenu du fichier `flag.txt` et de l'afficher sur stdout lorsque le fichier existe.

## Restrictions des syscalls

Puisque le flag semble se trouver dans le fichier `flag.txt`, on pourrait vouloir écrire notre propre shellcode pour ouvrir le fichier, le lire et afficher son contenu, puis donner ce code en stdin au programme, qui le lire dans `start_finder` et l'exécutera.

Malheureusement, cela n'est pas possible. En effet, le processus enfant qui exécute la fonction `start_finder` est surveillé, et seuls certains syscalls sont autorisés. Même si `open` est un syscall autorisé, il vient avec un handler qui n'autorise son exécution que lorsqu'il est appelé depuis `hidden_payload`.

## Egg hunt

Pour récapituler, nous avons un payload dans `hidden_payload`, qui est écrit dans le heap avec `hide_egg`, qui permet d'ouvrir le flag et d'afficher son contenu. Nous pouvons aussi écrire notre propre shellcode de jusqu'à 128 caractères qui sera exécuté dans `start_finder`, avec des restrictions sur les syscalls autorisés.

Nous devons donc utiliser notre shellcode pour retrouver dans la mémoire où est stocké `hidden_payload`, et l'exécuter. Cela consiste à la technique de "egg hunt", où un petit shellcode est utilisé pour en retrouver un plus gros, grâce à un tag unique. Le tag correspond ici aux mots de 4 octets 0x6564726f et 0x00363672, contenus dans la variable `order66`, qui sont écris en mémoire juste avant le payload.

### Shellcode

Mon shellcode est inspiré de celui posté sur ce blog: <https://epi052.gitlab.io/notes-to-self/blog/2018-07-29-x64-linux-egghunter-shellcode/>

Le shellcode final est dans [shellcode.nasm](shellcode.nasm).

Le principe de fonctionnement du shellcode est le suivant: On parcourt les adresses de mémoire virtuelle. Pour chaque page, on vérifie si on peut y accéder avec un appel au syscall `access`, qui renverra `EFAULT` si l'adresse donnée dans `rdi` n'est pas mappée dans la mémoire, au lieu de causer un segmentation fault. Ensuite, pour chaque adresse dans la page, on vérifie si les deux prochains mots de 4 octets sont égaux à notre egg.

Trois modifications ont été apportées pour s'adapter à notre cas spécifique. D'abord, au lieu de vérifier si la même valeur est présente deux fois de suite pour l'egg, on vérifie si les deux valeurs différentes données dans le code sont présentes.

Ensuite, on vérifie aussi si le shellcode a atteint la fin d'une page, car cela nécessite de vérifier si on a accès à la nouvelle page. Sans cette mesure, on a un segmentation fault dès qu'on passe d'une page mémoire mappée à une page qui ne l'est pas.

Enfin, la ligne `mov rdi, PLACEHOLDER` permet de dynamiquement commencer la recherche à l'adresse indiquée par l'exécutable dans le `printf("[Hint] ...")`.

### Script d'exploitation

Le script permettant l'exploitation finale se trouve dans [solve.py](solve.py). Après avoir commencé l'exécution, le hint est extrait puis inséré dans le shellcode. Le shellcode est ensuite compilé (nécessite les outils standards de compilations ainsi que `nasm`), puis envoyé au programme. Enfin, le flag est affiché et les fichiers temporaires sont supprimés. Résultat:

```
[+] Opening connection to ctf.polycyber.io on port 47641: Done
Hint: 0x754775500000
[+] Receiving all data: Done (85B)
[*] Closed connection to ctf.polycyber.io port 47641
find the Order 66 !
Congrate, you find the order 66:
polycyber{0rd3r_66_n0_m0r3_j3d1}
```

**Flag: polycyber{0rd3r_66_n0_m0r3_j3d1}**
