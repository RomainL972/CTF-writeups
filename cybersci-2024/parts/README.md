# Parts

Ce writeup est à propos du challenge "parts" de l'édition 2024 de la compétition régionale Cybersci.

L'énoncé du challenge est le suivant :

We've intercepted this high profile message. Can you find anything of value?

Flag format: cybersci{[A-Za-z0-9_-]+}

## Recréation du challenge

Pour tester ce challenge à la maison, téléchargez les fichiers [encrypt.py](encrypt.py) et [output.txt](output.txt).

## Exploration

Les fichiers fournis correspondent à un script permettant des chiffrer des fichiers avec l'algorithme RSA, ainsi que le résultat de l'exécution de cet algorithme.

L'objectif est donc de retrouver le flag, qui devrait se retrouver sous forme chiffrée dans la variable `ct` dans le fichier d'output. On remarque que `ct` est une liste de nombres, où chaque nombre correspond à quatre lettres chiffrées avec la clé RSA générée aléatoirement.

## Cryptanalyse

Comme les messages chiffrés ne font que 4 caractères, il devrait être possible de pré-calculer toutes les possibilités puis de déchiffrer le message au complet, surtout si le message chiffré ne contient presque que des lettres et des chiffres, comme indiqué dans l'énoncé.

Pour vérifier mon hypothèse, j'essaie de chiffrer le mot "cyber" avec la clé publique fournie :

```python
from string import ascii_lowercase, ascii_uppercase, digits
import itertools

n = 129...
e = 65537
ct = [571..., ...]
letters = ascii_lowercase + ascii_uppercase + digits + "-_"

def encrypt(msg):
    return pow(msg, e, n)

def encode(comb):
    return bytes_to_long(''.join(comb).encode())

def verify_decrypt(comb, c=ct[0]):
    pt = encode(comb)
    if encrypt(pt) == c:
        return True
    return False

assert verify_decrypt("cyber")
```

Malheureusement, le résultat ne correspond pas au premier nombre de `ct`. Il semble alors que le message chiffré ne commence pas par le "cybersci" du début du flag.

Ma deuxième hypothèse est que le message chiffré correspond à la partie entre les accolades {} dans l'énoncé. J'essaie alors de chiffrer toutes les combinaisons autorisées par le regex du flag pour les comparer à `ct[0]`.

```python
for comb in itertools.product(letters, repeat=4):
    if verify_decrypt(comb):
        print(comb)
        break
```

Là encore, aucun résultat n'est trouvé. Il semble alors que le message chiffré contient d'autres informations en plus du flag, qui elles ne respectent pas le regex du flag. La complexité de pré-calculer toutes les combinaisons de caractères imprimables est beaucoup plus élevée que celle de calculer seulement les combinaisons avec des lettres et des chiffres.

## Exploitation

Si le message chiffré contient le mot "cybersci", alors une des valeurs de `ct` devrait correspondre à un des sous-ensembles de 4 lettres du mot. On le retrouve avec ce script :

```python
choices = ["cybe", "yber", "bers", "ersc"]
for i, cti in enumerate(ct):
    for choice in choices:
        if decrypt_helper(choice, cti):
            break
```

On obtient comme résultat que le mot `yber` se trouve à `ct[8]`, puis donc que `sci{` se trouve à `ct[9]`. Nous pouvons donc maintenant déchiffrer le reste du flag en pré-calculant toutes les possibilités qui respectent le regex.

```python
mapping = {}
for comb in itertools.product(letters, repeat=4):
    mapping[encrypt(encode(comb))] = "".join(comb)

for i, cti in enumerate(ct[10:]):
    print(f"{i}: {mapping[cti]}")
```

On obtient alors le flag suivant : `cybersci{no_need_to_worry}`.

## Script complet

Le script final est disponible ici : [script.py](script.py)

Celui-ci contient du multithreading pour accélérer le calcul du mapping, ainsi que l'utilisation de pickle pour sauvegarder les mappings et ne pas avoir besoin de les recalculer à chaque fois. Le fichier précalculé de mappings est disponible ici : [mapping.pkl](https://drive.google.com/file/d/1pTms3hOAPkCIznZu87EbxCfKhE_kFv7F/view?usp=drive_link). Si vous ne trustez pas mon fichier, ne l'utilisez pas et le script recalculera tout automatiquement.

Le calcul des possibilités prend 1 minute 30 secondes sur un AMD Ryzen™ 7 7840U.
