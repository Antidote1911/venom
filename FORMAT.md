# Venom Container Format — Version 1

Spécification binaire précise du format de conteneur chiffré `.vnm`.
Toutes les valeurs multi-octets sont en **little-endian**.
Tous les octets non documentés dans les zones de slots inutilisés sont remplis
d'octets aléatoires cryptographiquement sûrs (deniabilité plausible).

---

## 1. Vue d'ensemble du fichier

```
Offset          Taille          Description
─────────────────────────────────────────────────────────────────────────────
0               512             En-tête extérieur — primaire (chiffré)
512             512             En-tête extérieur — backup (copie identique)
1 024           14 152          Zone destinataires (password slots + key slots)
15 176          N × 32 768      Zone de données (N slots de 32 768 octets)
EOF − 1 024     512             En-tête caché — backup  (si volume caché, sinon aléatoire)
EOF − 512       512             En-tête caché — primaire (si volume caché, sinon aléatoire)
─────────────────────────────────────────────────────────────────────────────
```

**Taille de queue (tail) :**
- Conteneur sans volume caché : 512 octets (placeholder aléatoire)
- Conteneur avec volume caché : 1 024 octets (backup 512 + primaire 512)

Constantes :

| Constante              | Valeur  | Calcul                                        |
|------------------------|--------:|-----------------------------------------------|
| `HEADER_SIZE`          |     512 | fixe                                          |
| `HEADER_REGION_SIZE`   |   1 024 | fixe (2 × 512)                                |
| `MAX_PASSWORD_SLOTS`   |       8 | fixe                                          |
| `MAX_KEY_SLOTS`        |       8 | fixe                                          |
| `PW_SLOT_SIZE`         |     101 | 32 + 1 + 68                                   |
| `KEY_SLOT_SIZE`        |   1 668 | 32 + 1 568 + 68                               |
| `RECIPIENT_AREA_SIZE`  |  14 152 | 8 × 101 + 8 × 1 668                           |
| `DATA_AREA_OFFSET`     |  15 176 | 1 024 + 14 152                                |
| `SLOT_SIZE`            |  32 768 | fixe                                          |

Taille minimale d'un fichier conteneur :
`DATA_AREA_OFFSET + 16 × SLOT_SIZE + 512 = 15 176 + 524 288 + 512 = 539 976 octets`

---

## 2. En-tête (512 octets)

Deux en-têtes existent dans chaque fichier :
- **En-tête extérieur** : octets `[0..512]`
- **En-tête caché** : octets `[EOF−512..EOF]` (octets aléatoires si absent)

### 2.1 Champs en clair (octets 0–67)

```
Offset  Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0       64      [u8; 64]    salt — sel Argon2id de ce volume (aléatoire)
64       1      u8          cipher_id
                              0 = ChaCha20-Poly1305
                              1 = AES-256-GCM
65       1      u8          kdf_profile_id
                              0 = interactive  (m=65 536 KiB, t=3, p=4)
                              1 = sensitive    (m=262 144 KiB, t=4, p=4)
66       1      u8          num_password_slots  (0–8)
67       1      u8          num_key_slots       (0–8)
──────────────────────────────────────────────────────────────────────────
```

### 2.2 Bloc VNMB chiffré (octets 68–499, 432 octets)

Le bloc VNMB (voir §4) contient 396 octets de corps en clair chiffrés avec
`K_master` (volume extérieur) ou `Argon2id(password, salt)` (volume caché).

```
Offset  Taille  Description
──────────────────────────────────────────────────────────────────────────
68       4      magic b"VNMB"
72       4      version u32 LE = 1
76      12      nonce (aléatoire par écriture)
88     396      corps chiffré (voir §2.3)
484     16      tag AEAD
──────────────────────────────────────────────────────────────────────────
```

AAD (données authentifiées non chiffrées) :
- En-tête extérieur : `b"vnm:header:outer:v1"`
- En-tête caché    : `b"vnm:header:hidden:v1"`

Octets `[500..512]` : padding nul (12 octets inutilisés).

### 2.3 Corps de l'en-tête (396 octets en clair avant chiffrement)

```
Offset  Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0        4      [u8; 4]     magic b"VNM1"
4        4      u32 LE      version du corps
                              1 = volume extérieur (encode_header)
                              3 = volume caché (encode_header_with_password)
8        8      u64 LE      data_area_offset = 15 176
16       8      u64 LE      outer_slots
                              volume extérieur : nombre de slots alloués
                              volume caché     : nombre de slots du volume caché
24       8      u64 LE      hidden_start
                              volume extérieur : 0
                              volume caché     : index du 1er slot physique caché
32       8      u64 LE      root_slot — index du slot racine du système de fichiers
40       8      u64 LE      created_at — timestamp Unix en secondes
48      64      [u8; 64]    label — UTF-8 null-paddé
112    284      [u8; 284]   réservé (zéros)
──────────────────────────────────────────────────────────────────────────
Total  396 octets
```

### 2.4 Dérivation de clé pour le volume caché

Le volume caché n'utilise **pas** de zone destinataires séparée.
Sa clé d'en-tête est dérivée directement du mot de passe :

```
K_hidden = Argon2id(
    password   = mot de passe saisi,
    salt       = en-tête[0..64],
    profile    = en-tête[65],
)
```

Cette clé chiffre le corps de l'en-tête caché et sert de `K_master`
pour tous les slots de données du volume caché.

---

## 3. Zone destinataires (octets 1 024–15 239)

Disposition fixe, jamais réallouée :

```
Offset                  Taille          Description
──────────────────────────────────────────────────────────────────────────
1 024                   8 × 101 = 808   8 password slots (voir §3.1)
1 024 + 808 = 1 832     8 × 1 668 = 13 344   8 hybrid key slots (voir §3.2)
──────────────────────────────────────────────────────────────────────────
Total                   14 152 octets
```

Les slots inutilisés contiennent des octets aléatoires
(indiscernables des slots actifs, deniabilité plausible).

### 3.1 Password slot (101 octets)

Chaque slot chiffre `K_master` avec une clé dérivée du mot de passe.

```
Offset  Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0       32      [u8; 32]    salt Argon2id (aléatoire, unique par slot)
32       1      u8          kdf_profile_id (0=interactive, 1=sensitive)
33      68      VNMB block  K_master chiffré (32 octets en clair → 68 octets)
──────────────────────────────────────────────────────────────────────────
```

Dérivation de la clé de slot :
```
slot_key = Argon2id(password, salt=slot[0..32], profile=slot[32])
K_master = AEAD_decrypt(slot_key, slot[33..101], aad=b"vnm:pw:v1")
```

### 3.2 Hybrid key slot (1 668 octets)

Chaque slot chiffre `K_master` avec une clé hybride X25519 + ML-KEM-1024.

Aucun fingerprint n'est stocké en clair : tous les slots sont testés à
l'aveugle à l'ouverture. Cela préserve **l'anonymat des destinataires** —
un adversaire possédant le conteneur et une liste de clés publiques suspectes
ne peut pas déterminer à qui le fichier est destiné.

```
Offset  Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0       32      [u8; 32]    x25519_eph_pk — clé publique éphémère X25519
32    1 568      [u8; 1568]  mlkem_ct — chiffré ML-KEM-1024
1 600   68      VNMB block  K_master chiffré (32 octets en clair → 68 octets)
──────────────────────────────────────────────────────────────────────────
```

Dérivation de la clé de slot :
```
x25519_shared = ECDH(x25519_eph_pk, x25519_sk_recipient)
mlkem_ss      = ML-KEM-1024.Decapsulate(mlkem_seed, mlkem_ct)
hybrid_key    = SHA-256(
    b"venom:hybrid:v1"
    ‖ x25519_shared    (32 B)
    ‖ mlkem_ss         (32 B)
    ‖ x25519_eph_pk    (32 B)
    ‖ mlkem_ct         (1568 B)
)
K_master = AEAD_decrypt(hybrid_key, slot[1600..1668], aad=b"vnm:key:v1")
```

---

## 4. Format de bloc VNMB

Tous les payloads chiffrés (en-tête, slots destinataires, slots données)
utilisent ce format d'enveloppe :

```
Offset  Taille  Description
──────────────────────────────────────────────────────────────────────────
0        4      magic b"VNMB"
4        4      version u32 LE = 1
8       12      nonce 96 bits (aléatoire par écriture)
20       P      ciphertext (P = taille du plaintext)
20+P    16      tag AEAD 128 bits
──────────────────────────────────────────────────────────────────────────
Total = 36 + P octets
```

Tailles de blocs courants :

| Plaintext (P)  | Bloc total | Utilisation                     |
|---------------:|----------:|----------------------------------|
|         32 B   |     68 B  | K_master dans un slot destinataire |
|        396 B   |    432 B  | Corps de l'en-tête               |
|       ≤ 32 732 B | ≤ 32 768 B | Payload d'un slot de données   |
|         96 B   |    132 B  | Clé privée protégée (.key)       |

---

## 5. Zone de données (à partir de l'offset 15 176)

### 5.1 Slot de données (32 768 octets)

```
Offset  Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0        4      u32 LE      len — longueur du bloc VNMB qui suit
4       len     VNMB block  payload chiffré (plaintext ≤ 32 732 octets)
4+len   pad     [u8]        zéros jusqu'à la fin du slot (32 768 octets)
──────────────────────────────────────────────────────────────────────────
```

AAD de chiffrement : `slot_index as u64 LE` (8 octets).
Cela lie chaque slot à sa position physique (protection contre le déplacement).

Index des slots réservés :
- Slot 0 : bloc d'allocation du volume extérieur (`OUTER_ALLOC_SLOT`)
- Slot 1 : répertoire racine du volume extérieur (`OUTER_ROOT_SLOT`)
- Dernier slot du volume caché : bloc d'allocation du volume caché

Les slots libérés sont **écrasés avec des octets aléatoires** (forward secrecy).

### 5.2 Bloc d'allocation (slot 0 pour l'extérieur, slot_limit−1 pour le caché)

Le plaintext déchiffré du slot d'allocation contient :

```
Offset  Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0        8      u64 LE      n — nombre total de slots du volume
8       ⌈n/8⌉   [u8]        bitmap : bit i = 1 → slot (slot_start + i) est LIBRE
──────────────────────────────────────────────────────────────────────────
```

Le bit i du byte k correspond au slot `slot_start + k×8 + i`.

### 5.3 Nœuds du système de fichiers (MessagePack)

Le plaintext de chaque slot de données (sauf le slot d'allocation) est un
objet **MessagePack** (`rmp-serde`, format `to_vec_named`) représentant un
des quatre types suivants :

Constantes du système de fichiers :

| Constante           | Valeur  | Description                                     |
|---------------------|--------:|-------------------------------------------------|
| `CHUNK_SIZE`        |  30 000 | octets de données utiles par slot               |
| `MAX_DIRECT_SLOTS`  |   4 000 | ids de slots max dans le slot tête (~120 Mo)    |
| `MAX_INDEX_SLOTS`   |   4 080 | ids de slots max par `FileIndexBlock` (~120 Mo) |

---

#### Répertoire (`VaultNode::Directory`)

```json
{
  "Directory": {
    "kind": "directory",
    "entries": [
      { "name": "fichier.txt", "slot": 42, "kind": "file" },
      { "name": "sous-dossier", "slot": 7,  "kind": "directory" }
    ]
  }
}
```

---

#### Fichier — slot tête (`VaultNode::File`, kind=`"file"`)

Contient les métadonnées du fichier, l'index ordonné des slots de continuation,
et les données du chunk 0 en ligne.

```json
{
  "File": {
    "kind":        "file",
    "total_size":  123456,
    "data_slots":  [17, 23, 41, 58],
    "index_chain": null,
    "data":        "<chunk 0, ≤ 30 000 octets>"
  }
}
```

- `data_slots` : ids physiques des slots de continuation, dans l'ordre
  (chunk 1 = `data_slots[0]`, chunk 2 = `data_slots[1]`, …).
  Contient jusqu'à `MAX_DIRECT_SLOTS` entrées (fichiers ≤ ~120 Mo + 30 Ko).
- `index_chain` : slot d'un `FileIndexBlock` si `data_slots` est saturé,
  `null` sinon.
- `data` : octets du chunk 0 en ligne (≤ `CHUNK_SIZE`).

---

#### Fichier — chunk de continuation (`VaultNode::FileData`, kind=`"file_data"`)

Contient uniquement les données brutes d'un chunk (chunks 1, 2, …).
Aucun pointeur — l'index est dans le slot tête.

```json
{
  "FileData": {
    "kind": "file_data",
    "data": "<chunk N, ≤ 30 000 octets>"
  }
}
```

---

#### Fichier — index overflow (`VaultNode::FileIndex`, kind=`"file_index"`)

Utilisé uniquement pour les fichiers dépassant `MAX_DIRECT_SLOTS + 1` chunks
(≈ 120 Mo). Peut chaîner pour supporter des fichiers arbitrairement grands.

```json
{
  "FileIndex": {
    "kind":       "file_index",
    "slot_ids":   [102, 107, 115, 122],
    "next_index": null
  }
}
```

- `slot_ids` : ids des chunks suivants dans l'ordre (≤ `MAX_INDEX_SLOTS`).
- `next_index` : slot du prochain `FileIndexBlock`, ou `null`.

---

#### Structure complète d'un fichier

```
Slot tête (VaultNode::File)
  ├── data          → chunk 0 (inline, ≤ 30 KB)
  ├── data_slots    → [slot_A, slot_B, …]  (chunks 1..MAX_DIRECT_SLOTS)
  └── index_chain ──→ FileIndexBlock
                         ├── slot_ids  → [slot_X, slot_Y, …] (chunks suivants)
                         └── next_index ──→ FileIndexBlock → …

Chaque slot_A / slot_X pointe vers un VaultNode::FileData
  └── data → chunk N (≤ 30 KB)
```

Capacité par niveau d'index :

| Niveau                       | Chunks supplémentaires | Taille fichier max cumulée |
|------------------------------|----------------------:|---------------------------|
| Inline dans tête (chunk 0)   |                     1 | 30 Ko                      |
| `data_slots` dans tête       |             4 000     | ~120 Mo                    |
| 1 `FileIndexBlock`           |             4 080     | ~242 Mo                    |
| N `FileIndexBlock` chaînés   |        N × 4 080      | illimité                   |

Accès aléatoire en O(1) : `chunk_index → data_slots[i]` ou
O(profondeur de chaîne) ≤ O(2) pour les fichiers < 480 Mo.

---

## 6. Fichiers de clés

### 6.1 Fichier `.key` non protégé (1 785 octets)

```
Offset   Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0          4     [u8; 4]     magic b"VKEY"
4          4     u32 LE      version = 1
8          8     u64 LE      created_at (timestamp Unix)
16        64     [u8; 64]    label UTF-8 null-paddé
80         8     [u8; 8]     fingerprint = SHA-256(x25519_pk ‖ mlkem_ek)[0..8]
88        32     [u8; 32]    x25519_pk — clé publique X25519
120     1 568     [u8; 1568]  mlkem_ek — clé d'encapsulation ML-KEM-1024
1 688      1     u8          protected = 0
1 689     32     [u8; 32]    x25519_sk — scalaire privé X25519 (en clair)
1 721     64     [u8; 64]    mlkem_seed — graine 64 octets pour régénérer la paire ML-KEM
──────────────────────────────────────────────────────────────────────────
Total  1 785 octets
```

### 6.2 Fichier `.key` protégé par phrase secrète (1 886 octets)

```
Offset   Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0       1 688    —           identique au format non protégé (§6.1, octets 0–1687)
1 688      1     u8          protected = 1
1 689     64     [u8; 64]    argon2_salt (aléatoire)
1 753      1     u8          kdf_profile (0=interactive, 1=sensitive)
1 754    132     VNMB block  AEAD(derived_key, ChaCha20-Poly1305,
                               aad=b"vnm:key:protect:v1",
                               plaintext = x25519_sk(32) ‖ mlkem_seed(64))
──────────────────────────────────────────────────────────────────────────
Total  1 886 octets
```

Dérivation de la clé de protection :
```
derived_key = Argon2id(passphrase, salt=bytes[1689..1753], profile=bytes[1753])
```

### 6.3 Fichier `.pub` — clé publique seule (1 688 octets)

```
Offset   Taille  Type        Description
──────────────────────────────────────────────────────────────────────────
0          4     [u8; 4]     magic b"VPUB"
4          4     u32 LE      version = 1
8          8     u64 LE      created_at (timestamp Unix)
16        64     [u8; 64]    label UTF-8 null-paddé
80         8     [u8; 8]     fingerprint = SHA-256(x25519_pk ‖ mlkem_ek)[0..8]
88        32     [u8; 32]    x25519_pk
120     1 568     [u8; 1568]  mlkem_ek
──────────────────────────────────────────────────────────────────────────
Total  1 688 octets
```

---

## 7. Détails cryptographiques

### 7.1 KDF — Argon2id

| Profil        | Mémoire     | Itérations | Parallélisme | Sortie |
|---------------|------------:|----------:|-------------:|-------:|
| `interactive` | 65 536 KiB  |         3 |            4 |   32 B |
| `sensitive`   | 262 144 KiB |         4 |            4 |   32 B |

Algorithme : Argon2id, version 0x13 (NIST SP 800-232).

### 7.2 Chiffrement authentifié (AEAD)

| cipher_id | Algorithme          | Taille clé | Taille nonce | Tag  |
|----------:|---------------------|:----------:|:------------:|:----:|
| 0         | ChaCha20-Poly1305   | 256 bits   | 96 bits      | 128 bits |
| 1         | AES-256-GCM         | 256 bits   | 96 bits      | 128 bits |

Le nonce est généré aléatoirement à chaque écriture (non incrémental).

### 7.3 KEM hybride — X25519 + ML-KEM-1024

Tailles des composants :

| Composant          | Taille  | Description                             |
|--------------------|--------:|-----------------------------------------|
| X25519 sk          |    32 B | scalaire secret                         |
| X25519 pk          |    32 B | point public                            |
| ML-KEM-1024 seed   |    64 B | graine → régénère la paire complète     |
| ML-KEM-1024 ek     | 1 568 B | clé d'encapsulation (publique)          |
| ML-KEM-1024 ct     | 1 568 B | chiffré KEM                            |
| shared secret      |    32 B | SHA-256 des deux secrets                |

Combinaison des secrets partagés :
```
hybrid_key = SHA-256(
    b"venom:hybrid:v1"      (16 B, séparateur de domaine)
    ‖ x25519_shared         (32 B)
    ‖ mlkem_ss              (32 B)
    ‖ x25519_eph_pk         (32 B, lie le chiffré X25519)
    ‖ mlkem_ct              (1568 B, lie le chiffré KEM)
)
```

Sécurité : le conteneur reste sécurisé si **l'un des deux** algorithmes
tient (X25519 contre l'attaquant classique, ML-KEM-1024 contre le quantique).

### 7.4 Fingerprint (fichiers de clés uniquement)

```
fingerprint[8] = SHA-256(x25519_pk ‖ mlkem_ek)[0..8]
```

Le fingerprint est stocké dans les fichiers `.key` et `.pub` pour l'interface
utilisateur (identification d'une clé dans le gestionnaire). Il n'est **pas**
présent dans les slots destinataires du conteneur — les slots sont testés à
l'aveugle pour préserver l'anonymat des destinataires.

---

## 8. Procédure d'ouverture

```
1. Tenter d'ouvrir l'en-tête extérieur primaire [0..512] :
     a. Lire cipher_id, kdf_profile, num_password_slots, num_key_slots
     b. Pour chaque password slot [0..num_password_slots) à offset (1024 + i×101) :
          slot_key = Argon2id(password, salt=slot[0..32], profile=slot[32])
          K_master = AEAD_decrypt(slot_key, slot[33..101])
          Si succès → aller en 1d
     c. Pour chaque key slot [0..num_key_slots) à offset (1832 + j×1668) :
          Décapsuler (essai aveugle) → K_master
          Si succès → aller en 1d
     d. Déchiffrer le bloc VNMB [68..500] avec K_master → valider magic b"VNM1"

2. Si l'étape 1 échoue (header corrompu) → recommencer avec le backup [512..1024]

3. Si succès : accéder aux slots via DATA_AREA_OFFSET + slot_index × SLOT_SIZE
```

Pour le volume caché :
```
1. Tenter d'ouvrir l'en-tête caché primaire [EOF-512..EOF] :
     K_hidden = Argon2id(password, salt=hdr[0..64], profile=hdr[65])
     Déchiffrer bloc VNMB → valider magic b"VNM1"

2. Si échec → tenter le backup [EOF-1024..EOF-512]

3. Si succès : slots du volume caché = [hidden_start .. hidden_start + outer_slots)
```

La procédure d'ouverture essaie toujours le primaire en premier ; le backup
n'est utilisé qu'en cas d'échec d'authentification AEAD (corruption physique).
Un mauvais mot de passe échoue sur les deux et retourne `AuthenticationFailed`.

---

## 9. Sémantique d'écriture (driver FUSE)

Cette section décrit le comportement observable lors d'une copie de fichier
dans un conteneur monté. Elle ne fait pas partie du format binaire mais
est nécessaire pour comprendre quand les données sont physiquement sur disque.

### 9.1 Cycle de vie d'un fichier en écriture

```
Opération FUSE       Disque              RAM (cache)
─────────────────────────────────────────────────────────────────
create()             slot tête créé ✓    cache vide
write(chunk 0)       —                   cache[0] = données, dirty
write(chunk 1..N)    —                   cache[1..N] = données, dirty
                                         ↑ tant que dirty_cont ≤ 128
─────────────────────────────────────────────────────────────────
seuil dépassé        chunks anciens      dirty count ≤ 128 chunks
(write-through)      écrits sur disque ✓
─────────────────────────────────────────────────────────────────
close() / flush()    chunks dirty ✓      cache vidé
                     slot tête mis
                     à jour (index) ✓
─────────────────────────────────────────────────────────────────
```

### 9.2 Garanties

| Propriété | Valeur |
|-----------|--------|
| RAM max par fichier ouvert | `MAX_CACHE_CHUNKS × CHUNK_SIZE` ≈ **7,7 Mo** |
| Seuil write-through | `WRITE_THROUGH_THRESHOLD` = **128 chunks** ≈ 3,8 Mo dirty |
| Données visibles dans l'index | uniquement après `close()` (slot tête mis à jour) |
| Perte en cas de crash avant `close()` | chunks écrits par write-through sont sur disque ; chunk 0 et l'index tête sont perdus |

### 9.3 Atomicité

Le slot tête (qui contient `total_size` et l'index `data_slots` complet) est
écrit en dernier, lors du `flush()` final. Tant qu'il n'est pas mis à jour,
le fichier apparaît avec son ancienne taille dans le répertoire parent.

Les chunks de continuation écrits en write-through sont physiquement sur
disque mais non référencés dans le slot tête — ils seront inclus dans
l'index lors du prochain `flush()`. Un crash entre le write-through et le
`flush()` final laisse des slots orphelins qui seront récupérés par un
éventuel outil de réparation (`fsck`).
