# ADR-0022 — Recherche d'empreinte sur VirusTotal

- **Statut** : accepté (22/11/2026). **DÉROGATION explicite** à la décision du plan de projet « Hébergement : UE uniquement, aucun service externe (pas de CDN ni d'API tierce) », rappelée dans ADR-0018 et ADR-0021. C'est la première et la seule sortie de Keryx vers un service tiers. **Essayé seulement contre un faux serveur** (`tests/fake_virustotal.py`), **jamais contre le vrai VirusTotal** : voir « À valider » plus bas.
- **Pourquoi** : pour qualifier une alerte, l'analyste veut savoir si un fichier (pièce déposée, fichier signalé par le contrôle d'intégrité de Wazuh) est déjà connu comme malveillant. Sans cela, il copie l'empreinte dans un navigateur, hors de Keryx : la recherche n'est ni tracée ni rattachée au ticket.
- **Exigence** : aucune exigence de la matrice du projet n'impose de consulter un service de réputation. La fonction est une **demande de l'utilisateur** (22/11/2026). Elle est rattachée à la qualification (PDIS IV.2.1.q) et au traitement des codes malveillants (PRIS IV.3.q) qu'elle outille ; sa traçabilité relève de PRIS VI.5.3.d (registre des actions), d'ISO/IEC 27037 (chaîne de possession) et de PDIS IV.3.9.c (journalisation).
- **Dépendance** : aucune ajoutée. L'appel utilise `httpx`, déjà présent pour le SSO ; la SBOM est inchangée.

## Ce qui sort de Keryx, et ce qui n'en sort pas

| Sort vers VirusTotal | Ne sort jamais |
|---|---|
| **Une empreinte** de fichier : SHA-256 ou SHA-1 (64 ou 40 caractères hexadécimaux), dans le chemin de la requête | Le fichier, ou la moindre partie de son contenu |
| **La clé d'API de l'utilisateur** qui lance la recherche (en-tête `x-apikey`) | Le nom du fichier, sa taille, son type, sa description |
| **L'adresse IP de sortie** du serveur Keryx (ou du mandataire), l'heure de la requête | Le client, le ticket, l'équipement, l'alerte, l'identité de l'analyste dans Keryx |
| L'en-tête `User-Agent: keryx` | Tout cookie, toute session, tout autre en-tête d'identification |

Une seule requête existe : `GET https://www.virustotal.com/api/v3/files/{empreinte}`. Aucune requête n'est émise sans le geste d'un analyste ou d'un manager sur une empreinte précise : pas de recherche automatique à l'ingestion ni au dépôt, pas de recherche en arrière-plan, et **enregistrer une clé n'appelle pas VirusTotal**.

Le lien « Ouvrir la fiche sur VirusTotal » affiché avec un résultat est une autre sortie, depuis le **navigateur de l'analyste** cette fois : s'il le suit, son poste contacte `www.virustotal.com` directement (nouvel onglet, `rel="noopener noreferrer"`, en-tête `Referrer-Policy: no-referrer` : l'adresse de la fiche Keryx n'est pas transmise). L'adresse est construite par Keryx (`https://www.virustotal.com/gui/file/{empreinte}`), jamais lue dans la réponse.

## Risques

- **VirusTotal est un service américain** (hors UE), tiers au SOC et au client. Il **apprend qu'une empreinte donnée intéresse le titulaire de telle clé, depuis telle adresse IP, à telle heure**. Pour un fichier public (un outil, un maliciel répandu), cela ne dit presque rien. Pour un fichier propre à un client ou forgé pour l'attaquer, la recherche peut révéler qu'il a été trouvé : l'attaquant qui surveille son échantillon, ou tout abonné du service qui voit les recherches, peut en déduire qu'il est détecté.
- **Une empreinte ne révèle pas le contenu** du fichier : elle ne permet pas de le reconstituer. Elle permet en revanche de **confirmer** qu'on détient un fichier donné à qui possède déjà ce fichier.
- **La clé d'API** identifie son titulaire auprès de VirusTotal. Les **conditions de l'API publique gratuite sur l'usage commercial sont à vérifier par l'exploitant** avant tout usage pour le compte de clients : cet ADR ne les affirme pas, et Keryx ne distingue pas une clé gratuite d'une clé sous contrat.
- **Réponse non fiable** : tout ce que VirusTotal renvoie (noms de fichiers, noms donnés par les moteurs, étiquettes) est fourni par des tiers. Un nom peut contenir du balisage ou des caractères de contrôle.
- **Un résultat n'est pas un verdict.** « Inconnu de VirusTotal » ne veut pas dire sain ; « aucune détection » non plus.
- **Réglage d'essai** : `KERYX_VIRUSTOTAL_URL` fait partir les empreintes **et les clés des utilisateurs** vers l'adresse réglée. Il n'existe que pour les essais ; le serveur l'écrit dans son journal au démarrage.

## Décision

**Disponible par défaut** (décision de l'utilisateur du 22/11/2026) : pas d'activation par l'Admin, pas d'accord par client, pas de blocage selon le marquage TLP du ticket ou de la pièce. Ce choix est assumé comme une dérogation ; ses garde-fous sont : seule l'empreinte sort, un geste explicite par recherche, une clé personnelle (sans clé, rien ne part), une trace de chaque recherche, et l'interrupteur ci-dessous. Un exploitant qui ne veut pas de cette sortie la coupe ; il peut aussi fermer la sortie réseau du serveur vers `www.virustotal.com` (les recherches échouent alors proprement, en 503).

**Interrupteur d'instance** : `KERYX_VIRUSTOTAL_ENABLED` (vrai par défaut). À `false` : les routes de recherche, de liste des empreintes et d'enregistrement de la clé répondent 409 ; `features.virustotal` de `/api/v1/me` est faux et l'interface ne montre rien ; la fiche d'un ticket ne porte plus le bloc `virustotal`. Les recherches déjà faites restent en base, à l'audit et au registre des actions des tickets. Le retrait de sa propre clé reste possible (un secret doit toujours pouvoir être effacé).

**Clé par utilisateur**, saisie dans le profil (analyste et manager ; client et Admin : 403) : `GET /api/v1/me/virustotal` → `{configured, enabled}` ; `PUT` `{api_key}` ; `DELETE`. La clé est chiffrée au repos en AES-256-GCM comme le secret TOTP (ADR-0006), colonne `users.vt_api_key`, contexte `vt_api_key:<id du compte>` (recopiée sur un autre compte, elle ne se déchiffre pas). Elle n'est **jamais renvoyée** (seul son état l'est), jamais journalisée, jamais inscrite à l'audit (`auth.vt_key_set`, `auth.vt_key_removed` : sans la clé). Forme contrôlée : 32 à 128 lettres et chiffres, les blancs autour sont retirés ; l'erreur ne recopie pas la saisie. **L'Admin ne voit rien de la clé** : aucune route d'administration ne la renvoie, pas même un indicateur ; il voit seulement, dans le journal d'audit, qu'un compte a enregistré ou retiré une clé (action et date, sans contenu). Un compte qui quitte les rôles analyste ou manager perd sa clé (l'audit de la modification du compte note « effacée »). La clé n'est pas essayée à l'enregistrement : pas de bouton « tester », une clé refusée se voit à la première recherche.

**Sources d'une empreinte**, toutes sur la fiche d'un ticket (`POST /api/v1/tickets/{ref}/virustotal`) :

1. **Une pièce du ticket** (`{"source": "piece", "attachment_id": …}`) : **le serveur prend l'empreinte lui-même** ; une empreinte envoyée par le navigateur avec une pièce est refusée (422).
   - Archive : l'empreinte de la pièce, qui est celle du fichier reçu. **Une pièce en quarantaine garde l'empreinte de l'original** (c'est l'archive chiffrée qui est stockée, ADR-0019) : c'est le cas le plus utile.
   - **Image** : Keryx la ré-encode au dépôt (ADR-0008), donc l'empreinte de la pièce est celle d'un fichier qui n'existe que dans Keryx et que VirusTotal ne peut pas connaître. L'empreinte du fichier **reçu** n'est conservée que dans le motif de l'événement de dépôt de la chaîne de possession (« empreinte reçue … ») : quand elle s'y trouve, **c'est elle qui est cherchée**, et la trace le dit (« fichier reçu, avant ré-encodage de l'image »). Sinon (dépôt ancien, ou image que le ré-encodage n'a pas modifiée), c'est l'empreinte de la pièce.
   - Un document produit par Keryx (jeu de contexte Wazuh conservé, ADR-0021) n'est pas proposé : son empreinte ne désigne aucun fichier qui existe ailleurs.
2. **Une preuve externe** (même appel) : l'empreinte déclarée par l'analyste.
3. **Une empreinte d'alerte** (`{"source": "alerte", "hash": …}`) : elle doit figurer dans une alerte brute conservée **de ce ticket** (422 sinon). Extraction défensive et bornée : seuls `syscheck` (`sha256_after`, `sha1_after`, `sha256_before`…) et `data.*` sont lus, y compris les listes « SHA1=…,SHA256=… » de Sysmon ; 25 alertes, 2 000 valeurs par alerte, profondeur 8, 40 empreintes par ticket.
4. **Une saisie manuelle** (`{"source": "saisie", "hash": …}`).

`GET /api/v1/tickets/{ref}/virustotal/hashes` liste les empreintes des pièces et des alertes (lecture tracée, rien ne sort). Seuls **SHA-256 et SHA-1** sont acceptés, en minuscules, par expression régulière stricte. **MD5 est refusé** : ses collisions sont praticables, un rapport obtenu par MD5 peut décrire un autre fichier que celui du ticket, et Wazuh fournit SHA-1 et SHA-256.

**Accès** : analyste et manager affectés au client du ticket. Client et Admin : 403, par un contrôle de rôle placé avant la validation du corps (le même que pour le contexte Wazuh) ; la tentative d'un Admin est tracée. Ticket d'un autre client : 404. La recherche reste possible sur un ticket clos, comme un téléchargement.

**Appel sortant** (`keryx/virustotal.py`, client isolé) :

- **hôte fixe** `www.virustotal.com` : aucun utilisateur, pas même l'Admin, ne saisit d'adresse ; il n'y a donc pas de requête forgée côté serveur à craindre. Le chemin ne contient que l'empreinte validée ;
- HTTPS (TLS 1.2 au moins), certificat vérifié contre le magasin d'autorités du système ; aucun réglage ne désactive ce contrôle ni n'ajoute une autorité, et devant un certificat non reconnu la négociation échoue avant que la clé ne parte ; **aucune redirection suivie** ; **aucun mandataire d'environnement** (`HTTP_PROXY` et consorts ne sont pas lus) ; un mandataire explicite est possible (`KERYX_VIRUSTOTAL_PROXY`, `http://hôte:port`, sans identifiants) ;
- 3 s pour se connecter, 8 s pour l'ensemble ; réponse bornée à 4 Mio ; réponse non compressée demandée, et si elle arrive tout de même en gzip elle est décompressée sous la même borne ; JSON seulement ;
- un client HTTP neuf par recherche : ni connexion ni clé gardées en mémoire entre deux appels.

Pour les essais seulement, `KERYX_VIRUSTOTAL_URL` remplace l'adresse de base : accepté en HTTPS, ou en HTTP vers la boucle locale si `KERYX_VIRUSTOTAL_ALLOW_LOOPBACK=true`. Une adresse refusée arrête le démarrage. **Ne pas le régler en production.**

**Résultats** :

| Réponse de VirusTotal | Ce que fait Keryx |
|---|---|
| 200 | « trouvé » : compteurs `malicious` / `suspicious` / `harmless` / `undetected` et total, date de dernière analyse et de première soumission (UTC, RFC 3339), nom et type du fichier, taille, étiquette de menace suggérée, au plus 8 noms donnés par des moteurs, SHA-256 annoncé |
| 404 avec l'enveloppe d'erreur JSON de l'API | **« inconnu de VirusTotal »** : jamais présenté comme sain (pastille neutre, phrase « cela ne dit rien du fichier ») |
| 404 d'une autre forme (page d'un mandataire, mauvaise adresse) | erreur 502 : un faux « inconnu » ne doit pas entrer au registre |
| 401, 403 | 502, « VirusTotal refuse votre clé d'API : vérifiez-la ou remplacez-la dans votre profil » |
| 429 | 429, « quota de votre clé atteint » |
| Rapport d'une autre empreinte que celle demandée | 502 : il n'est pas attribué à ce fichier |
| Redirection, autre statut, réponse illisible ou trop grande | 502 ; injoignable ou trop lent : 503 |

Aucun message d'erreur ne contient la clé, un en-tête ou le corps de la réponse. Tout texte venant de VirusTotal est ramené à du **texte pur et borné** (`clean_text`, le même assainissement que le contexte Wazuh : pas de caractère de contrôle, pas de marque de sens d'écriture) et l'interface le rend comme du texte, jamais comme du HTML. Les compteurs sont des entiers bornés ; aucune adresse de la réponse n'est reprise. Un fichier « trouvé » sans aucune détection n'est pas présenté comme sain non plus : la pastille reste neutre, la phrase dit qu'une absence de détection ne prouve rien. Il n'existe pas de pastille verte.

**Traçabilité** : chaque recherche aboutie (trouvé ou inconnu) est inscrite

- dans la table **`hash_lookups`** (migration 0018) : ticket, client, empreinte, type, type et identifiant de la source, statut, résumé JSON borné, auteur, date UTC ; affichée sur la fiche pour l'équipe, **jamais au client** (le bloc `virustotal` est absent de sa vue) ;
- au **registre des actions du ticket** par un événement interne `virustotal_lookup` ;
- à l'**audit** : `ticket.virustotal_lookup` (empreinte, source, statut, compteurs ; jamais la clé, jamais les textes de la réponse) ;
- si la source est une pièce ou une preuve externe, dans sa **chaîne de possession** : événement `analyse_virustotal` (empreinte cherchée, d'où elle vient, connu ou inconnu).

**Un échec n'enregistre aucun résultat** : seulement l'entrée d'audit `ticket.virustotal_lookup_failed` (empreinte, source, catégorie de l'échec) et une ligne dans le journal du serveur, sans la clé. La liste des empreintes d'un ticket est tracée par `ticket.virustotal_hashes`.

**Débit** : 4 recherches par minute et par utilisateur (`KERYX_VIRUSTOTAL_USER_LIMIT` ; valeur demandée par l'utilisateur, à rapprocher par l'exploitant du quota réel de la clé employée) et 20 par minute et par client (`KERYX_VIRUSTOTAL_CLIENT_LIMIT`) ; réponse 429 (RFC 6585). Une demande refusée avant l'appel (422, 409) ne consomme rien.

**Rétention** : les lignes de `hash_lookups` suivent le ticket (supprimées avec lui). La purge des alertes brutes ne les touche pas. Lors d'une fusion, elles restent sur le ticket où la recherche a été faite.

## Déploiement visant la qualification PDIS : fonction coupée (ajout du 22/11/2026)

Dans un déploiement qui vise la qualification PDIS : **`KERYX_VIRUSTOTAL_ENABLED=false`**. Texte lu dans le référentiel PDIS v2.0 du 21/12/2017, chapitre IV.3.7 (« Service de détection du service », la détection que le prestataire opère sur son propre système d'information) :

- IV.3.7.j : « Il est recommandé que le prestataire utilise des outils permettant de réaliser une analyse statique ou dynamique de fichiers suspects. »
- IV.3.7.k : « Dans le cas où le prestataire utilise des outils d'analyse statiques ou dynamiques de fichiers suspects faisant appel à des ressources hébergées sur Internet, le prestataire doit réaliser ces opérations hors du système d'information du service de détection des incidents de sécurité ».

L'exigence est placée dans ce chapitre, mais ce qu'elle vise ne dépend pas de lui : un outil du système d'information du service qui interroge Internet à propos d'un fichier suspect, ce que fait cette recherche. Deux autres passages vont dans le même sens : la liste des interconnexions autorisées (IV.3.10.a) ne comprend aucune sortie vers un service d'Internet, et les recherches en sources ouvertes se font depuis la zone internet, hors du système d'information du service, sur des postes dédiés, en étant horodatées et journalisées (IV.3.16.a, d, f). L'analyste fait donc la recherche depuis son poste de la zone internet, et reporte le résultat sur la fiche. L'interprétation de IV.3.7.k appartient à l'organisme de qualification ; cet ADR retient la lecture prudente.

Le kit `deploy/docker` (ADR-0023) écrit `KERYX_VIRUSTOTAL_ENABLED=false` tant que la sortie réseau de Keryx est fermée, ce qui est son réglage par défaut. Hors de ce cas, la décision ci-dessus (fonction disponible par défaut) est inchangée.

## Envoi de fichier : non fait, et ce qu'il faudrait

**Keryx n'envoie aucun fichier à VirusTotal : il n'existe ni route, ni code, ni réglage pour cela.** Un fichier envoyé à VirusTotal devient accessible à ses abonnés : c'est une divulgation, sans retour possible. Le client HTTP est isolé dans `keryx/virustotal.py` (`Client`) pour qu'un envoi puisse y être ajouté comme une seconde opération, mais seulement après une nouvelle décision, qui devra au moins régler :

1. **Accord du client**, explicite et par client (réglage posé par l'Admin, tracé), sans valeur par défaut ; la convention de service doit le prévoir.
2. **Marquage TLP** : refus au-dessus d'un seuil à fixer (par exemple, jamais pour TLP:AMBER+STRICT et TLP:RED), jugé sur la sensibilité de la pièce **et** celle du ticket.
3. **Taille** : borne propre à l'envoi (l'API de VirusTotal a ses propres limites, à vérifier), jamais une preuve externe.
4. **Confirmation** de l'analyste à chaque envoi, avec le nom de la pièce et la conséquence écrite ; envoi réservé à un rôle à décider.
5. **Chaîne de possession** : événement dédié (divulgation à un tiers), distinct de `analyse_virustotal`.
6. **Quarantaine** : envoyer l'original, pas l'archive chiffrée ; ne jamais envoyer une image ré-encodée à la place du fichier reçu.
7. Un nouvel ADR, une nouvelle revue de la dérogation, et des essais contre le vrai service.

## À valider sur le vrai VirusTotal (rien de ceci n'a été essayé)

1. **Forme des réponses** : `data.attributes` avec `last_analysis_stats`, `last_analysis_results`, `last_analysis_date`, `first_submission_date`, `meaningful_name`, `type_description`, `size`, `popular_threat_classification.suggested_threat_label`, `sha256`, `sha1`. Écrit d'après la connaissance de l'API v3, non vérifié sur le service.
2. **Fichier inconnu** : Keryx attend un statut 404 avec un corps JSON `{"error": {…}}`. Si le service répond autrement, un fichier inconnu donnera une erreur 502 (jamais un faux résultat).
3. **Clé** : forme réelle des clés (la borne 32 à 128 lettres et chiffres est volontairement large) ; statuts renvoyés pour une clé invalide (401) ou sans droit (403) ; quotas réels (429).
4. **Recherche par SHA-1** : acceptée par le service à la même adresse que par SHA-256.
5. **Codage de la réponse** : Keryx demande `Accept-Encoding: identity` ; vérifier que le service répond sans compression ou en gzip (seuls cas acceptés).
6. **Taille** des rapports : la borne de 4 Mio doit suffire aux rapports les plus fournis.
7. **Mandataire** : `KERYX_VIRUSTOTAL_PROXY` n'a été essayé qu'en HTTP en clair vers le faux serveur ; le mode CONNECT vers un hôte HTTPS est celui de la bibliothèque `httpx` et n'a pas été essayé.
8. **Certificat** : la voie HTTPS n'a été essayée que contre le faux serveur muni d'une autorité privée (refus, puis succès une fois l'autorité reconnue), jamais contre le certificat réel de `www.virustotal.com` ; le magasin d'autorités du système doit être présent sur le serveur (paquet `ca-certificates`).
9. **Conditions d'utilisation** de la clé employée (usage commercial, volume) : à vérifier par l'exploitant.

## Écarts et limites

- Pas de recherche automatique, pas de recherche groupée, pas de rafraîchissement d'un résultat : chaque recherche est un nouveau geste et une nouvelle ligne.
- Une image dont le ré-encodage ne change rien (cas rare) et une image déposée avant que l'empreinte reçue ne soit notée ne se distinguent pas : dans les deux cas, c'est l'empreinte de la pièce qui est cherchée.
- Les empreintes d'alertes sont repérées par leur forme : une suite de 40 ou 64 caractères hexadécimaux d'un champ `data.*` qui n'est pas une empreinte de fichier sera proposée aussi. C'est l'analyste qui choisit ce qu'il cherche.
- Les recherches ne figurent ni dans le rapport d'incident imprimable ni dans l'export IODEF.
- Le résumé conservé est celui du moment de la recherche ; le rapport complet reste sur VirusTotal.
- **Exigences** : PDIS IV.2.1.q (qualification), PRIS IV.3.q (codes malveillants) ; PRIS VI.5.3.d (registre des actions) ; ISO/IEC 27037 et RFC 3227 (chaîne de possession) ; PDIS IV.3.8.g (cloisonnement), IV.3.9.c (journalisation), IV.3.9.d à h (séparation Admin / opérateurs) ; ISO/IEC 27002:2022 8.24 (secrets, via ADR-0006) ; RFC 6585 (429), RFC 9457 (erreurs), RFC 3339 (dates UTC). Les références PDIS et PRIS sont reprises de la matrice du projet ; le texte des normes ISO n'a pas été revérifié ici, et aucun numéro d'exigence ASVS n'est cité faute de l'avoir dans la matrice.
