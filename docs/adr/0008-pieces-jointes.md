# ADR-0008 — Pièces jointes, preuves et quarantaine

- **Statut** : accepté (20/11/2026)
- **Décision** :
  - Types acceptés, vérifiés par signature binaire (pas par l'extension) : archive ZIP, PNG, JPEG, WebP. 20 Mo maximum. Pas de SVG ni de HTML.
  - Images ré-encodées par Pillow (métadonnées EXIF et données ajoutées supprimées, limite de pixels contre les bombes de décompression).
  - Archives jamais décompressées par Keryx.
  - Stockage hors racine web, nom aléatoire, droits 0600, empreinte SHA-256.
  - Registre de collecte obligatoire : description, date et heure, méthode, sensibilité TLP.
  - Analyse ClamAV (protocole clamd INSTREAM) si configuré. Une détection place le fichier en quarantaine (répertoire séparé, jamais supprimé, jamais servi au client, servi à l'équipe en `application/octet-stream` après confirmation explicite).
  - Téléchargement d'une archive : motif obligatoire, inscrit dans la chaîne de possession comme chaque dépôt, restitution ou destruction (destruction réservée au manager).
  - Au-delà de 20 Mo : « preuve externe » référencée (empreinte, lieu de conservation) sans fichier.
- **Exigences** : PRIS VI.5.3.c, VI.2.4 ; PDIS IV.3.q ; ISO/IEC 27037 ; RFC 3227 ; ISO/IEC 27002:2022 8.7 (protection contre les logiciels malveillants).
- **Écart assumé** : le plan prévoyait de rezipper les fichiers en quarantaine avec un mot de passe. La bibliothèque standard Python ne sait pas chiffrer un ZIP ; plutôt que d'ajouter une dépendance, le fichier est isolé et marqué. À revoir si un outil d'analyse exige le format « zip infected ».
- **Limite** : sans ClamAV, les fichiers restent « non analysé » (affiché dans l'interface).
