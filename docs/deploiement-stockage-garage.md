# Stockage des pièces : déploiement de Garage (auto-hébergé, UE)

*Choix retenu pour la production. Garage est un stockage objet libre compatible S3, développé par l'association française Deuxfleurs. Testé avec Garage 1.0.1 (signatures AWS v4 vérifiées par le serveur) ; la haute disponibilité (plusieurs nœuds) n'a pas été essayée ici.*

## Principe
Keryx chiffre chaque pièce (AES-256-GCM, clé dérivée de `KERYX_SECRET_KEY`) **avant** de l'envoyer : Garage ne voit jamais le contenu. Le chemin de l'objet est lié aux données authentifiées, donc un objet déplacé ou altéré ne se déchiffre pas. **Sans `KERYX_SECRET_KEY`, les pièces sont définitivement illisibles.**

## Installation (un nœud d'essai, puis production)
1. Installer le binaire Garage (voir garagehq.deuxfleurs.fr), créer l'utilisateur système, les dossiers `meta` et `data` sur des volumes sauvegardés.
2. Copier `deploy/garage/garage.toml.example` vers `/etc/garage.toml`, remplacer les deux secrets (`openssl rand -hex 32` et `openssl rand -base64 32`), lancer le service (`garage -c /etc/garage.toml server`, sous systemd).
3. Initialiser : `GARAGE_CONF=/etc/garage.toml ZONE=site1 CAPACITY=500G deploy/garage/init.sh keryx-pieces`. Le script règle la disposition du cluster, crée le bucket et une clé d'accès **dédiée à Keryx**, puis affiche les variables à placer dans l'environnement de Keryx.
4. Exposer l'API S3 (port 3900) **en HTTPS** derrière votre proxy TLS ; Keryx refuse une adresse en HTTP (sauf essai local avec `KERYX_S3_ALLOW_HTTP`).
5. Vérifier : Administration > État du système affiche « stockage objet : joignable » ; déposer une pièce, la télécharger.

## Production
- **Au moins 3 nœuds sur 3 sites**, `replication_factor = 3` : perdre un nœud ne perd aucune pièce. Un seul nœud n'est qu'un essai.
- Ne jamais exposer le port d'administration (3903) ni le port RPC (3901) hors du réseau interne.
- Sauvegardes : `keryx backup` ne contient plus les pièces dans ce mode ; sauvegarder les volumes de Garage (ou répliquer vers un second cluster). Une restauration doit être répétée régulièrement.
- Rotation de la clé d'accès : `garage key create` puis `garage bucket allow` pour la nouvelle, changer `KERYX_S3_ACCESS_KEY` / `_SECRET_KEY`, redémarrer Keryx, supprimer l'ancienne.

## Migrer des pièces déjà déposées sur disque
1. Configurer `KERYX_STORAGE=s3` et `KERYX_S3_*` dans l'environnement.
2. `keryx migrate-attachments --dry-run` (simulation), puis `keryx migrate-attachments` : chaque pièce est copiée, relue et comparée au fichier d'origine. La commande est rejouable et **ne supprime rien** : garder le dossier d'origine jusqu'à validation (téléchargement de quelques pièces, restauration d'essai).
3. Les pièces mises en quarantaine sont migrées telles quelles (archive chiffrée).
