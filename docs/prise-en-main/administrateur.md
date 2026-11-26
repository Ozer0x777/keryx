# Fiche administrateur

Le rôle Admin gère la plateforme ; **il n'a pas accès au contenu des tickets** (séparation entre administration
et exploitation, PDIS IV.3.9).

## Mettre en service

1. Installer (`deploy/docker/install.sh`, voir [`../deploiement-docker.md`](../deploiement-docker.md)). Le premier
   compte Admin est créé à l'installation, avec un code d'activation.
2. **Clients** : créer chaque client (clé courte, ex. `ACME`), puis « Paramétrer » : grille de gravité et délais
   cibles de qualification et de résolution s'ils diffèrent des valeurs par défaut, contacts de notification,
   rétention des alertes brutes, taille maximale d'une pièce, et le cas échéant la lecture de son indexeur Wazuh. Si
   plusieurs clients lisent le même indexeur, régler pour chacun sa « source Wazuh » (nom de son manager ou de son
   cluster) : Keryx l'exige pour ne jamais mêler leurs événements (ADR-0031).
3. **Parc d'agents** (facultatif) : dans « Paramétrer », l'adresse de l'API du manager Wazuh, le groupe Wazuh du
   client et un compte de lecture de l'API (création côté Wazuh : `integrations/wazuh/README.md`, section 6).
   L'équipe et le client voient alors l'état des agents ; vous voyez seulement si le relevé réussit.
4. **Clés d'API** : une clé d'ingestion par client, affichée une seule fois, à coller dans le bloc `<integration>`
   du manager Wazuh (voir `integrations/wazuh/README.md` ; en cluster, sur chaque nœud qui analyse des agents).
5. **Comptes** : créer les analystes et managers (rattachés aux clients qu'ils suivent) et les comptes clients
   (rattachés à un seul client). Chacun reçoit un code d'activation et enregistre lui-même sa double
   authentification.

Pour essayer avant de brancher Wazuh : `keryx demo` (client DEMO, dix incidents fictifs).

## Au quotidien

- **État du système** : antivirus, notifications en échec, sources Wazuh muettes, stockage, espace disque.
- **Revue des comptes** : rôle, clients, dernière connexion et état de chaque compte, exportable ; à faire à
  intervalle régulier.
- **Table MITRE** et **Journal d'audit** (consultation ; le détail des actions sur les tickets n'y est pas lisible
  par l'Admin).
- Sauvegardes : `keryx backup` (chiffrée), et vérification de la chaîne d'audit : `keryx verify-audit`.

## À ne pas faire

- Ne pas créer de compte partagé ; un compte par personne.
- Ne pas exporter de variable `KERYX_…` dans le terminal pour changer un réglage du kit Docker : modifier `.env`.
- Ne pas perdre `KERYX_SECRET_KEY` (fichier `.env`) : sans elle, les secrets chiffrés et les sauvegardes sont perdus.
