# ADR-0011 — Administration dans l'interface

- **Statut** : accepté (20/11/2026)
- **Décision** : comptes, clients, clés d'API, table MITRE, revue des comptes, journal d'audit et état du système s'administrent dans l'interface, réservés au rôle Admin (la table MITRE est aussi ouverte au Manager). Les clés d'API ne sont affichées qu'une seule fois. Le secret TOTP et les codes de secours d'un utilisateur ne sont JAMAIS vus par l'Admin : le compte est créé avec un mot de passe temporaire, et le titulaire active lui-même sa double authentification à sa première connexion (génération du secret, vérification d'un code, choix de son mot de passe, affichage unique de ses codes de secours). Toute modification de rôle, de clients ou de statut d'un compte ferme ses sessions. Un Admin ne peut ni changer son propre rôle ni se désactiver. La réinitialisation de la 2FA est réservée à l'Admin et tracée.
- **Exigences** : PDIS IV.3.9.d à h (séparation administrateur / opérateur) ; PDIS IV.3.4.b (revue des comptes) ; PRIS IV.3.n, o ; ISO/IEC 27002 5.15, 5.16, 5.18, 8.2.
- **Limite** : tant que le titulaire n'a pas activé son compte, le mot de passe temporaire est connu de l'Admin ; il est inutilisable pour accéder aux données (la 2FA est obligatoire) et il est refusé comme mot de passe définitif.
- **Cloisonnement** : aucune route d'administration ne donne accès au contenu des tickets.
