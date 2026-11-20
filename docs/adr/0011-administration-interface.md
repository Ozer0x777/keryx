# ADR-0011 — Administration dans l'interface

- **Statut** : accepté (20/11/2026)
- **Décision** : comptes, clients, clés d'API, table MITRE, revue des comptes, journal d'audit et état du système s'administrent dans l'interface, réservés au rôle Admin (la table MITRE est aussi ouverte au Manager). Les secrets générés (clé d'API, URI TOTP, codes de secours) ne sont affichés qu'une seule fois. Toute modification de rôle, de clients ou de statut d'un compte ferme ses sessions. Un Admin ne peut ni changer son propre rôle ni se désactiver. La réinitialisation de la 2FA est réservée à l'Admin et tracée.
- **Exigences** : PDIS IV.3.9.d à h (séparation administrateur / opérateur) ; PDIS IV.3.4.b (revue des comptes) ; PRIS IV.3.n, o ; ISO/IEC 27002 5.15, 5.16, 5.18, 8.2.
- **Compromis connu** : à la création d'un compte, l'Admin voit le secret TOTP de l'utilisateur (comme avec la ligne de commande). Un enrôlement par l'utilisateur à sa première connexion le supprimerait ; c'est une évolution prévue, pas encore faite.
- **Cloisonnement** : aucune route d'administration ne donne accès au contenu des tickets.
