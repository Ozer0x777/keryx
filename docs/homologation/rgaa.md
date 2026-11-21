# Accessibilité (RGAA) — état et périmètre d'audit

*Ce document n'est pas une déclaration de conformité.* Aucun audit RGAA n'a été réalisé : il exige un auditeur et des tests manuels (lecteur d'écran, navigation clavier complète, zoom, contrastes en situation, contenus riches) que l'équipe n'a pas menés.

## Ce qui a été contrôlé automatiquement
- **axe-core** (règles WCAG 2.1 A et AA) sur 19 écrans de 3 rôles (admin, manager, client) : aucune violation détectée ; une violation corrigée en cours de route (région défilable atteignable au clavier). Reproduire : `cd e2e && node run.mjs` (scénario `90-accessibilite.mjs`). Un contrôle automatisé n'attrape qu'une partie des critères.
- Éléments conçus pour l'accessibilité : vrais `button`, `a`, `label`, `th scope`, `aria-sort` sur les colonnes triables, régions `role="status"` pour les messages, graphiques avec équivalent tableau, interface sans ressource externe, langue du document (`lang`) mise à jour, interface disponible en français et en anglais.

## À auditer (périmètre proposé)
Écrans : connexion (mot de passe, 2FA, activation, SSO, clé de sécurité), liste, Kanban (glisser-déposer : alternative au clavier fournie par le menu « Déplacer… »), fiche ticket (éditeur riche TipTap, pièces, registre de crise, classification ETSI ISI), portail client, tableau de bord et graphiques, rapports imprimables, administration, profil.
Points à vérifier en priorité : éditeur riche (clavier, lecteur d'écran), glisser-déposer du Kanban, notifications (cloche), fenêtres de confirmation du navigateur, impression, thème, responsive.

## Déclaration d'accessibilité
À rédiger par l'organisation après audit (état de conformité, contenus non accessibles, dérogations, contact, voies de recours).
