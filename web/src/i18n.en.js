// Traductions anglaises. Clé = texte source français exact.
export default {
  // Navigation
  'Navigation principale': 'Main navigation', 'Détection': 'Detection', 'Portail client': 'Client portal', 'Administration': 'Administration',
  'Tickets': 'Tickets', 'Kanban': 'Kanban', 'Pilotage': 'Dashboard', 'Rapports': 'Reports', 'Table MITRE': 'MITRE table',
  "Journal d'audit": 'Audit log', 'Mes incidents': 'My incidents', 'Notifications': 'Notifications', 'Mon profil': 'My profile',
  'Se déconnecter': 'Sign out', '2FA active': '2FA enabled', 'Chargement…': 'Loading…',
  // Rôles
  'Admin': 'Admin', "Manager d'équipe": 'Team manager', 'Analyste': 'Analyst', 'Client': 'Client',
  // Statuts et libellés
  'Nouveau': 'New', 'En évaluation': 'Under assessment', 'En réponse': 'In response', 'Clôturé': 'Closed', 'Faux positif': 'False positive',
  "Retour d'exp.": 'Lessons learned', 'Détection et signalement': 'Detection and reporting', 'Évaluation et décision': 'Assessment and decision',
  'Confinement, éradication, rétablissement': 'Containment, eradication, recovery', 'Incident traité': 'Incident handled',
  'Clos après évaluation': 'Closed after assessment', 'Tirer les enseignements': 'Learn lessons',
  'Vrai positif — incident avéré': 'True positive — confirmed incident', 'Vrai positif — non avéré': 'True positive — not confirmed',
  'Limités': 'Limited', 'Significatifs': 'Significant', 'Graves': 'Severe', 'Standard': 'Standard', 'Sensible': 'Sensitive', 'Vital': 'Vital',
  'Non analysé': 'Not scanned', 'Sain': 'Clean', 'Quarantaine': 'Quarantine', 'Conservé': 'Kept', 'Restitué': 'Returned', 'Détruit': 'Destroyed',
  'Wazuh': 'Wazuh', 'Table': 'Table', 'Manuel': 'Manual', 'à compléter': 'to complete',
  // Connexion
  'Gestion des incidents de sécurité': 'Security incident management', 'Double authentification obligatoire pour tous les comptes.': 'Two-factor authentication is mandatory for all accounts.',
  'Chaque connexion et chaque action sont journalisées.': 'Every sign-in and action is logged.', 'Accès réservé aux personnes habilitées.': 'Access restricted to authorised people.',
  'Étape 1 sur 2': 'Step 1 of 2', 'Étape 2 sur 2': 'Step 2 of 2', 'Connexion': 'Sign in', 'Identifiant': 'Username', 'Mot de passe': 'Password',
  'Continuer': 'Continue', 'Code de secours': 'Recovery code', 'Code de vérification': 'Verification code', 'Vérifier': 'Verify', 'Retour': 'Back',
  "Saisissez l'un de vos codes de secours (usage unique).": 'Enter one of your recovery codes (single use).',
  "Saisissez le code à 6 chiffres de votre application d'authentification.": 'Enter the 6-digit code from your authenticator app.',
  'Utiliser un code de secours': 'Use a recovery code', 'Utiliser le code TOTP': 'Use the TOTP code', 'Code TOTP': 'TOTP code',
  'Après plusieurs échecs, le compte est verrouillé 15 minutes.': 'After several failures the account is locked for 15 minutes.',
  'Première connexion': 'First sign-in', "Code d'activation": 'Activation code', 'Activer votre compte': 'Activate your account',
  'Activer mon compte': 'Activate my account', 'Compte activé': 'Account activated', 'Nouveau mot de passe (12 caractères minimum)': 'New password (12 characters minimum)',
  'Confirmer le mot de passe': 'Confirm password', 'Les deux mots de passe ne correspondent pas.': 'The two passwords do not match.',
  "Saisissez le code d'activation qui vous a été remis (par courriel ou par votre administrateur).": 'Enter the activation code you were given (by e-mail or by your administrator).',
  'Code invalide, ou session expirée : recommencez si besoin.': 'Invalid code, or session expired: start again if needed.',
  // Liste des tickets
  'File des tickets': 'Ticket queue', 'Clients affectés : {clients}': 'Assigned clients: {clients}', 'aucun': 'none',
  'Vous voyez uniquement les tickets de votre organisation et les échanges qui vous sont destinés.': 'You only see your organisation’s tickets and the exchanges meant for you.',
  'Liste': 'List', 'Type de vue': 'View type', 'Synthèse': 'Summary', 'À qualifier': 'To qualify', 'nouveaux ou en évaluation': 'new or under assessment',
  'confinement / éradication': 'containment / eradication', 'Critiques ouverts': 'Open critical', 'gravité ou criticité': 'severity or criticality',
  'En retard': 'Overdue', 'échéance dépassée': 'deadline exceeded', 'REX en attente': 'Lessons learned pending', 'obligatoire si Élevée ou Critique': 'mandatory if High or Critical',
  'Vues': 'Views', 'Tous': 'All', 'Mes tickets': 'My tickets', 'Non assignés': 'Unassigned', 'Filtres :': 'Filters:', 'Filtres': 'Filters', 'Recherche': 'Search',
  'Titre, règle, agent, IP, commentaire…': 'Title, rule, agent, IP, comment…', 'Statut': 'Status', 'Client': 'Client', 'Réinitialiser': 'Reset', 'Enregistrer ce filtre': 'Save this filter',
  'Réf.': 'Ref.', 'Titre': 'Title', 'Criticité': 'Criticality', 'Gravité': 'Severity', 'MITRE ATT&CK': 'MITRE ATT&CK', 'Assigné': 'Assignee', 'Détecté': 'Detected', 'TLP': 'TLP', 'Occur.': 'Occur.',
  'Aucun ticket ne correspond.': 'No matching ticket.', 'Affecter à': 'Assign to', 'Choisir…': 'Choose…', 'Personne': 'Nobody', 'Désélectionner': 'Clear selection',
  'Actions groupées': 'Bulk actions', 'sélectionné(s)': 'selected', 'Nom du filtre': 'Filter name',
  'Criticité initiale calculée depuis le niveau de règle Wazuh · gravité fixée à la qualification.': 'Initial criticality computed from the Wazuh rule level · severity set at qualification.',
  // Kanban
  'Kanban des incidents': 'Incident Kanban', 'Mes tickets seulement': 'My tickets only',
  'Colonnes = phases ISO/IEC 27035 · glisser une carte change son statut (journalisé). Les faux positifs sont rangés avec les tickets clos.': 'Columns = ISO/IEC 27035 phases · dragging a card changes its status (logged). False positives are filed with closed tickets.',
  // Profil
  'Mon profil': 'My profile', 'Changer de mot de passe': 'Change password', 'Mot de passe actuel': 'Current password', 'Nouveau mot de passe': 'New password',
  'Modifier': 'Change', 'Codes de secours': 'Recovery codes', 'Régénérer': 'Regenerate', 'Sessions actives': 'Active sessions', 'Fermer': 'Close',
  'Ouverte le': 'Opened on', 'Dernière activité': 'Last activity', "Notifications dans l'interface": 'In-app notifications', 'Langue': 'Language',
  "Ticket qui m'est affecté": 'Ticket assigned to me', 'Mention dans un commentaire': 'Mention in a comment', 'Échéance dépassée': 'Deadline exceeded', "Réponse d'un client": 'Client reply',
  'Mot de passe modifié. Vos autres sessions ont été fermées.': 'Password changed. Your other sessions were closed.',
  // Divers
  'Imprimer / PDF': 'Print / PDF', 'Annuler': 'Cancel', 'Enregistrer': 'Save', 'Supprimer': 'Delete',
}
