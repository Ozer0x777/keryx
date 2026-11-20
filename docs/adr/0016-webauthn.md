# ADR-0016 — Clés de sécurité WebAuthn (second facteur en option)

- **Statut** : accepté (20/11/2026)
- **Décision** : en plus du TOTP, un utilisateur peut enregistrer des clés de sécurité WebAuthn / FIDO2 (Profil > Clés de sécurité, mot de passe redemandé). À l'étape 2 de la connexion, une clé peut remplacer le code TOTP. Le mot de passe reste le premier facteur. Le TOTP et les codes de secours restent disponibles : perdre une clé ne bloque pas le compte. Une réinitialisation de la 2FA par l'Admin retire aussi les clés. Les échecs d'une clé comptent pour le verrouillage comme ceux du TOTP.
- **Paramètres** : l'origine attendue est `KERYX_PUBLIC_URL` et l'identifiant de partie de confiance son nom d'hôte : ces valeurs doivent correspondre à l'adresse réellement utilisée dans le navigateur, sinon l'enregistrement échoue. Authentificateurs sans clé résidente, vérification de l'utilisateur « préférée » (le mot de passe étant déjà vérifié).
- **Exigences** : ASVS 5.0 chap. 6 (authentification multifacteur résistante à l'hameçonnage ; numéro exact à vérifier) ; PDIS IV.3.9 (comptes) ; plan : « clés physiques WebAuthn/FIDO2 en option ».
- **Limite** : pas d'obligation d'une clé pour un rôle donné, pas de preuve d'attestation du modèle de clé (aucune restriction par constructeur).
- **Test** : le parcours complet (enregistrement, connexion sans TOTP, retrait) est vérifié avec l'authentificateur virtuel de Chrome (`e2e/scenarios/50-webauthn.mjs`) ; les tests Python couvrent les refus, le cloisonnement et la réinitialisation. Non testé avec une clé physique réelle.
