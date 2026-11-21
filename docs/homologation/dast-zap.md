# Analyse dynamique automatisée (OWASP ZAP) — Keryx 0.7.0

*Auto-contrôle de l'équipe de développement. **Ce n'est pas un test d'intrusion** : un scan automatique ne remplace ni l'analyse humaine ni les tests de logique métier (cloisonnement, rôles), qui restent à confier à un prestataire (`cahier-test-intrusion.md`).*

## Méthode
- Outil : OWASP ZAP 2.16.1, plan d'automatisation (`e2e/dast.mjs`, reproductible : `ZAP_HOME=… node dast.mjs [minutes]`).
- Cible : instance de test jetable (base temporaire, données fictives), **authentifiée en manager** (session complète : mot de passe + TOTP, jeton CSRF fourni au scanner).
- Étapes : import de la description OpenAPI (83 routes), exploration (108 URL), analyse passive, **analyse active de 5 minutes**.
- Exclus (pour ne pas détruire la session du scanner) : déconnexion, changement de mot de passe, sessions, clés WebAuthn, comptes, SSO.

## Résultats et traitement

| Constat ZAP | Gravité annoncée | Analyse | Suite |
|---|---|---|---|
| Injection SQL (SQLite) sur `POST /tickets/bulk-assign`, paramètre `username` | Haute (confiance moyenne) | **Faux positif.** Détection « temporelle » (charge `randomblob(1000000)`) : mesurée en direct, la charge et une valeur banale prennent le même temps (10,03 ms contre 9,95 ms en médiane sur 60 essais) et reçoivent la même réponse (422 « Utilisateur inconnu ») ; les charges classiques (`' OR '1'='1`, `; DROP TABLE…`, `UNION SELECT…`) sont traitées comme des valeurs et la table des utilisateurs reste intacte. Les requêtes sont paramétrées (SQLAlchemy). L'écart détecté par ZAP vient du bruit de mesure pendant le scan. | Test de non-régression `tests/test_injection.py` : 7 charges sur 13 points d'entrée texte (recherche, filtres, journal d'audit, registre, liens, affectations, connexion) |
| CSP : `style-src 'unsafe-inline'` | Moyenne | **Fondé.** Permettait des blocs `<style>` injectés. | **Corrigé** : `style-src 'self'; style-src-attr 'unsafe-inline'` (seuls les attributs de style restent permis, ceux posés par l'interface) ; l'éditeur n'injecte plus de CSS (`injectCSS: false`, styles repris dans `styles.css`). Toute violation de CSP fait échouer le banc navigateur |
| Fichiers cachés trouvés (`/.hg`, `/.bzr`, `/BitKeeper`, `/._darcs`…) | Moyenne (confiance faible) | **Faux positif de fond, vrai défaut de forme** : aucune de ces ressources n'existe, mais l'application répondait 200 avec la page d'accueil à n'importe quel chemin. | **Corrigé** : tout chemin débutant par un point ou se terminant par une extension de fichier reçoit un vrai 404 (test dans `test_injection.py`) |
| Informations (identification d'authentification, commentaires suspects, application web moderne, agents utilisateurs, gestion de session) | Information | Attendu pour une application à session. Les « commentaires suspects » viennent du code JavaScript compilé de bibliothèques. | Aucune |

Aucun autre constat de gravité moyenne ou haute. Les règles d'injection XSS, de traversée de chemin, d'injection de commandes et de falsification de requêtes ont été exécutées sur les routes importées, sans résultat.

## Limites de cette analyse
Cinq minutes d'analyse active ; routes importées depuis OpenAPI seulement ; un seul rôle (manager) ; pas de parcours multi-comptes (cloisonnement entre clients, élévation de privilèges), pas de test des flux SSO, WebAuthn et d'ingestion Wazuh avec clé d'API, pas d'infrastructure réelle (proxy TLS, base de production). Ces points sont dans le périmètre du test d'intrusion à commander.

## Second passage (21/11/2026), après les corrections de la revue de code

Même plan, 6 minutes, manager authentifié, code des commits jusqu'à `edc1cfa`. Aucune alerte de gravité haute confirmée, aucune alerte moyenne confirmée.

| Constat ZAP | Analyse | Suite |
|---|---|---|
| Injection SQL (SQLite), `GET /audit/entries` paramètre `actor` et `POST /admin/users` paramètre `display_name` | **Faux positif**, même mécanisme que le premier passage (détection temporelle `randomblob`). Mesuré en direct, 40 essais par charge : médiane 11,5 / 12,1 ms pour les charges contre 11,8 ms pour une valeur banale (`actor`) ; 9,4 / 9,1 contre 8,9 ms (`display_name`) ; maximum 18,5 ms. Les 469 ms rapportés par ZAP viennent du bruit pendant le scan actif. Requêtes paramétrées ; le point `actor` est couvert par `tests/test_injection.py`. | Aucune |
| Fichier caché trouvé : `GET /BitKeeper` (200) | **Faux positif.** Le chemin n'a pas d'extension : le repli de l'application monopage renvoie `index.html` (200, `text/html`) pour toute route inconnue, ce qui est le comportement voulu (routes du navigateur). Aucun fichier `BitKeeper` n'existe ; les chemins à extension ou commençant par un point répondent 404. | Aucune |
| Divers (informatifs) | Commentaires suspects (bundle JavaScript), détection d'une application moderne, identification d'authentification : sans effet. | Aucune |

Limite inchangée : un scan automatique ne remplace pas un test d'intrusion indépendant.
