# ADR-0036 : PDF des rapports produits par le serveur

- **Statut** : accepté (28/11/2026), décision du mainteneur (feuille de route, section 4).
- **Contexte** : les rapports (rapport périodique d'un client, rapport d'incident, point de situation, rapport
  d'analyse PRIS) ne sortaient en PDF que par l'impression du navigateur : mise en page variable d'un navigateur à
  l'autre, en-têtes et pieds ajoutés par le navigateur, marquage TLP absent des pages suivantes, aucun moyen d'obtenir
  le document sans navigateur.
- **Décision** :
  1. **Quatre routes** : `GET /api/v1/reports/period.pdf` (mêmes paramètres que `/reports/period`),
     `GET /api/v1/tickets/{ref}/rapport.pdf`, `/point-situation.pdf` (`heures`), `/rapport-analyse.pdf`. Chaque page de
     rapport propose « Télécharger le PDF » ; « Imprimer » reste à côté.
  2. **Une seule source de vérité** : chaque PDF part de la réponse de la route JSON qui alimente la page, appelée
     telle quelle. Droits, cloisonnement par client, données retirées pour le client (noms des analystes, retards,
     échéances internes) et traces au journal d'audit sont donc ceux de la page ; une entrée `report.pdf` s'y ajoute.
     Les rapports internes (incident, point de situation, analyse) sont réservés à l'équipe, comme leurs pages.
  3. **Bibliothèque** : reportlab 5.1.0 (BSD), roue Python pure, qui n'ajoute que charset-normalizer aux dépendances.
     Écartés : WeasyPrint (moteur HTML et CSS complet, plusieurs bibliothèques système de plus dans l'image, et un
     rendu de HTML côté serveur à durcir), un navigateur sans tête dans l'image (lourd, surface d'attaque), fpdf2
     (licence LGPL, moins de mise en page de tableaux).
  4. **Contenu non fiable** : tout texte est échappé avant d'entrer dans le balisage de reportlab. Le HTML des tickets,
     déjà assaini côté serveur, est relu par `html.parser` et réduit à des paragraphes, titres, listes, gras, italique
     et code ; une balise laissée ouverte est refermée ; une image devient « [image] ». Aucune ressource externe n'est
     chargée.
  5. **Police** : DejaVu (paquet `fonts-dejavu-core` de l'image), pour écrire tous les caractères d'une alerte. Sans
     elle (installation hors image), les polices de base du PDF, et les caractères hors de leur jeu sont remplacés par
     « ? » ; `KERYX_PDF_FONT_DIR` désigne un autre dossier de polices.
  6. **Mise en page** : A4, une colonne, en-tête avec le titre et le marquage TLP sur chaque page, pied de page avec la
     date de production et le numéro de page ; dates en UTC, comme dans l'interface de l'équipe. Texte en français.
- **Limites** : les PDF sont en français quelle que soit la langue de l'interface. Ce ne sont pas des PDF/A
  d'archivage, et ils ne sont ni signés ni horodatés (l'horodatage RFC 3161 reste celui des pièces).
- **Exigences** : PRIS v3.2 VI.6 (point de situation) et VI.7 (rapport d'analyse) ; PDIS IV.2.3.g (notification par
  le numéro du ticket seulement : le PDF se télécharge depuis Keryx, il n'est jamais joint à un courriel).
- **Tests** : `tests/test_pdf.py` (contenu, droits, données internes absentes du rapport du client, HTML piège,
  caractères hors latin), scénario e2e `99-pdf.mjs` (téléchargement depuis chaque page, équipe et client).
