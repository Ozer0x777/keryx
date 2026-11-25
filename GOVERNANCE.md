# Gouvernance de Keryx

*In English: Keryx is run by a single maintainer who makes final decisions after public discussion in issues;
contributors propose changes through pull requests; continuity is ensured by sealed access credentials and a
designated trusted person (see "Continuité"). Contributions in English are welcome.*

## Modèle

Keryx est un projet libre (licence MIT) à **mainteneur unique** : un mainteneur décide, après discussion publique.
Ce modèle convient à la taille actuelle du projet ; il sera revu dès qu'un deuxième mainteneur régulier existera
(voir « Évolution »).

## Rôles et responsabilités

| Rôle | Qui | Responsabilités | Droits sur le dépôt |
|---|---|---|---|
| Mainteneur | Ozer0x777 | Feuille de route, relecture et fusion des demandes, publication des versions et de l'image signée, traitement des vulnérabilités (`SECURITY.md`), application du code de conduite, réglages du dépôt et du paquet ghcr.io | Administration |
| Contributeur | Toute personne qui propose une issue, une demande de fusion, une traduction ou une relecture | Suivre `CONTRIBUTING.md` (tests, ADR, exigence citée) et le code de conduite | Lecture, demandes de fusion depuis un fork |
| Rapporteur de vulnérabilité | Toute personne qui signale une faille | Signaler en privé, laisser le temps du correctif (`SECURITY.md`) | Signalement privé GitHub |
| Utilisateur | SOC, MSSP, CERT qui déploient Keryx | Signaler bogues et besoins en issue, appliquer les mises à jour de sécurité | Lecture |

## Prise de décision

- **Changement courant** (correctif, test, documentation) : une demande de fusion, CI verte, relecture du mainteneur.
- **Choix technique** (dépendance, format, architecture, sécurité) : un ADR dans `docs/adr/` au statut « proposé »,
  discuté dans la demande de fusion, accepté par le mainteneur.
- **Changement qui engage les utilisateurs** (fonction retirée, rupture d'API ou de schéma, changement de licence) :
  une issue ouverte au moins 14 jours avant la décision, pour recueillir les avis ; la décision et sa raison y sont
  écrites.
- **Désaccord** : discuté en issue ; le mainteneur tranche et explique sa décision par écrit.

## Continuité

Le projet doit pouvoir continuer si le mainteneur disparaît ou ne peut plus s'en occuper : gérer les issues, accepter
des modifications et publier une version dans la semaine.

- Les accès nécessaires (compte GitHub propriétaire du dépôt et du paquet ghcr.io, codes de récupération de la double
  authentification) sont conservés sous scellé, dans un coffre dont une **personne de confiance désignée** connaît
  l'existence et peut obtenir l'ouverture.
- Un document du mainteneur donne à cette personne le droit de reprendre le projet, ou de le transmettre à un
  nouveau mainteneur.
- Rien d'autre n'est nécessaire pour publier : la publication est entièrement faite par la CI du dépôt
  (`docs/publication.md`), la signature de l'image n'utilise aucune clé privée à conserver (signature sans clé liée
  au workflow), le code est sous licence MIT et peut être repris par un fork.

Statut au 25/11/2026 : dispositif en place (coffre et personne de confiance désignée, volontairement non nommés
ici).

## Contact

- Vulnérabilité : signalement privé GitHub uniquement (`SECURITY.md`).
- Bogue, besoin, question : issues GitHub.
- Code de conduite (comportement inacceptable) : en privé, à <ozer0x777@reversing.re>.

## Évolution

Quand un contributeur régulier le souhaite et que le mainteneur l'accepte, il devient co-mainteneur : droits
d'écriture sur le dépôt, relecture des demandes de fusion des autres. Avec deux mainteneurs ou plus, chaque demande
de fusion est relue par un mainteneur autre que son auteur, et ce document est mis à jour.
