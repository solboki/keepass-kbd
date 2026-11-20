# Journal des versions — Clavier KeePass pour Sailfish OS

Numérotation [SemVer](https://semver.org/lang/fr/) : correctif → `patch`, fonctionnalité → `minor`,
changement incompatible → `major`. Passage en 1.0.0 à la première diffusion publique.
Incrémenter avec `scripts/bump-version.sh patch|minor|major`.

## [Non publié]

## [0.8.0] - 2026-11-20
### Ajouté
- Création d'entrée : titre proposé (nom de l'application lu dans son .desktop, ou nom du site)
  et identifiant repris de la page (mémorisé par FUTO, sinon suivi de secours en mémoire vive).
- Notification système en haut de l'écran après l'enregistrement (ou en cas d'échec).
- `KEEPASS_KBD_DATA_DIR` pour isoler les données des tests.
### Modifié
- Formulaire d'enregistrement au style Sailfish : titre, identifiant, mot de passe masqué (œil), URL,
  puis bouton d'enregistrement, l'un sous l'autre.

## [0.7.1] - 2026-11-20
### Corrigé
- Entrée « Clavier KeePass » absente de Paramètres › Entrée de texte : la clé `settings=` n'est lue
  que si la disposition déclare un gestionnaire de saisie (`KeepassInputHandler.qml`).
### Modifié
- L'engrenage reste toujours aligné sur le bord droit, quel que soit l'écran affiché.

## [0.7.0] - 2026-11-20
### Ajouté
- Entrée « Clavier KeePass » dans Paramètres › Saisie de texte (clé `settings=` de la disposition).
- Numérotation des versions : version unique dans `Cargo.toml`, recopiée à l'installation, journal et script d'incrémentation.
### Modifié
- Saisie du mot de passe maître au style Sailfish : texte, trait de la couleur du thème, libellé discret dessous.
- Bouton de validation rectangulaire et compact.
### Corrigé
- Page Paramètres : « service injoignable » (l'application Paramètres tourne avec le groupe `privileged`).

## [0.6.0] - 2026-11-20
### Ajouté
- Touche d'effacement dans le champ de l'application (appui long répété).
- Page Paramètres : délai avant de redemander le mot de passe maître, choix du fichier .kdbx, à propos, crédits.
- Engrenage dans la disposition pour ouvrir les Paramètres.
### Modifié
- Icône « + » pour le générateur.
- Reverrouillage compté depuis le déverrouillage (`relock_policy`).

## [0.5.0] - 2026-11-20
### Ajouté
- Retour automatique à la disposition précédente à la fermeture du clavier.
- Suggestions pour les applications AppSupport d'après les segments du nom de paquet.

## [0.4.0] - 2026-11-20
### Ajouté
- Suggestions selon le site ou l'application au premier plan.
- Interface graphique : icônes Sailfish, avatars, générateur coloré, œil de mot de passe.
### Modifié
- Plus de verrouillage à la mise en veille par défaut.

## [0.3.0] - 2026-11-20
### Ajouté
- Remplissage automatique identifiant + mot de passe en touchant une entrée.
- Affichage du mot de passe maître, verrouillage à la mise en veille.
### Modifié
- Présentation : recherche, propositions, puis boutons d'insertion.

## [0.2.0] - 2026-11-20
### Corrigé
- Mini-clavier absent sur l'écran de déverrouillage.
- Nom D-Bus exclusif : le service ne peut plus être remplacé par un autre processus.

## [0.1.0] - 2026-11-20
### Ajouté
- Service `keepass-kbd` (Rust) : lecture directe du .kdbx, rechargement automatique, générateur,
  ajout d'entrées avec écriture vérifiée et sauvegardes.
- Disposition clavier « KeePass » pour Maliit.
