# sample/

Ce dossier contient des projets C++ d'exemple destinés à tester Argus.

Chaque sous-dossier est un projet C++ autonome avec son propre `CMakeLists.txt`.
Vous pouvez les soumettre directement via l'interface d'Argus pour valider
l'analyse statique et le rapport d'exploitabilité.

## Utilisation

1. Lancez Argus (`docker compose up` depuis `backend/`).
2. Dans l'interface (port 3000), sélectionnez un sous-dossier de `sample/` comme répertoire de projet.
3. Lancez l'analyse.

## Ajouter vos propres projets de test

Déposez simplement un nouveau dossier ici contenant au minimum :
- un fichier `CMakeLists.txt` à la racine du projet
- vos fichiers sources `.cpp` / `.h`

Argus détectera automatiquement le `CMakeLists.txt` et les fichiers sources,
même si votre projet est organisé en plusieurs sous-répertoires.
