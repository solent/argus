# Argus

> Analyse statique de vulnérabilités C++ propulsée par l'IA — évaluation d'impact CVE, découpage de flux de données, et score de consensus multi-modèles.

---

## Ce que ça fait

Argus analyse des projets C++ pour déterminer si des CVEs connues dans leurs dépendances sont **réellement exploitables** dans le contexte du code source.

Il ne se contente pas de vérifier si une version de bibliothèque est affectée — il trace le flux de données depuis les entrées externes jusqu'aux sinks vulnérables, puis demande à un modèle on-premise de produire un rapport d'exploitabilité. Un second workflow optionnel permet d'évaluer objectivement la qualité de ce modèle via des juges cloud.

---

## Deux workflows distincts

### Workflow 1 — Analyse (confidentialité totale du code)

```
Projet C++
    │
    ▼
tree-sitter + CMake      Construction du graphe d'appels, détection des bibliothèques liées
    │
    ▼
NVD / ExploitDB          Récupération des CVEs et exploits publics associés
    │
    ▼  [cloud — sans code source]
OpenRouter               Résolution des symboles ambigus (quelle lib pour send() ?)
                         Enrichissement contextuel CVE (CWE, patterns canoniques)
    │
    ▼  [on-premise — code source jamais envoyé au cloud]
BackSlicer               Extraction du contexte de données pertinent autour du point d'appel
Modèle on-premise        Rapport d'exploitabilité local + synthèse globale
    │
    ▼
Dashboard                Graphe coloré par risque, CVEs par nœud, rapport IA détaillé
```

**Le code source ne quitte jamais le serveur local.** OpenRouter ne reçoit que des noms de fonctions et des descriptions CVE pour la résolution et l'enrichissement.

### Workflow 2 — Benchmarking (évaluation de modèle)

```
Modèle on-premise        Analyse le projet (identique au workflow 1)
    │
    ▼  [cloud — code source transmis aux juges pour évaluation]
Juges cloud              Phase 1 : analyse indépendante
                         Phase 2 : révision croisée avec justification technique obligatoire
                         Phase 3 : consensus (médiane pondérée)
    │
    ▼
Dashboard /tests         Scores, métriques qualité par nœud, rapport de consensus
```

**À réserver aux projets non confidentiels.** Le code est transmis aux juges cloud uniquement pour évaluer la qualité du modèle on-premise, pas pour l'analyse de production.

---

## Architecture

```
argus/
├── backend/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│   └── src/
│       ├── server.py              FastAPI — endpoints REST, file de jobs asyncio
│       └── classes/
│           ├── CallGraphNode.py   Graphe d'appels + génération de rapports IA
│           ├── BackSlicer.py      Slicer arrière par flux de données (4 passes)
│           ├── ProjectInfos.py    Métadonnées projet + parsing CMake
│           ├── LibraryInfos.py    Récupération bibliothèques + CVEs
│           ├── CVE.py             Modèle CVE + requêtes NVD + ExploitDB
│           ├── CMake.py           Résolution des dépendances CMake
│           ├── OpenRouter.py      Client LLM (compatible OpenAI /v1)
│           ├── Model.py           Dataclass infos modèle
│           └── config.py          Configuration modèles
├── frontend/
│   └── src/
│       ├── app/
│       │   ├── page.tsx           Vue analyse (graphe d'appels interactif)
│       │   └── tests/
│       │       └── TestsPage.tsx  Dashboard benchmarking
│       └── components/
└── rapports/
    ├── Doc/
    │   └── guide_utilisation.pdf      Guide d'utilisation complet
    ├── DebugStory/
    │   └── historique_projet.pdf      Historique du développement
    └── PoC/
        └── poc_limites.pdf            Résultats de benchmarking et limites
```

---

## Installation

### Prérequis

- Docker et Docker Compose
- Un serveur Ollama accessible (local ou distant) avec un modèle compatible (voir [Modèles](#modèles))
- Clé API [OpenRouter](https://openrouter.ai) (résolution de bibliothèques, enrichissement CVE, juges)
- (Optionnel) Clé API [NVD](https://nvd.nist.gov/developers/request-an-api-key) pour un rate limit augmenté

### Démarrage

Créer `backend/.env` :

```env
# Obligatoire
OPENROUTER_API_KEY=sk-or-v1-...

# Optionnel — augmente le rate limit NVD de 10 req/min à 120 req/min
NVD_API_KEY=

# Modèle on-premise — URL de votre serveur Ollama (compatible OpenAI /v1)
ON_PREMISE_BASE_URL=http://<votre-serveur-ollama>/v1
ON_PREMISE_MODEL=devstral:24b

# Clé d'authentification Ollama — laisser vide si non requise
ON_PREMISE_API_KEY=

# 0 : logs minimaux | 1 : affiche chaque prompt et réponse LLM dans stdout
DEBUG_AI=0
```

```bash
cd backend
docker compose up --build
```

Le backend est accessible sur le port **8000**, le frontend sur le port **3000**.

Les résultats de benchmarking sont persistés dans `backend/data/test_results.db` (volume Docker — ne pas supprimer entre les redémarrages).

---

## Modèles

Argus utilise deux catégories de modèles :

| Rôle | Hébergement | Usage |
|------|-------------|-------|
| **Modèle on-premise** | Votre serveur Ollama | Analyse du code source — ne quitte jamais le serveur local |
| **Modèles cloud** | OpenRouter | Résolution de bibliothèques, enrichissement CVE, juges de benchmarking |

### Modèles on-premise compatibles

| Modèle | Qualité | Remarque |
|--------|---------|----------|
| `devstral:24b` | **Recommandé** | Spécialisé code, meilleur alignement avec les juges |
| `qwen3:32b` | Bon | Solide en raisonnement général + code |
| `gpt-oss:20b` | Déconseillé | Variance élevée entre exécutions, sous-évalue systématiquement |
| Autres modèles 24B+ | À benchmarker | Utiliser le workflow Test pour évaluer tout nouveau modèle |

Tout modèle 24B paramètres minimum exposant une API compatible OpenAI sur `/v1` peut être utilisé. En dessous de 24B, les modèles manquent les chemins de taint et peinent à produire du JSON structuré.

---

## Concepts clés

### BackSlicer — découpe arrière par flux de données

Pour chaque point d'appel d'une fonction potentiellement vulnérable, Argus extrait une tranche de code précise — pas la fonction entière, uniquement les lignes pertinentes :

- **Passe 1** — chaînes d'assignation : `a = b; b = recv(...)` jusqu'à la source
- **Passe 2** — sinks de sécurité : `memcpy`, `strcpy`, `malloc`, `recv`, `fopen`...
- **Passe 3** — accès membres et indexation de tableaux sur les variables suivies
- **Passe 4** — déclarations de taille : `sizeof`, `strlen`, constantes numériques

La solution idéale serait un slicer basé sur l'AST Clang (PDG/SDG), mais cette approche impose de fournir tous les en-têtes système et dépendances à la compilation — une contrainte lourde à automatiser. Le slicer heuristique est un compromis pragmatique : aucune configuration de l'environnement de compilation n'est requise, au prix d'une couverture incomplète sur les templates C++ complexes et les appels via pointeurs de fonctions.

### Scoring par consensus en 3 phases

| Phase | Ce qui se passe |
|-------|-----------------|
| **1 — Indépendante** | Chaque juge produit son rapport sur le code + rapport du modèle testé |
| **2 — Révision croisée** | Chaque juge voit les rapports des autres et révise son score avec justification technique obligatoire |
| **3 — Synthèse** | Médiane pondérée des scores révisés ; poids = 1.0 + 0.5 × (nombre de constats partagés, max 4) |

Le score global ne peut dépasser le maximum des scores locaux que si une chaîne d'exploitation A→B est confirmée par au moins deux juges.

### Échelle de scores (0–10)

| Verdict | Plage | Conditions |
|---------|-------|------------|
| `EXPLOITABLE` | 7.0–10.0 | Entrée attaquant confirmée atteignant le sink, aucun garde efficace |
| `LIKELY_EXPLOITABLE` | 5.0–8.0 | Probable, comportement par défaut vulnérable, ou aucune mitigation visible |
| `CONDITIONALLY_EXPLOITABLE` | 3.0–6.0 | Nécessite des conditions d'exécution spécifiques |
| `INSUFFICIENT_INFO` | 3.0–5.0 | Impossible de trancher — inconnu ≠ sûr, jamais 0.0 |
| `NOT_EXPLOITABLE` | 0.0–2.0 | Uniquement si une mitigation explicite, efficace et non contournable est présente |

---

## API

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/analyze` | Parse le projet, construit le graphe d'appels (sans IA) |
| `POST` | `/llm_generate_report` | Génère un rapport IA pour un projet ou un nœud |
| `POST` | `/test_results` | Soumet un test de benchmarking — retourne `{ job_id }` (202) |
| `GET` | `/jobs/{job_id}` | Suivi du job + résultat quand terminé |
| `GET` | `/test_results` | Liste tous les tests + modèles disponibles |
| `GET` | `/test_results/{id}` | Récupère un résultat de test |

Documentation interactive : `http://localhost:8000/docs`

---

## Métriques d'évaluation (benchmarking)

Chaque juge évalue le rapport du modèle testé sur **12 critères locaux** (par nœud) et **10 critères globaux** (0.0–1.0 par critère).

Critères locaux principaux : `taint_analysis_quality`, `cve_version_matching`, `exploit_completeness`, `speculation_control`, `technical_clarity`, `false_positive_rate`, `audit_usefulness`.

Critères globaux spécifiques : `exploit_chain_detection` (chaîne A→B avec topologie), `critical_node_identification` (top-3 nœuds), `call_graph_exploitation` (utilisation de la structure d'appels).

---

## Résultats de benchmarking

12 tests sur 3 modèles et 2 projets cibles, évalués par DeepSeek Chat et Gemini 2.5 Flash.

| Modèle | Score moyen (brut) | Score consensus moyen | Correction |
|--------|-------------------|----------------------|------------|
| `devstral:24b` | 7.5 | 7.8 | +0.3 |
| `qwen3:32b` | 7.5 | 8.5 | +1.0 |
| `gpt-oss:20b` | 6.5 | 8.8 | +2.3 |

*Moyennes sur les 9 tests valides (projets vulnérables). Les 3 tests à score 0.0 correspondent au projet sans CVE — résultat correct et attendu.*

Le consensus corrige systématiquement les sous-évaluations (+1.25 à +1.75 points sur VulnerableCurlExample). Résultats complets dans `rapports/PoC/poc_limites.pdf`.

---

## Limitations

- Argus analyse les **points d'appel visibles** — une CVE déclenchée via callback implicite ou initialisation statique ne sera pas détectée.
- Le BackSlicer est heuristique — templates C++ complexes, macros et appels via pointeurs de fonctions peuvent ne pas être entièrement suivis.
- **CMake uniquement** — les projets sans `CMakeLists.txt` (Makefile, Bazel, Meson...) ne sont pas supportés.
- L'analyse LLM est probabiliste — le mécanisme de consensus réduit la variance mais ne l'élimine pas.
- Tests de benchmarking séquentiels (état partagé dans les `ClassVar` de `CallGraphNode`).

---

## Documentation

| Document | Description |
|----------|-------------|
| `rapports/Doc/guide_utilisation.pdf` | Guide complet — installation, configuration, utilisation, diagnostics |
| `rapports/DebugStory/historique_projet.pdf` | Historique du développement — décisions d'architecture et problèmes rencontrés |
| `rapports/PoC/poc_limites.pdf` | Proof of Concept — protocole de benchmarking, résultats complets, limites et pistes d'amélioration |

---

## Auteurs

SCHOBERT Néo, EL AKRABA Othmane, AYOUBI Houcine, TRAORE Idrissa — IMT Atlantique, 2024–2025.
