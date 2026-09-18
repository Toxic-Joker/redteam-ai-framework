# RedTeam AI Framework

![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

Framework d'orchestration Red Team multi-agents. Un modele de langage local
(`qwen3.5:9b` par defaut) est **consultatif** : il resume, redige et propose
des pistes. Toute decision engageante — severite d'un finding, risque global
de la mission, structure du rapport — est **deterministe**, ancree sur la
preuve produite par les outils (nmap, gobuster, nikto, sqlmap, ffuf), jamais
sur l'opinion du modele.

Voir `PROJECT.md` pour la mission, les audiences et la portee du MVP ;
`CLAUDE.md` pour le blueprint technique ; `docs/HISTORY.md` pour la
retrospective complete de la premiere version (memoire de Mastere EFREI).

## Demarrage rapide

```bash
git clone <ce-depot>
cd redteam-framework
cp .env.example .env
docker compose up --build
```

Le dashboard est servi sur `http://localhost:8000`. Au premier demarrage,
`ollama-pull` telecharge automatiquement `qwen3.5:9b` (~6.6 Go) et le modele
d'embeddings `nomic-embed-text` (~0.27 Go) — cela peut prendre plusieurs
minutes selon la connexion.

## Choisir un modele selon la RAM disponible

Le modele par defaut (`qwen3.5:9b`) utilise environ 7-8 Go de RAM a l'inference
(confirme en deploiement reel), pas seulement le budget disque documente
plus haut. Sur une machine avec peu de marge, changer `OLLAMA_MODEL_MAIN` dans
`.env` avant le premier `docker compose up`, ou a chaud si le stack tourne deja :

| RAM totale de la machine | Modele recommande | RAM approx. a l'inference |
|---|---|---|
| 8 Go | `qwen3.5:4b` | ~4-4.5 Go |
| 12-16 Go | `qwen3.5:9b` (defaut) | ~7-8 Go |

Voir `CLAUDE.md`, section 3, pour le tableau complet (fiabilite d'appel
d'outils par modele) et `docs/HISTORY.md`, section 6, pour le retour de
deploiement qui a motive cette recommandation.

**Changer de modele sur un stack deja lance**, sans tout reconstruire :

```bash
# 1. couper le framework (interrompt une mission en cours, pas de reprise a chaud)
docker compose stop framework

# 2. mettre a jour .env
sed -i 's/^OLLAMA_MODEL_MAIN=.*/OLLAMA_MODEL_MAIN=qwen3.5:4b/' .env

# 3. tirer le nouveau modele dans le conteneur ollama deja en cours d'execution
docker exec redteam-ai-framework-ollama-1 ollama pull qwen3.5:4b

# 4. retirer l'ancien modele pour liberer l'espace disque (~6.6 Go pour qwen3.5:9b)
docker exec redteam-ai-framework-ollama-1 ollama rm qwen3.5:9b

# 5. recreer le framework pour qu'il prenne en compte la nouvelle variable
docker compose up -d framework
```

(Adapter le nom du conteneur `redteam-ai-framework-ollama-1` s'il differe sur
votre machine — verifiable avec `docker compose ps`.)

## Profils additionnels

```bash
# Ollama deja installe sur la machine hote (pas de conteneur ollama)
docker compose -f docker-compose.host-ollama.yml up --build

# GPU NVIDIA pour Ollama (necessite le NVIDIA Container Toolkit)
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build
```

## Utilisation

1. Ouvrir le dashboard, saisir la cible (toujours externe — aucune cible
   vulnerable n'est embarquee dans ce depot) et une reference d'autorisation.
2. Suivre la progression en temps reel (recon -> enum -> exploit ->
   postexploit -> rapport).
3. Telecharger le rapport PDF une fois la mission terminee.

## Developpement local (sans Docker)

```bash
python -m venv .venv
source .venv/bin/activate  # ou .venv\Scripts\activate sur Windows
pip install -r requirements-dev.txt
pytest
```

Les tests unitaires (`tests/`) couvrent en priorite le coeur deterministe
(`core/state.py`) et les garde-fous anti-boucle de l'orchestrateur ; ils ne
necessitent ni Ollama ni les binaires d'outils externes.

## Variables d'environnement

Voir `.env.example` et `CLAUDE.md`, section 9. Une seule source de verite
par variable, lue dans `core/config.py`.

## Licence

Apache 2.0 (coherente avec la licence des modeles Qwen recommandes).
