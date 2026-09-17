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
`ollama-pull` telecharge automatiquement `qwen3.5:9b` (~5-6 Go) et le modele
d'embeddings `nomic-embed-text` (~0.27 Go) — cela peut prendre plusieurs
minutes selon la connexion.

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
