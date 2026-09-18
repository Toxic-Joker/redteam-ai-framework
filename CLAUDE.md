# RedTeam AI Framework v2 : blueprint de reconstruction

Ce document est lu automatiquement par Claude Code comme contexte de projet. Il contient le "comment" technique : architecture, pièges à éviter, choix du modèle, ordre de construction. Le "pourquoi" et le "pour qui" (mission, audiences, portée du MVP, non-goals) vivent dans `PROJECT.md`, document stable à ne pas modifier au fil des sessions. L'historique complet de la première version (tout ce qui a été tenté, cassé, corrigé) vit dans `docs/HISTORY.md`. Lire `PROJECT.md` avant de commencer ; consulter `docs/HISTORY.md` avant de remettre en question une règle de ce document qui semble arbitraire.

## TL;DR

- Reconstruction Docker-first d'un framework d'orchestration Red Team multi-agents déjà conçu, corrigé et validé une première fois. Cette fois, toutes les corrections de la v1 sont intégrées dès le premier commit, pas ajoutées en cours de route.
- Principe non négociable : le LLM est **consultatif**, toute décision critique (sévérité, risque, structure du rapport) est **déterministe**, ancrée sur la preuve des outils.
- Modèle par défaut : `qwen3.5:9b` (voir section 3), choisi pour son meilleur équilibre fiabilité d'appel d'outils / taille, avec `qwen3:8b` en repli éprouvé. Sur une machine à ~8 Go de RAM totale, préférer `qwen3.5:4b` (une seule variable d'environnement, validé en déploiement réel, voir section 3 et `docs/HISTORY.md` section 6).
- Budget de taille cible : 8 à 10 Go en configuration par défaut, plafond de sécurité à 25 Go.
- Aucune cible vulnérable embarquée dans `docker-compose.yml`. La cible est toujours externe, saisie dans l'interface web.

---

## 0. Lire avant de commencer

Ce projet a déjà été construit une fois. Le code initial avait une dette technique invisible : les mécanismes de fiabilité (plafonnement de sévérité, consolidation, calcul déterministe du risque, garde-fous anti-boucle) ont été ajoutés **après coup**, agent par agent, ce qui a produit un bug d'oubli précis : un agent non couvert a laissé passer un CRITICAL entièrement halluciné jusqu'au rapport final (détail dans `docs/HISTORY.md`, section 4, incident 10). Le packaging Docker a aussi été fait en second temps, ce qui a produit une longue série d'erreurs évitables (`docs/HISTORY.md`, section 4).

Cette reconstruction doit intégrer tout cela **dès la conception**. Les sections suivantes sont la spécification à construire, pas une proposition à débattre sur les points marqués "non négociable".

---

## 1. Contexte du projet

Résumé ultra condensé (détail complet dans `docs/HISTORY.md`) :

- Le cycle offensif complet (recon, énumération, exploitation, post-exploitation, rapport) a été construit et validé sur des exécutions réelles.
- Le cœur déterministe (plafonnement de sévérité, consolidation des constatations, séparation findings/pistes, calcul du risque) est la contribution centrale du projet et a fonctionné comme prévu, y compris pour neutraliser une hallucination critique du LLM.
- Le déploiement Docker a été ajouté après coup et a généré une dizaine d'incidents évitables (réseau, paquets manquants, binaires mal nommés, taille excessive). Objectif de cette reconstruction : les éviter dès le départ (section 2).
- Deux points restent explicitement non prouvés : la généralité sur plusieurs cibles, et l'évasion mesurée face à un EDR/XDR réel. Voir `PROJECT.md` pour la liste complète des non-goals du MVP.

---

## 2. Pièges rencontrés à ne jamais reproduire (checklist de conception)

Chaque ligne correspond à un incident réel documenté dans `docs/HISTORY.md`, section 4. Cette fois, ils doivent être résolus **dans le premier commit**, pas découverts en production.

- [ ] Épingler la base Docker (`python:3.11-slim-bookworm`, jamais `python:3.11-slim` seul).
- [ ] `nikto` et `sqlmap` ne sont pas des paquets apt fiables : les installer depuis leurs dépôts GitHub (idéalement en épinglant un tag de release pour la reproductibilité dans le temps).
- [ ] Dépendances Perl de `nikto` à ne pas oublier : `perl`, `libnet-ssleay-perl`, `libjson-perl`, `libxml-writer-perl`, `libnet-ip-perl`.
- [ ] Le nom du binaire `gobuster` doit être identique dans le code et dans l'image (`gobuster`, jamais `gobuster3`). Pas de symlink de compatibilité à maintenir.
- [ ] `gobuster` et `ffuf` : binaires de release GitHub (multi-arch `amd64`/`arm64`), pas de build depuis les sources.
- [ ] `nmap` doit toujours tourner avec `-Pn`, en mode découverte, ports et vuln. Sans ça, un hôte qui bloque l'ICMP (fréquent depuis un pont Docker vers un réseau segmenté) est vu comme "down" et le scan de ports est sauté entièrement.
- [ ] `sudo` uniquement si le processus ne tourne pas déjà en root (`os.geteuid() == 0` -> pas de `sudo`).
- [ ] Jamais de cible vulnérable embarquée dans `docker-compose.yml`.
- [ ] Une seule source de vérité pour le nom du modèle : une variable d'environnement, lue à un seul endroit (`core/config.py`), propagée partout.
- [ ] Pas de `torch` ni `sentence-transformers` dans les dépendances Python : embeddings via l'endpoint d'Ollama (section 8).
- [ ] Wordlist de gobuster résolue avec vérification d'existence (`os.path.exists`) et repli sur un chemin connu.
- [ ] Le plafonnement de sévérité doit être appliqué par **tous** les agents qui créent des findings, sans exception, en particulier l'agent de reconnaissance. Écrire la fonction une fois dans `core/`, l'appeler partout, jamais la dupliquer.
- [ ] La limite de cycles et le suivi des phases terminées de l'orchestrateur doivent exister depuis le premier commit du graphe, pas être ajoutés après avoir observé une boucle infinie.
- [ ] Un guess `-O` (détection d'OS) à faible confiance ne doit jamais apparaître comme un fait dans un rapport.
- [ ] Détection de vulnérabilité `sqlmap` : ne jamais combiner des mots-clés indépendants présents n'importe où dans la sortie (`"parameter" in stdout and "injectable" in stdout`) — `sqlmap` imprime aussi ces deux mots dans ses messages **négatifs** (`"parameter 'id' is NOT injectable"`). Un seul signal positif non ambigu, vérifié ligne par ligne (voir `docs/HISTORY.md`, section 6).
- [ ] Démarrer une mission avec `asyncio.create_task` (handle conservé pour permettre l'annulation), jamais `BackgroundTasks` de FastAPI qui ne donne aucune prise pour interrompre une mission en cours.
- [ ] Toute bibliothèque synchrone/bloquante appelée depuis un agent (ex. `dnspython`) doit passer par `asyncio.to_thread`, jamais un appel direct dans une coroutine — un appel bloquant y gèle toute la boucle asyncio, donc l'API et le dashboard entiers, pas seulement la mission en cours.

---

## 3. Choix du modèle

`llama3.2:3b` (v1) produisait un JSON malformé dans une fraction significative de ses réponses et consommait l'essentiel du temps de mission en inférence. Recherche menée pour la v2, avec un critère explicite : **priorité à la fiabilité d'appel d'outils et à la réduction des hallucinations, la vitesse passant en second**.

Point important trouvé en recherchant : les benchmarks généraux de "qualité/intelligence" ne prédisent pas la fiabilité d'appel d'outils. Sur une évaluation dédiée spécifiquement à l'appel d'outils, `gpt-oss-20b` obtient un score d'intelligence générale supérieur à Qwen3 et tourne plus vite, mais son taux de succès sur l'appel d'outils structuré est plus bas (environ 85 %) que celui de la famille Qwen3/Qwen3.5 (95 % et plus) à une taille équivalente ou inférieure. Autrement dit : plus "intelligent" en général ne veut pas dire plus fiable pour ce que ce projet lui demande de faire. Ce n'est donc pas le meilleur choix ici malgré les apparences.

| Modèle | Taille (Ollama) | RAM estimée (inférence) | Fiabilité appel d'outils | Remarque |
|---|---|---|---|---|
| `llama3.2:3b` (v1, à remplacer) | ~2.0 Go | ~2.5-3 Go | Faible, JSON souvent malformé | Ne pas réutiliser |
| `qwen3:4b` | 2.5 Go | ~3-3.5 Go | Très bon pour sa taille (~95 %) | Option la plus légère si la RAM est très limitée |
| **`qwen3.5:4b`** | 3.4 Go (confirmé sur `ollama.com/library`) | ~4-4.5 Go (estimation : poids + recouvrement contexte/cache KV) | Dépasse déjà `qwen3:8b` sur un benchmark dédié à l'appel d'outils, malgré sa taille | **Recommandé sur une machine à ~8 Go de RAM totale.** Validé en déploiement réel (Parrot OS, voir `docs/HISTORY.md` section 6) : meilleure fiabilité que `qwen3:8b` pour moins de la moitié de sa RAM. |
| **`qwen3.5:9b`** (défaut du dépôt) | 6.6 Go (confirmé) | ~7-8 Go (confirmé en déploiement réel : Ollama a rapporté ~7.4 Go de RAM totale disponible, quasi entièrement occupés sur une machine à 8 Go) | Génération la plus récente de la famille, meilleure fiabilité absolue de la table | Réserver aux machines avec au moins 12-16 Go de RAM. Sur une machine à 8 Go, préférer `qwen3.5:4b` : peu de marge sinon pour le reste de la pile (framework, outils, OS). |
| `qwen3:8b` (repli éprouvé) | 5.2 Go | ~6-7 Go | ~95 %, très largement éprouvé | À utiliser si `qwen3.5` pose un souci de compatibilité de gabarit de chat sur une version d'Ollama donnée |
| `nemotron-nano:4b` (repli léger) | ~4.2 Go | ~5 Go | ~95 % | Alternative si les deux modèles ci-dessus posent un problème sur une machine précise |
| `gpt-oss-20b` (non retenu) | ~13 Go | ~14-16 Go | ~85 % sur l'appel d'outils, malgré un meilleur score de raisonnement général | Plus rapide et "plus intelligent" au sens général, mais moins fiable specifiquement sur l'appel d'outils structuré, et RAM disproportionnée. Écarté pour ce projet malgré des apparences favorables |

RAM estimée = poids du modèle quantifié + recouvrement pour le contexte/cache KV (~15-30 % à la longueur de contexte par défaut de ce projet, 4096 tokens). Les valeurs marquées "confirmé" viennent d'une verification directe (taille du modèle sur `ollama.com/library`, ou logs Ollama en déploiement réel) ; les autres sont des estimations par extrapolation, à confirmer au premier `pull` sur la machine cible.

Décision : `qwen3.5:9b` reste la référence par défaut du dépôt (meilleure fiabilité absolue) pour les machines avec assez de RAM. Sur une machine à ~8 Go de RAM totale, basculer vers `qwen3.5:4b` via `OLLAMA_MODEL_MAIN` (une seule variable d'environnement, aucun changement de code) — c'est la configuration validée en déploiement réel. `qwen3:8b` reste le repli de compatibilité si `qwen3.5` pose un souci de gabarit de chat. Licence Apache 2.0 dans tous les cas.

Point d'implémentation à respecter : utiliser les variantes **instruct / non-thinking** de ces modèles pour la boucle d'agents, pas les variantes "raisonnement" (`thinking mode`, DeepSeek-R1-Distill, QwQ, etc.). Un modèle qui "réfléchit" avant d'appeler un outil ajoute de la latence sans forcément améliorer la fiabilité de la sortie structurée, et ce n'est pas ce que cette architecture attend du LLM (il est déjà cantonné à un rôle consultatif, pas besoin de chaîne de raisonnement longue).

Garder le cœur déterministe malgré ce meilleur modèle. Un modèle plus fiable réduit la fréquence des hallucinations, il ne les élimine pas, et la valeur de l'architecture ne dépend pas de la qualité du modèle (voir `PROJECT.md`, principe directeur).

Le modèle tourne dans un conteneur Ollama séparé, jamais dans l'image du framework, pour pouvoir en changer sans reconstruire l'image applicative et pour permettre à un utilisateur avancé de pointer vers un Ollama déjà installé sur sa machine hôte (profil `host-ollama`, section 8).

---

## 4. Architecture cible

```
+-------------+      +--------------+
|  Dashboard   |<---->|   FastAPI    |
|  (Alpine.js  |  WS  |   + API REST |
|   + HTMX)    |      +------+-------+
+-------------+             |
                    +--------+--------+
                    |   Orchestrateur  |  (LangGraph, garde-fous anti-boucle)
                    +--------+--------+
        +----------+---------+---------+-----------+
        v          v         v         v           v
     Recon       Enum     Exploit   Postexploit   Rapport
        |          |         |         |           |
        +----------+---------+---------+-----------+
                    | (outils : nmap, gobuster, nikto, sqlmap, ffuf)
                    v
              MissionState (SQLite)
              + mémoire sémantique (ChromaDB, embeddings via Ollama)
                    |
                    v
          +-------------------+       +--------------+
          |  Conteneur Ollama  |<----->| qwen3.5:9b    |
          |  (LLM consultatif  |       | + modèle      |
          |   + embeddings)    |       |  embeddings   |
          +-------------------+       +--------------+
```

Composants (repris du projet précédent, corrections de la section 2 intégrées dès la conception) :

- **`core/`** : `state.py` (MissionState, Finding, Lead, enums, fonctions déterministes), `orchestrator.py` (graphe LangGraph, garde-fous anti-boucle dès le départ), `memory.py` (SQLite + ChromaDB), `config.py` (Pydantic Settings, une seule source de vérité par variable).
- **`agents/`** : `base_agent.py`, `recon_agent.py`, `enum_agent.py`, `exploit_agent.py`, `postexploit_agent.py`, `report_agent.py`. Tous les agents qui créent des findings appellent la fonction de plafonnement de `core/state.py`, jamais une réimplémentation locale.
- **`tools/`** : `base.py`, `nmap_tool.py` (`-Pn` systématique), `gobuster_tool.py`, `nikto_tool.py`, `sqlmap_tool.py`, `ffuf_tool.py`.
- **`api/`** : routes REST (missions, reports, agents), WebSocket temps réel.
- **`templates/`** : `dashboard.html`, `report.html` (section "Pistes à vérifier" dès le premier gabarit).

---

## 5. Arborescence cible du dépôt

```
redteam-framework/
|-- PROJECT.md                   # vision, audiences, portée du MVP, non-goals
|-- CLAUDE.md                    # ce document
|-- README.md                    # copie orientée humains + badges GitHub
|-- docs/
|   `-- HISTORY.md               # rétrospective complète de la v1
|-- docker-compose.yml           # framework + ollama + ollama-pull
|-- docker-compose.host-ollama.yml
|-- docker-compose.gpu.yml
|-- Dockerfile
|-- .dockerignore
|-- .env.example
|-- requirements.txt             # runtime uniquement, pas de torch
|-- requirements-dev.txt         # pytest, outils de dev, jamais copié dans l'image
|-- core/
|   |-- state.py
|   |-- memory.py
|   |-- orchestrator.py
|   `-- config.py
|-- agents/
|   |-- base_agent.py
|   |-- recon_agent.py
|   |-- enum_agent.py
|   |-- exploit_agent.py
|   |-- postexploit_agent.py
|   `-- report_agent.py
|-- tools/
|   |-- base.py
|   |-- nmap_tool.py
|   |-- gobuster_tool.py
|   |-- nikto_tool.py
|   |-- sqlmap_tool.py
|   `-- ffuf_tool.py
|-- api/
|   |-- dependencies.py
|   |-- websocket.py
|   `-- routes/
|       |-- missions.py
|       |-- reports.py
|       `-- agents.py
|-- templates/
|   |-- base.html
|   |-- dashboard.html
|   `-- report.html
|-- main.py
|-- reports/                     # sorties générées, pas versionnées
|-- db/                          # sorties générées, pas versionnées
`-- tests/
    |-- test_state.py            # priorité : fonctions du cœur déterministe
    |-- test_orchestrator.py     # priorité : garde-fous anti-boucle
    |-- test_tools.py
    `-- test_agents.py
```

---

## 6. Modèle de données (contrat à respecter)

**`MissionState`** (source unique de vérité, un objet par mission) :
- Identité : `mission_id`, `mission_name`, `operator`, `authorization_ref` (obligatoire si `REQUIRE_AUTHORIZATION=true`).
- Cible : `target` (host, ports, services, os).
- Cycle de vie : `status`, `current_agent`, `last_decision`, `completed_phases` (liste), `orchestration_cycles` (compteur).
- Résultats confirmés : `findings` (liste de `Finding`), append-only.
- Hypothèses non confirmées : `leads` (liste de `Lead`), append-only, jamais utilisées dans le calcul du risque.
- Journal : `attack_chain`, `tool_results`, `errors`.
- Contexte partage entre phases : `scratch` (dict par nom d'agent, ex. `scratch["enum"]["candidate_urls"]`) - purement informatif, jamais une source pour une decision de severite/risque.
- Rapport : `report_path`.

**`Finding`** : `title`, `severity` (enum CRITICAL/HIGH/MEDIUM/LOW/INFO), `description`, `affected_component`, `evidence`, `cve` (optionnel, jamais rempli sans preuve d'exploitation), `remediation`, `discovered_by`, `tags`. Si `cap_severity` plafonne effectivement la severite a la construction, une note automatique est ajoutee a `description` (visible dans le rapport) plutot qu'un plafonnement silencieux.

**`Lead`** (piste spéculative) : `title`, `rationale`, `source`, `confidence` (0 à 1), `tags`. Pas de champ `severity` : une piste n'est pas notée, elle est à vérifier.

---

## 7. Cœur déterministe : contrats des fonctions clés

Ces fonctions vivent dans `core/state.py`, sont appelées par tous les agents concernés, et ont des tests unitaires écrits en même temps que le code, pas après.

```
cap_severity(severity, exploited: bool) -> Severity
    # Sans preuve d'exploitation, une simple découverte ne dépasse jamais MEDIUM.
    # HIGH/CRITICAL exige exploited=True.
    if not exploited and severity in (HIGH, CRITICAL):
        return MEDIUM
    return severity

compute_overall_risk(findings: list[Finding]) -> Severity
    # Jamais demandé au LLM. Sévérité maximale parmi les findings confirmés.
    # Les leads n'entrent jamais dans ce calcul.
    return max(f.severity for f in findings) or INFO

consolidate_denied_paths(candidate_paths) -> Finding | None
    # Regroupe tous les chemins en 401/403 en UN SEUL finding LOW,
    # au lieu d'un finding par chemin.

enforce_progression(state, proposed_next_phase) -> phase
    # Garde-fou anti-boucle :
    #   - incrémente orchestration_cycles à chaque décision
    #   - si orchestration_cycles > MAX_CYCLES (défaut 10) : force "report" puis fin
    #   - si proposed_next_phase déjà dans completed_phases (et != "report") :
    #     force la première phase non terminée de l'ordre linéaire
    #   - si le LLM veut terminer sans être passé par "report" : force "report"

is_target_in_allowed_ranges(host, allowed_ranges) -> bool
    # Garde-fou de périmètre optionnel (désactivé si allowed_ranges est vide,
    # ce qui est le défaut : le MVP doit fonctionner contre une cible externe
    # quelconque). Résout un nom d'hôte en IP pour la vérification ; ferme
    # (False) si la résolution échoue alors que la restriction est active.
```

Contrat pour `nmap_tool.py` :
- Mode découverte, ports, vuln : `-Pn` toujours présent.
- SYN scan (`-sS`) par défaut si root ; mode `-sT` (connect scan) activable par configuration pour les environnements où le SYN scan est filtré ou pour tourner sans privilèges élevés (absent de la v1, à inclure cette fois, cf. `PROJECT.md`).
- `sudo` uniquement si `os.geteuid() != 0`.

---

## 8. Docker : stratégie et budget de taille

### Dockerfile (grandes lignes)

- Base : `python:3.11-slim-bookworm`, épinglée.
- Build multi-étapes : une étape pour compiler d'éventuelles roues Python, l'étape finale ne copie que le nécessaire à l'exécution (pas les outils de compilation, pas `requirements-dev.txt`).
- Paquets système : `nmap`, `bind9-dnsutils`, `perl` + les 4 modules Perl de nikto (section 2), dépendances WeasyPrint (`libpango-1.0-0`, `libpangocairo-1.0-0`, `libgdk-pixbuf-2.0-0`, `libffi-dev`, `libcairo2`, `shared-mime-info`, `fonts-dejavu-core`), `git`, `curl`, `wget`, `ca-certificates`, `tar`.
- `nikto` et `sqlmap` : clonés depuis GitHub (tag de release épinglé si possible), wrapper shell sur le PATH.
- `gobuster` et `ffuf` : binaires de release GitHub, multi-arch, noms cohérents avec le code.
- Wordlist : SecLists `common.txt` téléchargée dans l'image.
- `requirements.txt` : FastAPI, LangGraph, langchain-ollama, SQLAlchemy+aiosqlite, ChromaDB (sans `sentence-transformers`/`torch`), Jinja2, WeasyPrint, python-nmap, dnspython, httpx, websockets, loguru.

### Embeddings sans torch

ChromaDB accepte une fonction d'embedding personnalisée : appeler l'endpoint `/api/embeddings` du conteneur Ollama (modèle dédié léger, ex. `nomic-embed-text`, environ 0.27 Go, ou `all-minilm`, environ 0.05 Go, pour un budget encore plus serré) au lieu de charger `sentence-transformers` dans l'image Python. Ce seul changement retire plusieurs Go et plusieurs minutes de build par rapport à la v1.

### `docker-compose.yml` (services)

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    volumes: [ollama:/root/.ollama]

  ollama-pull:
    image: ollama/ollama:latest
    depends_on: [ollama]
    # pull automatique de OLLAMA_MODEL_MAIN et du modèle d'embeddings au premier démarrage
    restart: "no"

  framework:
    build: .
    depends_on: [ollama]
    environment:
      - OLLAMA_BASE_URL=http://ollama:11434
      - OLLAMA_MODEL_MAIN=${OLLAMA_MODEL_MAIN:-qwen3.5:9b}
      - OLLAMA_EMBED_MODEL=${OLLAMA_EMBED_MODEL:-nomic-embed-text}
    ports: ["8000:8000"]
    volumes: [./reports:/app/reports, ./db:/app/db]

volumes:
  ollama: {}
```

Profils additionnels en fichiers séparés (pas dans le compose principal, pour ne pas complexifier le cas par défaut) :
- `docker-compose.host-ollama.yml` : supprime `ollama`/`ollama-pull`, pointe `OLLAMA_BASE_URL` vers `host.docker.internal:11434` avec `extra_hosts: ["host.docker.internal:host-gateway"]`.
- `docker-compose.gpu.yml` : ajoute la réservation GPU NVIDIA au service `ollama`.

### Budget de taille estimé

| Élément | Taille approx. |
|---|---|
| Image `framework` (sans torch) | 0.9 à 1.2 Go |
| Image `ollama` (CPU, sans CUDA) | 1.5 à 2 Go |
| `qwen3.5:9b` (défaut) | ~5 à 6 Go |
| Modèle d'embeddings (`nomic-embed-text`) | 0.27 Go |
| Wordlist + divers | < 0.1 Go |
| **Total, configuration par défaut** | **~8 à 9.5 Go** |
| Avec repli `qwen3:8b` à la place de `qwen3.5:9b` | ~8 à 9 Go, comparable |
| Avec profil GPU + `qwen3.5:9b` | ~11 à 13 Go |

Marge confortable sous le plafond de sécurité de 25 Go, même en configuration haute. 25 Go n'est pas une cible, c'est un plafond à ne jamais dépasser.

**Ce tableau mesure l'espace disque, pas la RAM.** Les deux budgets sont différents et la RAM s'est révélée la contrainte la plus bloquante en déploiement réel sur une machine à 8 Go (voir section 3 pour l'estimation de RAM par modèle, et `docs/HISTORY.md` section 6). Un disque large sous le plafond n'implique pas que le modèle par défaut tienne confortablement en RAM sur toute machine.

---

## 9. Variables d'environnement (source unique de vérité)

| Variable | Défaut | Rôle |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Point d'accès au LLM. Seul endroit où l'URL est définie. |
| `OLLAMA_MODEL_MAIN` | `qwen3.5:9b` | Modèle utilisé par tous les agents. Sur une machine à ~8 Go de RAM, basculer sur `qwen3.5:4b` ; repli de compatibilité : `qwen3:8b`. Sans changement de code dans tous les cas. Voir section 3 pour le choix selon la RAM disponible. |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Modèle d'embeddings pour ChromaDB. |
| `REQUIRE_AUTHORIZATION` | `true` | Bloque toute mission sans `authorization_ref`. |
| `ALLOWED_TARGET_RANGES` | (vide) | CIDR separes par des virgules. Vide = aucune restriction (defaut, coherent avec le support de cibles externes). Garde-fou optionnel via `core/state.py::is_target_in_allowed_ranges`. |
| `NMAP_SCAN_MODE` | `syn` | `syn` (`-sS`, défaut si root) ou `connect` (`-sT`, repli réseaux filtrés/non-root). |
| `MAX_CYCLES` | `10` | Garde-fou anti-boucle de l'orchestrateur. |
| `LOG_LEVEL` | `INFO` | Niveau de log. |

---

## 10. Ordre de construction recommandé

1. `core/state.py` avec les fonctions déterministes (section 7) et leurs tests unitaires en premier, avant tout agent.
2. `core/config.py` avec les variables d'environnement de la section 9, une seule fois.
3. `tools/` un par un, chaque outil avec son test (commande générée, parsing de sortie).
4. `agents/base_agent.py` puis chaque agent, chacun appelant systématiquement `cap_severity` avant de créer un finding.
5. `core/orchestrator.py` avec la limite de cycles et le suivi des phases terminées dès la première version du graphe.
6. `templates/report.html` avec la section "Pistes à vérifier" dès le premier gabarit.
7. `api/` et `templates/dashboard.html`.
8. `Dockerfile` et `docker-compose.yml` en parallèle du point 3 (valider chaque outil dans le conteneur au fur et à mesure, pas à la fin).
9. Une mission de bout en bout contre une cible de test (DVWA sur un serveur séparé) avant de considérer le MVP terminé.

## 11. Critères de validation du MVP

- Une mission complète se termine toujours, y compris si le LLM boucle ou renvoie du JSON invalide.
- Un scan contre une cible qui bloque l'ICMP ou expose un service sur un port non standard trouve bien les ports ouverts (test de non-régression direct de l'incident `-Pn`).
- Aucun finding ne dépasse MEDIUM sans preuve d'exploitation, y compris si le LLM propose une sévérité plus haute.
- 22 chemins en 401/403 produisent un seul finding LOW, pas 22.
- Le score de risque global est reproductible : deux exécutions de la même mission sur la même cible donnent le même badge.
- `git clone` puis `cp .env.example .env` puis `docker compose up --build` fonctionne sans intervention manuelle sur une machine neuve (tester sur une VM propre, pas seulement sur la machine de développement).
- Taille totale des images + modèle par défaut sous les 10 Go.

## 12. À décider avant de lancer la reconstruction

- Vérifier au premier `pull` que `qwen3.5:9b` fonctionne correctement avec la version d'Ollama installée (gabarit de chat, appel d'outils). En cas de souci, basculer sur `qwen3:8b` via `OLLAMA_MODEL_MAIN`, sans changement de code. **Mis à jour** : premier déploiement réel effectué (Parrot OS, 8 Go de RAM) — le gabarit/appel d'outils a fonctionné, mais la RAM disponible s'est révélée la contrainte réelle plutôt que la compatibilité ; bascule vers `qwen3.5:4b` sur ce profil de machine. Détail dans `docs/HISTORY.md`, section 6.
- Choisir le modèle d'embeddings définitif (`nomic-embed-text` pour la qualité, `all-minilm` pour le poids minimal).
- Décider si les tests de la section 11 doivent tourner en CI (GitHub Actions) dès le MVP ou seulement en local dans un premier temps.
