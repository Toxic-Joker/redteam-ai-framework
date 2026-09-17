# RedTeam AI Framework : document de projet

Document stable, à ne pas modifier au fil des sessions de développement. Il définit le "pourquoi" et le "pour qui" du projet. Le "comment" technique (architecture, pièges à éviter, choix du modèle, ordre de construction) vit dans `CLAUDE.md`. L'historique complet de la première version vit dans `docs/HISTORY.md`.

## Mission

Fournir un framework d'orchestration Red Team multi-agents qui automatise les phases répétitives d'un test d'intrusion (reconnaissance, énumération, exploitation, post-exploitation, rapport), en s'appuyant sur un modèle de langage local pour la synthèse et le raisonnement contextuel, sans jamais laisser ce modèle décider seul des éléments critiques du livrable (sévérité, risque global, structure du rapport).

## Principe directeur (non négociable)

Le modèle de langage est **consultatif**. Il propose, résume, rédige et suggère des pistes. Toute décision engageante (sévérité d'un finding, calcul du risque global, structure du rapport) est **déterministe**, codée en dur, ancrée sur la preuve produite par les outils (codes HTTP, sorties réelles de nmap/gobuster/nikto/sqlmap). On ne gouverne pas un rapport de sécurité sur l'opinion d'un LLM.

Ce principe ne dépend pas de la qualité du modèle choisi. Même avec un modèle fiable, la séparation des autorités de décision reste la règle : elle sert l'auditabilité et la gouvernance du livrable, pas seulement la compensation d'un modèle faible.

## À qui ce projet s'adresse

- **Pentesters / Red Team** : gain de temps sur les phases répétitives (recon, énumération, rapport), pour se concentrer sur l'exploitation à forte valeur.
- **SOC / Blue Team** : une base d'exposition reproductible et rejouable, comparable dans le temps, avec peu de faux positifs grâce à la séparation entre findings confirmés et pistes spéculatives.
- **Gouvernance, risque et conformité (GRC)** : un score de risque déterministe et un rapport auditable, défendable en audit.
- **Hardening / RETEX** : un livrable consolidé qui alimente directement les cycles de remédiation.

## Portée du MVP (v1)

- Cycle complet automatisé : reconnaissance, énumération, exploitation prudente (preuve requise avant toute sévérité élevée), post-exploitation, génération de rapport PDF.
- Interface web : saisie de la cible et de la référence d'autorisation, suivi de mission en temps réel, téléchargement du rapport.
- Fonctionne contre une cible externe quelconque (pas seulement en réseau local), y compris quand la découverte ICMP est bloquée.
- Séparation stricte entre findings confirmés (impactent le risque) et pistes spéculatives (n'impactent jamais le risque).
- Déploiement en une commande (`docker compose up`) sur une machine neuve, sans intervention manuelle.

## Hors périmètre pour le MVP (non-goals explicites)

- Évasion mesurée face à des solutions EDR/XDR réelles. Les niveaux d'évasion restent un paramètre configurable, non validé.
- Généralité prouvée sur plusieurs cibles/OS. La reproductibilité (même résultat sur la même cible) est un objectif du MVP ; la généralité (comportement sur des cibles hétérogènes) ne l'est pas.
- Garde-fous légaux complets au-delà de la référence d'autorisation obligatoire et de la journalisation.
- Mesure chiffrée du gain de temps par rapport à un audit manuel. Objectif secondaire une fois le MVP stable : comparer le temps de mission avant/après changement de modèle.

## Contraintes non négociables

- Docker-first dès le premier commit, pas ajouté après coup.
- Aucune cible vulnérable embarquée dans le `docker-compose.yml`. La cible est toujours externe.
- Modèle de langage exécuté en local (contrainte de confidentialité, non négociable).
- Budget de taille total (images + poids du modèle) : cible réelle 8 à 10 Go, plafond de sécurité 25 Go à ne jamais dépasser.

## Définition du succès

Voir la section "Critères de validation du MVP" de `CLAUDE.md` pour la liste technique complète. En résumé : une mission se termine toujours, un finding sans preuve d'exploitation ne dépasse jamais MEDIUM, le risque global est reproductible d'une exécution à l'autre sur la même cible, et `git clone` puis `docker compose up --build` fonctionne sans intervention manuelle sur une machine neuve.

## Documents liés

- `CLAUDE.md` : blueprint technique (architecture, pièges Docker et réseau à éviter, choix du modèle, arborescence, ordre de construction). Lu automatiquement par Claude Code à chaque session de travail sur ce dépôt.
- `docs/HISTORY.md` : rétrospective complète de la première version du projet (mémoire de Mastère EFREI, soutenue) : ce qui a été tenté, ce qui a cassé, ce qui a été corrigé.
