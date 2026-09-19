# RedTeam AI Framework

![Tests](https://github.com/Toxic-Joker/redteam-ai-framework/actions/workflows/tests.yml/badge.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

Multi-agent Red Team orchestration framework. A local language model
(`qwen3.5:9b` by default) is **consultative**: it summarizes, drafts, and
suggests leads. Every consequential decision — a finding's severity, the
mission's overall risk, the report's structure — is **deterministic**,
grounded in the evidence produced by the tools (nmap, gobuster, nikto,
sqlmap, ffuf), never in the model's opinion.

See `PROJECT.md` for the mission, audiences, and MVP scope; `CLAUDE.md` for
the technical blueprint; `docs/HISTORY.md` for the full retrospective of the
first version (EFREI Master's thesis).

## Quick start

```bash
git clone <this-repo>
cd redteam-framework
cp .env.example .env
docker compose up --build
```

The dashboard is served on `http://localhost:8000`. On first startup,
`ollama-pull` automatically downloads `qwen3.5:9b` (~6.6 GB) and the
embedding model `nomic-embed-text` (~0.27 GB) — this can take several
minutes depending on your connection.

## Choosing a model based on available RAM

The default model (`qwen3.5:9b`) uses about 7-8 GB of RAM at inference time
(confirmed in a real deployment), not just the disk budget documented above.
On a machine with little headroom, change `OLLAMA_MODEL_MAIN` in `.env`
before the first `docker compose up`, or live if the stack is already
running:

| Machine's total RAM | Recommended model | Approx. RAM at inference |
|---|---|---|
| 8 GB | `qwen3.5:4b` | ~4-4.5 GB |
| 12-16 GB | `qwen3.5:9b` (default) | ~7-8 GB |

See `CLAUDE.md`, section 3, for the full table (tool-calling reliability per
model) and `docs/HISTORY.md`, section 6, for the deployment feedback that
motivated this recommendation.

**Switching models on an already-running stack**, without rebuilding
everything:

```bash
# 1. stop the framework (interrupts any running mission, no hot resume)
docker compose stop framework

# 2. update .env
sed -i 's/^OLLAMA_MODEL_MAIN=.*/OLLAMA_MODEL_MAIN=qwen3.5:4b/' .env

# 3. pull the new model into the already-running ollama container
docker exec redteam-ai-framework-ollama-1 ollama pull qwen3.5:4b

# 4. remove the old model to free up disk space (~6.6 GB for qwen3.5:9b)
docker exec redteam-ai-framework-ollama-1 ollama rm qwen3.5:9b

# 5. recreate the framework so it picks up the new variable
docker compose up -d framework
```

(Adjust the container name `redteam-ai-framework-ollama-1` if it differs on
your machine — check with `docker compose ps`.)

## Additional profiles

```bash
# Ollama already installed on the host machine (no ollama container)
docker compose -f docker-compose.host-ollama.yml up --build

# NVIDIA GPU for Ollama (requires the NVIDIA Container Toolkit)
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build
```

## Usage

1. Open the dashboard, enter the target (always external — no vulnerable
   target is bundled in this repo) and an authorization reference.
2. Follow real-time progress (recon -> enum -> exploit -> postexploit ->
   report).
3. Download the PDF report once the mission is complete.

## Report and dashboard language

The generated report (PDF/HTML) and the dashboard UI are in **French**.
This project was originally built for a French client, and that's the only
reason — it isn't a technical constraint of the architecture. The LLM's own
prompts (`agents/*.py`) are also written in French, which is what makes the
model draft its executive summary, key risks, and immediate actions in
French too.

If you want the report/dashboard in another language, see the
"What's validated, and what's left to do" section below for where to make
that change.

## Local development (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt
pytest
```

The unit tests (`tests/`) primarily cover the deterministic core
(`core/state.py`) and the orchestrator's anti-loop guardrails; they require
neither Ollama nor the external tool binaries.

## Environment variables

See `.env.example` and `CLAUDE.md`, section 9. A single source of truth per
variable, read in `core/config.py`.

## What's validated, and what's left to do

The full offensive cycle (recon -> enum -> exploit -> postexploit -> report)
has been validated across several real missions against DVWA: SQL injection
and XSS confirmed by tool evidence, severity/risk computed deterministically,
a mission that always completes even when the local LLM loops or replies
with nonsense. A full mission now takes about 20 to 25 minutes (down from
70 to 90 minutes before the concurrency optimization, see `docs/HISTORY.md`
section 18). A security audit of the framework itself closed the most
consequential gap (no authentication on the API/dashboard, see section 20).

**For whoever picks up this project from here**, in a reasonable priority
order:

1. **Set `API_KEY` before any exposure beyond your own machine.**
   Empty by default so it doesn't break an existing deployment on the first
   `pull`, but `docker-compose.yml` publishes port 8000 on all network
   interfaces (`0.0.0.0`), not just `localhost`. Without this variable,
   anyone who can reach that port can launch a real mission against any
   target of their choosing. See `docs/HISTORY.md`, section 20.
2. **Scrape the real CSRF token instead of synthesizing `field=1` for every
   form field** (`tools/crawler_tool.py::_extract_forms`). DVWA modules
   protected by a CSRF token on a POST request (Stored XSS, Command
   Injection) are currently invisible to `sqlmap`/`commix`, since the
   synthesized token (`user_token=1`) is systematically rejected by the
   target before it ever reaches the vulnerable logic — not a failure of
   those tools, a limitation of the crawler's form-filling. Reading the real
   `value` of any field that looks like a token (`token`, `csrf`,
   `authenticity`) directly from the already-parsed HTML is enough for the
   first submission; beyond that, a token generally has a short lifetime and
   should be re-scraped before each new attempt rather than reused.
3. **Switch the container to a non-root user by default.**
   `NMAP_SCAN_MODE=connect` already exists for operating without elevated
   privileges; what's missing is the corresponding `USER` directive in the
   `Dockerfile` and confirming that every tool still works without root.
4. **Audit dependencies (`requirements.txt`) against known CVEs**
   (e.g. `pip-audit`) — never done, for lack of network access from the
   environment this project was built in.
5. **Prove generality across multiple targets.** Everything above has been
   validated repeatedly against a single lab target (DVWA). The two
   explicit MVP non-goals (`PROJECT.md`) — generality across multiple
   targets and measured evasion against a real EDR/XDR — remain unproven.
6. **Change the report/dashboard language, if needed.** It's French today
   only because the project's first client was French, not for any
   technical reason. Two places to touch, and both need to change together
   for a consistent result:
   - The LLM system/user prompts in each agent (`agents/recon_agent.py`,
     `enum_agent.py`, `exploit_agent.py`, `postexploit_agent.py`,
     `report_agent.py`) — these tell the model what language to draft its
     summaries, key risks, and immediate actions in. The deterministic
     fallback strings right next to them (used when the LLM replies with
     nothing usable, e.g. `report_agent.py::_fallback_executive_summary`,
     and every `Finding`/`Lead` text agents construct directly) are plain
     Python strings, not templated — just translate them like any other
     string literal.
   - The hardcoded UI text in `templates/dashboard.html` (labels, buttons,
     the synthesized log lines in `_diffAndLog`) and `templates/report.html`
     (section headings, table labels) — these aren't driven by the LLM at
     all, they're static template text.
   - Two hardcoded strings in the deterministic core itself:
     `core/state.py::consolidate_denied_paths` (the consolidated 401/403
     finding's title/description/remediation) and the automatic
     "severity capped" note in `Finding.__post_init__`. Everything else in
     `core/state.py`, the orchestrator, and every tool wrapper is
     language-agnostic — they only ever pass structured data (severities,
     booleans, URLs) around.

Every fix already applied (and its exact root cause) is documented
chronologically in `docs/HISTORY.md` — read it before questioning a
`CLAUDE.md` rule that might seem arbitrary out of context.

## License

Apache 2.0 - see `LICENSE`. Consistent with the license of the recommended
Qwen models (section 3).

The `Dockerfile` downloads several third-party tools from their official
repositories at build time (never vendored/redistributed in this repo):
`gobuster` (Apache 2.0), `ffuf`, `nuclei`, and `dalfox` (MIT), `sqlmap`
(GPLv2), `nikto` and `commix` (GPLv3). Each remains under its own license;
check its upstream repository for the exact terms.
