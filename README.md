# RedTeam AI Framework

![Tests](https://github.com/Toxic-Joker/redteam-ai-framework/actions/workflows/tests.yml/badge.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

**A multi-agent Red Team orchestration framework where the AI never gets the final word.**
A local language model (`qwen3.5:9b` by default) is **consultative** — it summarizes, drafts, and
suggests leads. Every consequential decision — a finding's severity, the mission's overall risk,
the report's structure — is **deterministic**, grounded in the evidence the tools (nmap, gobuster,
nikto, sqlmap, ffuf, nuclei, dalfox, commix) actually produced, never in the model's opinion.

<p align="center">
  <a href="#start-in-3-steps"><b>Start in 3 steps</b></a> &nbsp;·&nbsp;
  <a href="#built-to-survive-a-flaky-local-llm">Why trust it</a> &nbsp;·&nbsp;
  <a href="#secured-by-default">Security</a> &nbsp;·&nbsp;
  <a href="#questions">Questions</a>
</p>

See [`PROJECT.md`](PROJECT.md) for the mission, audiences, and MVP scope; [`CLAUDE.md`](CLAUDE.md)
for the technical blueprint; [`docs/HISTORY.md`](docs/HISTORY.md) for the full retrospective of
every incident, fix, and audit.

## Start in 3 steps

### 1. Clone and configure

```bash
git clone https://github.com/Toxic-Joker/redteam-ai-framework.git
```

```bash
cd redteam-ai-framework && cp .env.example .env
```

### 2. Bring up the stack

```bash
docker compose up --build
```

On first startup, `ollama-pull` automatically downloads `qwen3.5:9b` (~6.6 GB) — this can take
several minutes depending on your connection. The dashboard is then served at
`http://localhost:8000`, bound to your own machine only (see [Secured by
default](#secured-by-default)).

### 3. Run a mission

1. Open the dashboard, enter the target (always external — no vulnerable target is bundled in
   this repo) and an authorization reference.
2. Watch real-time progress across the five phases: recon → enum → exploit → postexploit → report.
3. Download the PDF report once the mission completes.

## Built to survive a flaky local LLM

A small, locally-hosted model loops, hallucinates, and returns malformed JSON in practice — the
architecture is built around that fact, not against it:

- **A mission always finishes.** An anti-loop guardrail (`enforce_progression`) forces the mission
  toward `report` once a cycle limit is hit, and a stuck or unreachable Ollama call degrades to an
  empty consultative reply rather than freezing the phase.
- **Severity is never the model's opinion.** `cap_severity` holds every discovery at `MEDIUM` or
  below unless the finding came with actual proof of exploitation — even if the LLM proposes
  `CRITICAL`. One structural checkpoint (`Finding.__post_init__`), impossible to bypass per-agent.
- **The risk score is reproducible.** `compute_overall_risk` takes the maximum severity among
  confirmed findings — never asked of the LLM. Two runs against the same target, the same badge.
- **A hunch can never inflate the risk.** Findings (tool-evidenced) and leads (LLM-suggested,
  unconfirmed) are structurally separate lists; leads never enter the risk calculation.
- **Malformed output doesn't stop a mission.** JSON extraction tolerates markdown fences, stray
  prose, and trailing commas — and `format="json"` constrains the model's own output at the
  source, reducing how often that tolerance is even needed.

## Secured by default

A tool built to find security gaps holds itself to the same standard on its own exposure surface:

- **Nothing is reachable off your machine unless you ask.** `BIND_HOST` defaults to `127.0.0.1`
  (opt-in to expose, not opt-out) — set it to `0.0.0.0` to reach the dashboard from your LAN.
- **Every `/api/*` route, plus the WebSocket, can require a shared key.** Set `API_KEY` for a
  second layer independent of network exposure; comparisons are timing-safe
  (`hmac.compare_digest`).
- **The container runs as a non-root user.** A fixed-UID `app` user, with `nmap`'s SYN-scan path
  already falling back to a connect scan automatically when it isn't root — no capability is
  granted that a mission doesn't need.
- **A target can't smuggle a flag into a tool's own argv.** Every `target_host` is validated at
  the API boundary before it ever reaches `nmap` or `dalfox` as a bare CLI argument.
- **Session cookies never leak into storage.** Any cookie supplied for an authenticated mission is
  redacted from every `Finding`/`Lead` before it's written to disk.

The full audit — what was found, how each fix was verified, and what's still open — is in
[`docs/HISTORY.md`](docs/HISTORY.md), section 27.

## Choosing a model based on available RAM

The default model (`qwen3.5:9b`) uses about 7-8 GB of RAM at inference time (confirmed in a real
deployment), not just its disk footprint. On a machine with little headroom, set
`OLLAMA_MODEL_MAIN` in `.env` before the first `docker compose up`:

| Machine's total RAM | Recommended model | Approx. RAM at inference |
|---|---|---|
| 8 GB | `qwen3.5:4b` | ~4-4.5 GB |
| 12-16 GB | `qwen3.5:9b` (default) | ~7-8 GB |

See `CLAUDE.md`, section 3, for the full table (tool-calling reliability per model) and
`docs/HISTORY.md`, section 6, for the deployment feedback that motivated this recommendation.
Switching models on an already-running stack is covered in [Questions](#questions) below.

## Additional deployment profiles

```bash
# Ollama already installed on the host machine (no ollama container)
docker compose -f docker-compose.host-ollama.yml up --build
```

```bash
# NVIDIA GPU for Ollama (requires the NVIDIA Container Toolkit)
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build
```

## Questions

<details>
<summary><b>Do I need authorization to scan a target?</b></summary>
<br>

Yes — that's enforced, not just advised. `REQUIRE_AUTHORIZATION=true` (the default) blocks any
mission without an `authorization_ref`. It's a traceability note, not a technical control: only a
non-empty string is checked, not verified against anything. The actual technical boundary is
`API_KEY` plus `BIND_HOST` — see [Secured by default](#secured-by-default). No vulnerable target
is ever bundled with this repo; the target is always external, entered by you in the dashboard.
</details>

<details>
<summary><b>Is the dashboard exposed to my network by default?</b></summary>
<br>

No. `BIND_HOST` defaults to `127.0.0.1`, so port 8000 is only reachable from the machine running
Docker. Set `BIND_HOST=0.0.0.0` in `.env` to reach it from your LAN, and set `API_KEY` first if
you do.
</details>

<details>
<summary><b>Does it need root?</b></summary>
<br>

No. The container runs as a non-root user by default. `nmap`'s SYN scan normally needs raw-socket
capability; when the process isn't root, `tools/nmap_tool.py` falls back to a TCP connect scan
(`-sT`) automatically, no configuration needed. You can also force connect-scan mode explicitly
with `NMAP_SCAN_MODE=connect`.
</details>

<details>
<summary><b>What does it cost to run?</b></summary>
<br>

Every tool involved is free and open source. The real cost is RAM for the local model (see the
table above) and disk for the Docker images and model weights (8 to 10 GB in the default
configuration, 25 GB safety ceiling never exceeded). No API keys, no cloud LLM billing — the
model runs entirely on your own machine.
</details>

<details>
<summary><b>Can I point it at an Ollama I already have installed?</b></summary>
<br>

Yes — `docker-compose -f docker-compose.host-ollama.yml up --build` skips the bundled `ollama`
container and points the framework at `host.docker.internal:11434` instead.
</details>

<details>
<summary><b>How do I switch models on an already-running stack?</b></summary>
<br>

```bash
# 1. stop the framework (interrupts any running mission, no hot resume)
docker compose stop framework
```

```bash
# 2. update .env
sed -i 's/^OLLAMA_MODEL_MAIN=.*/OLLAMA_MODEL_MAIN=qwen3.5:4b/' .env
```

```bash
# 3. pull the new model into the already-running ollama container
docker exec redteam-ai-framework-ollama-1 ollama pull qwen3.5:4b
```

```bash
# 4. remove the old model to free up disk space (~6.6 GB for qwen3.5:9b)
docker exec redteam-ai-framework-ollama-1 ollama rm qwen3.5:9b
```

```bash
# 5. recreate the framework so it picks up the new variable
docker compose up -d framework
```

(Adjust the container name `redteam-ai-framework-ollama-1` if it differs on your machine — check
with `docker compose ps`.)
</details>

<details>
<summary><b>Why is the report in French, and can I change it?</b></summary>
<br>

Only because the project's first client was French — not a technical constraint. The LLM's own
prompts (`agents/*.py`) are written in French, which is what makes the model draft its executive
summary in French too; the deterministic fallback strings and the dashboard's static template
text are separate plain strings that would need translating alongside them. Three places to
touch in total, listed exactly in [What's validated, and what's left to do](#whats-validated-and-whats-left-to-do).
</details>

<details>
<summary><b>Can I run it without Docker, for development?</b></summary>
<br>

```bash
python -m venv .venv
```

```bash
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

```bash
pip install -r requirements-dev.txt
```

```bash
pytest
```

The unit tests (`tests/`) primarily cover the deterministic core (`core/state.py`) and the
orchestrator's anti-loop guardrails; they require neither Ollama nor the external tool binaries.
Every environment variable is documented in `.env.example` and `CLAUDE.md`, section 9 — a single
source of truth per variable, read once in `core/config.py`.
</details>

## What's validated, and what's left to do

The full offensive cycle (recon → enum → exploit → postexploit → report) has been validated
across several real missions against DVWA: SQL injection and XSS confirmed by tool evidence,
severity/risk computed deterministically, a mission that always completes even when the local LLM
loops or replies with nonsense. A full mission now takes about 20 to 25 minutes (down from 70 to
90 minutes before the concurrency optimization, `docs/HISTORY.md` section 18). A full
security/quality audit closed every gap in [Secured by default](#secured-by-default) above,
including a live, non-root `docker compose up` run against a real mission — not just unit-tested
(`docs/HISTORY.md`, section 27). The dashboard has also had a full accessibility and UX pass:
WCAG-AA contrast throughout, keyboard navigation, a two-step confirmation before an irreversible
delete, and mission errors surfaced in full instead of a bare count.

**For whoever picks up this project from here**, in a reasonable priority order:

1. **Scrape the real CSRF token instead of synthesizing `field=1` for every form field**
   (`tools/crawler_tool.py::_extract_forms`). DVWA modules protected by a CSRF token on a POST
   request (Stored XSS, Command Injection) are currently invisible to `sqlmap`/`commix`, since the
   synthesized token (`user_token=1`) is systematically rejected by the target before it ever
   reaches the vulnerable logic — not a failure of those tools, a limitation of the crawler's
   form-filling. Reading the real `value` of any field that looks like a token (`token`, `csrf`,
   `authenticity`) directly from the already-parsed HTML is enough for the first submission;
   beyond that, a token generally has a short lifetime and should be re-scraped before each new
   attempt rather than reused.
2. **Audit dependencies (`requirements.txt`) against known CVEs** (e.g. `pip-audit`) — never done,
   for lack of network access from the environment this project was built in.
3. **Prove generality across multiple targets.** Everything validated so far has been against a
   single lab target (DVWA), repeatedly. The two explicit MVP non-goals (`PROJECT.md`) —
   generality across multiple targets and measured evasion against a real EDR/XDR — remain
   unproven.
4. **Change the report/dashboard language, if needed.** Two places to touch, and both need to
   change together for a consistent result:
   - The LLM system/user prompts in each agent (`agents/recon_agent.py`, `enum_agent.py`,
     `exploit_agent.py`, `postexploit_agent.py`, `report_agent.py`) — these tell the model what
     language to draft its summaries, key risks, and immediate actions in. The deterministic
     fallback strings right next to them (used when the LLM replies with nothing usable, e.g.
     `report_agent.py::_fallback_executive_summary`, and every `Finding`/`Lead` text agents
     construct directly) are plain Python strings, not templated — just translate them like any
     other string literal.
   - The hardcoded UI text in `templates/dashboard.html` (labels, buttons, the synthesized log
     lines) and `templates/report.html` (section headings, table labels) — these aren't driven by
     the LLM at all, they're static template text.
   - Two hardcoded strings in the deterministic core itself: `core/state.py::consolidate_denied_paths`
     (the consolidated 401/403 finding's title/description/remediation) and the automatic
     "severity capped" note in `Finding.__post_init__`. Everything else in `core/state.py`, the
     orchestrator, and every tool wrapper is language-agnostic — they only ever pass structured
     data (severities, booleans, URLs) around.
5. **Instrument phase-level timing/metrics** (duration, tool-call count, LLM-call count per
   phase). Time saved versus a manual audit has never been measured (`docs/HISTORY.md`, section
   5) — this closes that gap without touching the deterministic core (pure observability; no
   decision consumes the numbers). Deliberately left open rather than built: deciding where to
   instrument (per-agent, per-tool, or both) is a design call worth making deliberately
   (`docs/HISTORY.md`, section 21).
6. **Generic, non-actionable remediation text** on nmap-vuln and nuclei findings ("examine the
   script's result and apply the fix," "consult the template's documentation") — real advice
   would need a remediation lookup table keyed by script/template ID, or routing remediation
   drafting to the LLM as consultative content with the current text as the deterministic
   fallback (`docs/HISTORY.md`, section 23).
7. **`http-enum`'s MEDIUM severity** deserves a second look — unlike `LIKELY VULNERABLE` (now a
   `Lead`, see section 23), there's no generalizable nmap-side marker distinguishing a plain
   directory listing from a real finding, so fixing it means hardcoding one script ID, deliberately
   not done without first reviewing nmap's vuln-category script list as a whole.
8. **`log_error` is only called from `recon_agent.py` and `report_agent.py`.** Whether
   `enum`/`exploit`/`postexploit` genuinely never fail or just don't report it yet is unverified
   (`docs/HISTORY.md`, section 23).

Every fix already applied (and its exact root cause) is documented chronologically in
`docs/HISTORY.md` — read it before questioning a `CLAUDE.md` rule that might seem arbitrary out
of context.

## License

[Apache 2.0](LICENSE) — consistent with the license of the recommended Qwen models (section 3).

The `Dockerfile` downloads several third-party tools from their official repositories at build
time (never vendored/redistributed in this repo): `gobuster` (Apache 2.0), `ffuf`, `nuclei`, and
`dalfox` (MIT), `sqlmap` (GPLv2), `nikto` and `commix` (GPLv3). Each remains under its own
license; check its upstream repository for the exact terms.
