# RedTeam AI Framework v2: reconstruction blueprint

This document is read automatically by Claude Code as project context. It
contains the technical "how": architecture, pitfalls to avoid, model choice,
build order. The "why" and "for whom" (mission, audiences, MVP scope,
non-goals) live in `PROJECT.md`, a stable document not to be modified across
sessions. The full history of the first version (everything that was tried,
broken, fixed) lives in `docs/HISTORY.md`. Read `PROJECT.md` before starting;
check `docs/HISTORY.md` before questioning a rule in this document that
seems arbitrary.

## TL;DR

- Docker-first reconstruction of a multi-agent Red Team orchestration
  framework already designed, fixed, and validated once before. This time,
  every fix from v1 is integrated from the first commit, not added along the
  way.
- Non-negotiable principle: the LLM is **consultative**, every critical
  decision (severity, risk, report structure) is **deterministic**, grounded
  in tool evidence.
- Default model: `qwen3.5:9b` (see section 3), chosen for its best balance
  of tool-calling reliability vs. size, with `qwen3:8b` as a proven
  fallback. On a machine with ~8 GB of total RAM, prefer `qwen3.5:4b` (a
  single environment variable, validated in a real deployment, see section
  3 and `docs/HISTORY.md` section 6).
- Target size budget: 8 to 10 GB in the default configuration, safety
  ceiling of 25 GB.
- No vulnerable target bundled in `docker-compose.yml`. The target is always
  external, entered in the web interface.

---

## 0. Read before starting

This project has already been built once. The initial code had invisible
technical debt: the reliability mechanisms (severity capping, consolidation,
deterministic risk calculation, anti-loop guardrails) were added **after
the fact**, agent by agent, which produced a specific oversight bug: one
uncovered agent let a fully hallucinated CRITICAL through to the final
report (detail in `docs/HISTORY.md`, section 4, incident 10). Docker
packaging was also done as an afterthought, which produced a long series of
avoidable errors (`docs/HISTORY.md`, section 4).

This reconstruction must integrate all of that **from the design stage**.
The following sections are the specification to build, not a proposal to
debate on the points marked "non-negotiable."

---

## 1. Project context

Ultra-condensed summary (full detail in `docs/HISTORY.md`):

- The full offensive cycle (recon, enumeration, exploitation,
  post-exploitation, reporting) was built and validated on real runs.
- The deterministic core (severity capping, findings consolidation,
  findings/leads separation, risk calculation) is the project's central
  contribution and worked as intended, including neutralizing a critical
  LLM hallucination.
- Docker deployment was added afterward and generated about a dozen
  avoidable incidents (network, missing packages, mis-named binaries,
  excessive size). Goal of this reconstruction: avoid them from the start
  (section 2).
- Two points remain explicitly unproven: generality across multiple
  targets, and measured evasion against a real EDR/XDR. See `PROJECT.md`
  for the full list of MVP non-goals.

---

## 2. Pitfalls encountered, never to repeat (design checklist)

Each line corresponds to a real incident documented in `docs/HISTORY.md`,
section 4. This time, they must be resolved **in the first commit**, not
discovered in production.

- [ ] Pin the Docker base (`python:3.11-slim-bookworm`, never
      `python:3.11-slim` alone).
- [ ] `nikto` and `sqlmap` are not reliable apt packages: install them from
      their GitHub repos (ideally pinning a release tag for long-term
      reproducibility).
- [ ] `nikto`'s Perl dependencies not to forget: `perl`,
      `libnet-ssleay-perl`, `libjson-perl`, `libxml-writer-perl`,
      `libnet-ip-perl`.
- [ ] The `gobuster` binary name must be identical in code and in the image
      (`gobuster`, never `gobuster3`). No compatibility symlink to maintain.
- [ ] `gobuster`, `ffuf`, `nuclei`, `dalfox`: GitHub release binaries
      (multi-arch `amd64`/`arm64`), never built from source. Verify
      individually, for each tool, both the asset name (schemes already all
      different: `.tar.gz` vs `.zip`, `x86_64` vs `amd64`, `arm64` vs
      `aarch64`, with or without the tag's `v`) **and** the archive's
      internal structure (`dalfox` nests its binary in a versioned
      subfolder, unlike the other three which have it at the root —
      `tar --strip-components=1` rather than a fixed filename to not depend
      on it). Never assume a tool follows the same scheme as another one in
      the same Dockerfile, on either point.
- [ ] Before writing a parser for an external tool: check its current
      implementation language (`gh api repos/<owner>/<repo> --jq
      '.language'`) and read the real source code of the field that
      distinguishes a positive result from a negative/informational one,
      not just its general documentation or CLI flags. A tool may have
      changed language (and therefore output format) between the
      documentation found online and the version actually installed
      (`dalfox`: Go → Rust rewrite, a `"type"` field with four values of
      which only one - `"V"` - is a real confirmation, the others wrongly
      looked like confirmations too).
- [ ] `nmap` must always run with `-Pn`, in discovery, ports, and vuln
      modes. Without it, a host that blocks ICMP (common across a Docker
      bridge into a segmented network) is seen as "down" and the port scan
      is skipped entirely.
- [ ] `sudo` only if the process isn't already running as root
      (`os.geteuid() == 0` -> no `sudo`).
- [ ] Never a vulnerable target bundled in `docker-compose.yml`.
- [ ] A single source of truth for the model name: one environment
      variable, read in one place (`core/config.py`), propagated
      everywhere.
- [ ] No `torch` or `sentence-transformers` in the Python dependencies:
      embeddings via the Ollama endpoint (section 8).
- [ ] gobuster's wordlist resolved with an existence check
      (`os.path.exists`) and a fallback to a known path.
- [ ] Severity capping applies through a single structural point
      (`Finding.__post_init__` in `core/state.py`), never an explicit call
      in an agent. **Updated along the way**: agents initially called
      `cap_severity` themselves before constructing each `Finding`
      (consistent with this rule's original intent); removed after a
      `Finding` already pre-capped by the agent prevented `__post_init__`
      from ever detecting a real gap between the intended severity and the
      final one, making the transparency note (see `Finding` contract
      below) inoperative in practice. Agents now pass the "intended"
      severity as-is; `Finding.__post_init__` remains the sole place that
      caps it, structurally impossible to bypass or forget (incident #10).
- [ ] The orchestrator's cycle limit and completed-phase tracking must exist
      from the graph's first commit, not be added after observing an
      infinite loop.
- [ ] A low-confidence `-O` (OS detection) guess must never appear as a
      fact in a report.
- [ ] `sqlmap` vulnerability detection: never combine independent keywords
      present anywhere in the output (`"parameter" in stdout and
      "injectable" in stdout`) — `sqlmap` also prints both words in its
      **negative** messages (`"parameter 'id' is NOT injectable"`). A
      single unambiguous positive signal, checked line by line (see
      `docs/HISTORY.md`, section 6).
- [ ] Start a mission with `asyncio.create_task` (handle kept to allow
      cancellation), never FastAPI's `BackgroundTasks`, which gives no way
      to interrupt a running mission.
- [ ] Any synchronous/blocking library called from an agent (e.g.
      `dnspython`) must go through `asyncio.to_thread`, never a direct call
      in a coroutine — a blocking call there freezes the entire asyncio
      loop, so the whole API and dashboard, not just the current mission.
- [ ] JSON extraction from an LLM response must tolerate markdown fences,
      literal control characters (`json.loads(..., strict=False)`), stray
      text before/after the object, and trailing commas — a smaller local
      model produces this kind of imperfection in practice, not just
      plain invalid JSON.
- [ ] Pass an explicit `recursion_limit` to LangGraph in addition to the
      `orchestration_cycles` counter — never implicitly rely on the
      library's default limit (undocumented, subject to change).
- [ ] Never guess a CLI flag name by analogy with another tool in the same
      Dockerfile (`-Header` exists in other scanners, not in `nikto` 2.5.0
      — verified in its real `GetOptions`). An invalid flag can make the
      tool fail silently: `nikto` falls back into its help screen and exits
      with code 0 (`exit $is_failure` undefined, numified to 0 in Perl), so
      perceived as a success — no error anywhere, a help text mistaken for
      a real finding (`docs/HISTORY.md`, section 17). Read the tool's real
      argument parser, not just its output format (cf. the dalfox rule
      above).
- [ ] Independent tools within the same phase (none reads another's output)
      run concurrently via `asyncio.gather()`, never sequentially by
      default — sequentiality was an unexamined default choice, not a
      necessity, and multiplied mission time for no reason
      (`docs/HISTORY.md`, section 18). Only the order *between* phases
      (recon before enum before exploit) is a real dependency, already
      protected by `enforce_progression`. Any fan-out over a variable-sized
      list (candidate URLs, forms) goes through a bounded
      `asyncio.Semaphore`, never an unbounded burst of subprocesses.
- [ ] The tool that tests someone else's security must hold itself to the
      same standard on its own exposure surface: every `/api/*` route goes
      through `require_api_key` (empty by default so it doesn't break an
      existing deployment, but a warning is logged at startup as long as
      `API_KEY` isn't set); every free-text field stored in a
      `Finding`/`Lead` goes through session-cookie redaction before storage
      (`MissionState.add_finding`/`add_lead`), never an assumed guarantee
      just because one tool (nuclei) redacts its own output
      (`docs/HISTORY.md`, section 20).

---

## 3. Model choice

`llama3.2:3b` (v1) produced malformed JSON in a significant fraction of its
responses and spent most of the mission time on inference. Research done
for v2, with an explicit criterion: **priority to tool-calling reliability
and hallucination reduction, speed coming second**.

Important point found while researching: general "quality/intelligence"
benchmarks don't predict tool-calling reliability. On an evaluation
dedicated specifically to tool calling, `gpt-oss-20b` scores higher on
general intelligence than Qwen3 and runs faster, but its success rate on
structured tool calling is lower (around 85%) than the Qwen3/Qwen3.5 family
(95% and above) at an equal or smaller size. In other words: more
"intelligent" in general doesn't mean more reliable for what this project
asks of it. So it isn't the best choice here despite appearances.

| Model | Size (Ollama) | Estimated RAM (inference) | Tool-calling reliability | Note |
|---|---|---|---|---|
| `llama3.2:3b` (v1, to replace) | ~2.0 GB | ~2.5-3 GB | Low, JSON often malformed | Do not reuse |
| `qwen3:4b` | 2.5 GB | ~3-3.5 GB | Very good for its size (~95%) | Lightest option if RAM is very limited |
| **`qwen3.5:4b`** | 3.4 GB (confirmed on `ollama.com/library`) | ~4-4.5 GB (estimate: weights + context/KV cache overhead) | Already beats `qwen3:8b` on a tool-calling-dedicated benchmark, despite its size | **Recommended on a machine with ~8 GB of total RAM.** Validated in a real deployment (Parrot OS, see `docs/HISTORY.md` section 6): better reliability than `qwen3:8b` for less than half its RAM. |
| **`qwen3.5:9b`** (repo default) | 6.6 GB (confirmed) | ~7-8 GB (confirmed in real deployment: Ollama reported ~7.4 GB of total RAM available, almost entirely used up on an 8 GB machine) | Most recent generation in the family, best absolute reliability in the table | Reserve for machines with at least 12-16 GB of RAM. On an 8 GB machine, prefer `qwen3.5:4b`: otherwise little headroom for the rest of the stack (framework, tools, OS). |
| `qwen3:8b` (proven fallback) | 5.2 GB | ~6-7 GB | ~95%, very widely proven | Use if `qwen3.5` causes a chat-template compatibility issue on a given Ollama version |
| `nemotron-nano:4b` (light fallback) | ~4.2 GB | ~5 GB | ~95% | Alternative if the two models above cause an issue on a specific machine |
| `gpt-oss-20b` (not selected) | ~13 GB | ~14-16 GB | ~85% on tool calling, despite a better general reasoning score | Faster and "more intelligent" in the general sense, but specifically less reliable on structured tool calling, and disproportionate RAM. Discarded for this project despite favorable appearances |

Estimated RAM = quantized model weights + overhead for context/KV cache
(~15-30% at this project's default context length, 4096 tokens). Values
marked "confirmed" come from a direct check (model size on
`ollama.com/library`, or Ollama logs in a real deployment); the others are
extrapolated estimates, to confirm on the first `pull` on the target
machine.

Decision: `qwen3.5:9b` remains the repo's default reference (best absolute
reliability) for machines with enough RAM. On a machine with ~8 GB of total
RAM, switch to `qwen3.5:4b` via `OLLAMA_MODEL_MAIN` (a single environment
variable, no code change) — this is the configuration validated in a real
deployment. `qwen3:8b` remains the compatibility fallback if `qwen3.5`
causes a chat-template issue. Apache 2.0 license in all cases.

Implementation point to respect: use the **instruct / non-thinking**
variants of these models for the agent loop, not the "reasoning" variants
(`thinking mode`, DeepSeek-R1-Distill, QwQ, etc.). A model that "thinks"
before calling a tool adds latency without necessarily improving structured
output reliability, and that isn't what this architecture expects from the
LLM (it's already confined to a consultative role, no need for a long
reasoning chain).

Keep the deterministic core despite this better model. A more reliable
model reduces the frequency of hallucinations, it doesn't eliminate them,
and the architecture's value doesn't depend on the model's quality (see
`PROJECT.md`, guiding principle).

The model runs in a separate Ollama container, never in the framework's own
image, so it can be changed without rebuilding the application image, and
to let an advanced user point to an Ollama already installed on their host
machine (`host-ollama` profile, section 8).

---

## 4. Target architecture

```
+-------------+      +--------------+
|  Dashboard   |<---->|   FastAPI    |
|  (Alpine.js  |  WS  |   + API REST |
|   + HTMX)    |      +------+-------+
+-------------+             |
                    +--------+--------+
                    |   Orchestrator   |  (LangGraph, anti-loop guardrails)
                    +--------+--------+
        +----------+---------+---------+-----------+
        v          v         v         v           v
     Recon       Enum     Exploit   Postexploit    Report
        |          |         |         |           |
        +----------+---------+---------+-----------+
                    | (tools: nmap, gobuster, nikto, sqlmap, ffuf, HTML crawler,
                    | nuclei, dalfox, commix)
                    v
              MissionState (SQLite)
              + semantic memory (ChromaDB, embeddings via Ollama)
                    |
                    v
          +-------------------+       +--------------+
          |  Ollama container  |<----->| qwen3.5:9b    |
          |  (consultative LLM |       | + embedding   |
          |   + embeddings)    |       |  model        |
          +-------------------+       +--------------+
```

Components (carried over from the previous project, section 2 fixes
integrated from the design stage):

- **`core/`**: `state.py` (MissionState, Finding, Lead, enums, deterministic
  functions), `orchestrator.py` (LangGraph graph, anti-loop guardrails from
  the start), `memory.py` (SQLite + ChromaDB), `config.py` (Pydantic
  Settings, a single source of truth per variable).
- **`agents/`**: `base_agent.py`, `recon_agent.py`, `enum_agent.py`,
  `exploit_agent.py`, `postexploit_agent.py`, `report_agent.py`. Every agent
  that creates findings calls the capping function from `core/state.py`,
  never a local reimplementation.
- **`tools/`**: `base.py`, `nmap_tool.py` (`-Pn` systematic),
  `gobuster_tool.py`, `nikto_tool.py`, `sqlmap_tool.py`, `ffuf_tool.py`,
  `nuclei_tool.py`, `dalfox_tool.py` (XSS), `commix_tool.py` (command
  injection), `crawler_tool.py` (pure async HTTP client, doesn't inherit
  from `BaseTool`: no external binary or subprocess).
- **`api/`**: REST routes (missions, reports, agents), real-time WebSocket,
  `GET /health` (Ollama connectivity — without it, an unreachable LLM
  backend silently degrades every `ask_llm` into `{}` with no visible
  signal).
- **`templates/`**: `dashboard.html`, `report.html` ("Leads to verify"
  section from the first template).

---

## 5. Target repo layout

```
redteam-framework/
|-- PROJECT.md                   # vision, audiences, MVP scope, non-goals
|-- CLAUDE.md                    # this document
|-- README.md                    # human-oriented copy + GitHub badges
|-- docs/
|   `-- HISTORY.md               # full v1 retrospective
|-- docker-compose.yml           # framework + ollama + ollama-pull
|-- docker-compose.host-ollama.yml
|-- docker-compose.gpu.yml
|-- Dockerfile
|-- .dockerignore
|-- .env.example
|-- requirements.txt             # runtime only, no torch
|-- requirements-dev.txt         # pytest, dev tools, never copied into the image
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
|-- reports/                     # generated output, not versioned
|-- db/                          # generated output, not versioned
`-- tests/
    |-- test_state.py            # priority: deterministic core functions
    |-- test_orchestrator.py     # priority: anti-loop guardrails
    |-- test_tools.py
    `-- test_agents.py
```

---

## 6. Data model (contract to respect)

**`MissionState`** (single source of truth, one object per mission):
- Identity: `mission_id`, `mission_name`, `operator`, `authorization_ref`
  (mandatory if `REQUIRE_AUTHORIZATION=true`).
- Target: `target` (host, ports, services, os, optional `session_cookie`
  supplied by the operator for pages protected by authentication - never
  guessed or automated by the framework, never exposed in the clear in an
  API response or a report).
- Lifecycle: `status`, `current_agent`, `last_decision`,
  `completed_phases` (list), `orchestration_cycles` (counter).
- Confirmed results: `findings` (list of `Finding`), append-only,
  deduplicated by `MissionState.add_finding` on normalized (title, affected
  component, severity) — the same tool (nikto, gobuster, ...) may re-report
  the same thing twice in a mission.
- Unconfirmed hypotheses: `leads` (list of `Lead`), append-only,
  deduplicated by `add_lead` on (title, source), never used in the risk
  calculation.
- Log: `attack_chain`, `tool_results`, `errors`.
- Context shared between phases: `scratch` (dict keyed by agent name, e.g.
  `scratch["enum"]["candidate_urls"]`) - purely informational, never a
  source for a severity/risk decision.
- Report: `report_path`.

**`Finding`**: `title`, `severity` (enum CRITICAL/HIGH/MEDIUM/LOW/INFO),
`description`, `affected_component`, `evidence`, `cve` (optional, never
filled in without proof of exploitation), `remediation`, `discovered_by`,
`tags`. If `cap_severity` actually caps the severity at construction, an
automatic note is added to `description` (visible in the report) instead of
a silent cap.

**`Lead`** (speculative lead): `title`, `rationale`, `source`, `confidence`
(0 to 1), `tags`. No `severity` field: a lead isn't scored, it's to be
verified.

---

## 7. Deterministic core: contracts of the key functions

These functions live in `core/state.py`, are called by every relevant
agent, and have unit tests written at the same time as the code, not after.

```
cap_severity(severity, exploited: bool) -> Severity
    # Without proof of exploitation, a mere discovery never exceeds MEDIUM.
    # HIGH/CRITICAL requires exploited=True.
    if not exploited and severity in (HIGH, CRITICAL):
        return MEDIUM
    return severity

compute_overall_risk(findings: list[Finding]) -> Severity
    # Never asked of the LLM. Maximum severity among confirmed findings.
    # Leads never enter this calculation.
    return max(f.severity for f in findings) or INFO

consolidate_denied_paths(candidate_paths) -> Finding | None
    # Groups all 401/403 paths into a SINGLE LOW finding,
    # instead of one finding per path.

enforce_progression(state, proposed_next_phase) -> phase
    # Anti-loop guardrail:
    #   - increments orchestration_cycles on every decision
    #   - if orchestration_cycles > MAX_CYCLES (default 10): forces "report" then ends
    #   - if proposed_next_phase is already in completed_phases (and != "report"):
    #     forces the first non-completed phase in the linear order
    #   - if the LLM wants to finish without going through "report": forces "report"
    #   - if proposed_next_phase skips an incomplete intermediate phase
    #     (different from both the first non-completed phase AND "report"):
    #     forces the first non-completed phase - a real regression: exploit
    #     before enum deprives exploit_agent of the URLs enum would have discovered

is_target_in_allowed_ranges(host, allowed_ranges) -> bool
    # Optional perimeter guardrail (disabled if allowed_ranges is empty,
    # which is the default: the MVP must work against any external
    # target). Resolves a hostname to an IP for the check; fails closed
    # (False) if resolution fails while the restriction is active.
```

The LLM can influence the next phase (`MissionState.last_decision`, filled
via the same summary call each agent already makes at the end of its phase
- no extra inference call), but `enforce_progression` remains the sole
final judge: an invalid suggestion, one already completed, or one
attempting to finish without going through "report" is ignored exactly as
a default choice would be. This remains consistent with the guiding
principle (`PROJECT.md`): the phase sequence isn't a severity, a risk, or a
report structure, so it isn't a "critical decision" in the sense that
principle means.

Contract for `nmap_tool.py`:
- Discovery, ports, vuln modes: `-Pn` always present.
- SYN scan (`-sS`) by default if root; `-sT` (connect scan) mode
  configurable for environments where SYN scan is filtered or to run
  without elevated privileges (absent from v1, to include this time, cf.
  `PROJECT.md`).
- `sudo` only if `os.geteuid() != 0`.

---

## 8. Docker: strategy and size budget

### Dockerfile (broad outline)

- Base: `python:3.11-slim-bookworm`, pinned.
- Multi-stage build: one stage to compile any Python wheels, the final
  stage only copies what's needed at runtime (no build tools, no
  `requirements-dev.txt`).
- System packages: `nmap`, `bind9-dnsutils`, `perl` + nikto's 4 Perl
  modules (section 2), WeasyPrint dependencies (`libpango-1.0-0`,
  `libpangocairo-1.0-0`, `libgdk-pixbuf-2.0-0`, `libffi-dev`, `libcairo2`,
  `shared-mime-info`, `fonts-dejavu-core`), `git`, `curl`, `wget`,
  `ca-certificates`, `tar`, `unzip` (nuclei ships as `.zip`, not
  `.tar.gz`).
- `nikto`, `sqlmap` and `commix`: cloned from GitHub (pinned release tag
  when possible), shell wrapper on the PATH. `commix` directly reuses
  `sqlmap`'s CLI architecture (same conventions), confirmed via its own
  source code before writing, never assumed by analogy.
- `gobuster`, `ffuf`, `nuclei` and `dalfox`: GitHub release binaries,
  multi-arch, names consistent with the code. Each tool's actual naming
  verified individually via the GitHub API before writing (see section 2:
  never assume a tool follows the same scheme as another one in the same
  Dockerfile - `nuclei` uses a `.zip`, `gobuster` a `Linux_x86_64` naming,
  `dalfox` a `dalfox-vX.Y.Z-linux-aarch64.tar.gz` naming, again different
  from the other three). `nuclei` templates pre-downloaded at build time
  (`nuclei -update-templates`), tolerant of a network failure at build
  (`|| true`: catches up on first real run).
- Wordlist: SecLists `common.txt` downloaded into the image.
- `requirements.txt`: FastAPI, LangGraph, langchain-ollama,
  SQLAlchemy+aiosqlite, ChromaDB (without `sentence-transformers`/`torch`),
  Jinja2, WeasyPrint, python-nmap, dnspython, httpx, `beautifulsoup4`
  (`html.parser` backend, no `lxml`), websockets, loguru.

### Embeddings without torch

ChromaDB accepts a custom embedding function: call the Ollama container's
`/api/embeddings` endpoint (a dedicated lightweight model, e.g.
`nomic-embed-text`, about 0.27 GB, or `all-minilm`, about 0.05 GB, for an
even tighter budget) instead of loading `sentence-transformers` into the
Python image. This one change removes several GB and several minutes of
build time compared to v1.

### `docker-compose.yml` (services)

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    volumes: [ollama:/root/.ollama]

  ollama-pull:
    image: ollama/ollama:latest
    depends_on: [ollama]
    # automatic pull of OLLAMA_MODEL_MAIN and the embedding model on first startup
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

Additional profiles in separate files (not in the main compose file, to
keep the default case simple):
- `docker-compose.host-ollama.yml`: removes `ollama`/`ollama-pull`, points
  `OLLAMA_BASE_URL` to `host.docker.internal:11434` with
  `extra_hosts: ["host.docker.internal:host-gateway"]`.
- `docker-compose.gpu.yml`: adds the NVIDIA GPU reservation to the `ollama`
  service.

### Estimated size budget

| Element | Approx. size |
|---|---|
| `framework` image (no torch, includes `nuclei` templates) | 1.2 to 1.6 GB (to confirm on first build - `nuclei` templates add a non-negligible size not measured in this environment) |
| `ollama` image (CPU, no CUDA) | 1.5 to 2 GB |
| `qwen3.5:9b` (default) | ~5 to 6 GB |
| Embedding model (`nomic-embed-text`) | 0.27 GB |
| Wordlist + misc | < 0.1 GB |
| **Total, default configuration** | **~8 to 9.5 GB** |
| With `qwen3:8b` fallback instead of `qwen3.5:9b` | ~8 to 9 GB, comparable |
| With GPU profile + `qwen3.5:9b` | ~11 to 13 GB |

Comfortable margin under the 25 GB safety ceiling, even in the high-end
configuration. 25 GB isn't a target, it's a ceiling never to be exceeded.

**This table measures disk space, not RAM.** The two budgets are different,
and RAM turned out to be the most blocking constraint in a real deployment
on an 8 GB machine (see section 3 for RAM estimates per model, and
`docs/HISTORY.md` section 6). A large disk budget under the ceiling doesn't
imply the default model fits comfortably in RAM on every machine.

---

## 9. Environment variables (single source of truth)

| Variable | Default | Role |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Endpoint for the LLM. The only place the URL is defined. |
| `OLLAMA_MODEL_MAIN` | `qwen3.5:9b` | Model used by every agent. On a machine with ~8 GB of RAM, switch to `qwen3.5:4b`; compatibility fallback: `qwen3:8b`. No code change in any case. See section 3 for the choice based on available RAM. |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model for ChromaDB. |
| `REQUIRE_AUTHORIZATION` | `true` | Blocks any mission without `authorization_ref`. Only checks that a non-empty string is supplied - a note for traceability, not a technical control (see `API_KEY` for the API's actual protection). |
| `API_KEY` | (empty) | Shared key protecting every `/api/*` route (`X-API-Key` header, or `?api_key=` as a fallback for the report's direct download link). Empty by default = API open to anyone reaching the port - set before any exposure beyond the operator's machine (`docker-compose.yml` publishes on `0.0.0.0` by default). See `docs/HISTORY.md`, section 20. |
| `ALLOWED_TARGET_RANGES` | (empty) | Comma-separated CIDRs. Empty = no restriction (default, consistent with supporting external targets). Optional guardrail via `core/state.py::is_target_in_allowed_ranges`. |
| `NMAP_SCAN_MODE` | `syn` | `syn` (`-sS`, default if root) or `connect` (`-sT`, fallback for filtered networks/non-root). |
| `MAX_CYCLES` | `10` | Orchestrator anti-loop guardrail. |
| `LOG_LEVEL` | `INFO` | Log level. |
| `LLM_NUM_PREDICT` | `512` | Cap on Ollama generation length per call. Every prompt asks for short JSON; bounds the worst case on a CPU-only model without ever cutting off a useful reply (`docs/HISTORY.md`, section 18). |
| `LLM_TIMEOUT_SECONDS` | `180` | Safety timeout per LLM call (`client_kwargs` of the `ollama` client, itself based on httpx) - a stuck call must never freeze a phase indefinitely. |
| `NIKTO_MAX_TIME` | `180s` | nikto's own `-maxtime` (a real flag, see its `usage()`): bounds the worst case on a slow/verbose site. |
| `EXPLOIT_MAX_CONCURRENT_URLS` | `5` | Bounded concurrency between candidate URLs/forms in `exploit_agent.py` (`asyncio.Semaphore`) - never an unbounded burst of subprocesses against the target. |

---

## 10. Recommended build order

1. `core/state.py` with the deterministic functions (section 7) and their
   unit tests first, before any agent.
2. `core/config.py` with the environment variables from section 9, once.
3. `tools/` one by one, each tool with its test (generated command, output
   parsing).
4. `agents/base_agent.py` then each agent, each passing the "intended"
   severity directly to `Finding` without capping it itself -
   `Finding.__post_init__` is the sole point where `cap_severity` applies.
5. `core/orchestrator.py` with the cycle limit and completed-phase tracking
   from the graph's first version.
6. `templates/report.html` with the "Leads to verify" section from the
   first template.
7. `api/` and `templates/dashboard.html`.
8. `Dockerfile` and `docker-compose.yml` in parallel with point 3 (validate
   each tool in the container as you go, not at the end).
9. An end-to-end mission against a test target (DVWA on a separate server)
   before considering the MVP done.

## 11. MVP validation criteria

- A complete mission always finishes, including if the LLM loops or returns
  invalid JSON.
- A scan against a target that blocks ICMP or exposes a service on a
  non-standard port does find the open ports (direct regression test for
  the `-Pn` incident).
- No finding exceeds MEDIUM without proof of exploitation, including if the
  LLM proposes a higher severity.
- 22 paths returning 401/403 produce a single LOW finding, not 22.
- The overall risk score is reproducible: two runs of the same mission
  against the same target give the same badge.
- `git clone` then `cp .env.example .env` then `docker compose up --build`
  works with no manual intervention on a fresh machine (test on a clean VM,
  not just the development machine).
- Total size of the images + default model under 10 GB.

## 12. To decide before starting the reconstruction

- Verify on the first `pull` that `qwen3.5:9b` works correctly with the
  installed Ollama version (chat template, tool calling). If there's an
  issue, switch to `qwen3:8b` via `OLLAMA_MODEL_MAIN`, no code change.
  **Updated**: first real deployment done (Parrot OS, 8 GB of RAM) — the
  chat template/tool calling worked, but available RAM turned out to be the
  real constraint rather than compatibility; switched to `qwen3.5:4b` on
  this machine profile. Detail in `docs/HISTORY.md`, section 6.
- Choose the final embedding model (`nomic-embed-text` for quality,
  `all-minilm` for minimal weight).
- Decide whether the section 11 tests should run in CI (GitHub Actions)
  from the MVP onward or only locally at first. **Settled**: yes, as soon
  as the repo became public — `.github/workflows/tests.yml` runs `pytest`
  on every push/PR to `main`. Deliberately scoped to the unit tests
  (`tests/`), which need neither Ollama nor the external tool binaries; no
  end-to-end mission against a real target runs in CI.
