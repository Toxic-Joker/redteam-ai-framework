# Project history (v1)

Full retrospective of the framework's first version (Cybersecurity, Networks
& Cloud Master's thesis, EFREI, defended). This document explains the "why"
behind several technical choices that may look arbitrary in `CLAUDE.md` if
read without this context. Do not modify a `CLAUDE.md` rule without having
read the corresponding incident here.

## 1. What we originally set out to do

- Automate the full offensive cycle: reconnaissance, enumeration,
  exploitation, post-exploitation, reporting.
- A local LLM making contextual tactical decisions at each phase.
- Dynamic adaptation to the target's environment.
- Automatic generation of a professional pentest report (PDF).
- 40 to 50% reduction in time spent on repetitive tasks.
- Four contribution axes envisioned at the start: full coverage of the
  offensive cycle, dynamic evasion against EDR/XDR, report generation
  quality, ethical and legal guarantees.

## 2. What was actually built and validated

| Original goal | Status | Detail |
|---|---|---|
| Full recon, enum, exploit, postexploit, report cycle | Done | 5 agents orchestrated by a state graph (LangGraph), validated over several real runs against DVWA |
| Dynamic adaptation to the target | Partial | The LLM adapts the enumeration/exploitation plan to the services found, bounded by deterministic rules |
| Automatic PDF report generation | Done | Jinja2 to HTML then PDF (WeasyPrint), fixed structure, separate section for unconfirmed hypotheses |
| 40-50% time reduction | Never measured | No timed comparison against a manual baseline |
| 4 contribution axes | Refocused | Honest final scope: one central axis (deterministic reliability), two secondary axes delivered (full cycle, structured report), two axes out of scope (measured evasion, complete guardrails) |
| Reliability despite an unreliable local LLM | Done, core of the project | Severity capping, consolidation, findings/leads separation, deterministic risk calculation: confirmed on real reports |
| Infinite loop prevention | Done, fixed along the way | Cycle limit, completed-phase tracking, forced progression |
| Working against targets outside the local network or in a container | Done, with a necessary fix | `nmap -Pn` essential |
| Portable Docker deployment | Done, after a long series of fixes | See section 4 |
| False-positive reduction | Done | 22 paths returning 401/403 consolidated into a single LOW finding |

## 3. What was never done or validated

- Generality across multiple targets or operating systems: validated on a
  single target (DVWA), reproducibility demonstrated on only two repeated
  runs.
- Measured evasion against a real EDR/XDR: the parameter exists (levels 1 to
  3), never tested under real detection conditions.
- Complete ethical and legal guardrails: only a mandatory authorization
  reference and logging exist.
- `-sT` (connect scan) fallback for filtered targets: identified as
  missing, never implemented in v1.
- Reliable OS detection: `nmap -O` produced absurd results at high displayed
  confidence on single-port targets.
- Objective measurement of time saved compared to a manual audit.

## 4. Docker incident log (the most time-costly part)

Docker packaging was done after the application was built, not alongside
it. Result: a long series of avoidable back-and-forth. In real chronological
order:

1. **Unpinned Docker base.** `python:3.11-slim` (with no Debian version)
   changed major version under the project's feet along the way (switch to
   Debian trixie), breaking the installation of packages that had worked
   the day before. Fix: pin `python:3.11-slim-bookworm`.
2. **`nikto` not found via apt.** On recent Debian, `nikto` simply isn't an
   available package. Fix: GitHub clone + shell wrapper on the PATH.
3. **`sqlmap`, same problem.** Same fix: GitHub clone + shell wrapper.
4. **DNS broken inside the Docker build context**
   (`Temporary failure resolving 'deb.debian.org'`) while the host machine
   had working internet access. Cause: the Docker daemon had no working DNS
   resolver configured. Host-side fix: `/etc/docker/daemon.json` with
   `{"dns": ["8.8.8.8", "1.1.1.1"]}`, then `systemctl restart docker`.
5. **Disk space exhausted during an Ollama image pull**
   (`no space left on device`), caused by a `--no-cache` build cache never
   cleaned up (`docker builder prune -af` alone freed more than 10 GB)
   combined with an unnecessarily heavy Ollama image (CUDA libraries while
   the machine ran CPU-only).
6. **`gobuster` not found even though the image installed it.** The code
   called the binary `gobuster3` (a leftover from an old naming
   convention), the image installed `gobuster`. Result: silent failure of
   the entire directory enumeration, no visible error log on the user
   side. Temporary fix: a `gobuster3` symlink to `gobuster`. Clean fix for
   v2: a single name everywhere, no symlink to maintain.
7. **`nikto` failed silently in the container** (`Required module not
   found: JSON` then `XML::Writer`): missing Perl modules (`libjson-perl`,
   `libxml-writer-perl`), on top of `libnet-ssleay-perl` already present
   for SSL. Added `libnet-ip-perl` as a precaution.
8. **Empty reports in the container while the target responded perfectly
   fine to manual `curl` and `nmap -Pn`.** Cause: `nmap` without `-Pn` does
   its own host discovery (ping) before scanning ports. Across a Docker
   bridge into a segmented network (Host-Only VMware in this case), ICMP is
   commonly blocked, and the targeted service also ran on a non-standard
   port (8888) that default discovery doesn't test. Result: nmap concluded
   "host down" and skipped the port scan entirely. `-Pn` on every scan mode
   (ports, vuln) fixed the problem outright.
9. **`sudo nmap` failed in the container**: the slim image doesn't have
   `sudo` installed, and the container already runs as root. Fix: `sudo`
   only if `os.geteuid() != 0`.
10. **A hallucinated CRITICAL that made it through the whole pipeline.**
    Severity capping had been added to the enumeration agent but forgotten
    on the reconnaissance agent. The LLM produced a fake finding "Apache
    httpd vulnerable to Heartbleed, CVE-2014-0160" (an OpenSSL flaw,
    unrelated to Apache httpd, on a version not exposed to it) classified
    CRITICAL by the model itself, propagated as-is all the way to the
    mission's overall risk badge. Lesson recorded in `CLAUDE.md`: the
    capping function must be written once in `core/` and called by
    **every** agent that creates findings, never duplicated or forgotten
    agent by agent.
11. **Excessive weight and build time** caused by
    `sentence-transformers`/`torch` in `requirements.txt`, used only for
    ChromaDB semantic-memory embeddings. Never removed in v1 (identified,
    not fixed for lack of time). Planned fix for v2: embeddings via the
    `/api/embeddings` endpoint of a lightweight model already running in
    the Ollama container, which removes `torch` entirely from the Python
    dependencies.
12. **A vulnerable target initially bundled in `docker-compose.yml`** (a
    DVWA service). Removed on explicit request: the application container
    must only ever contain the framework, never a target, since the target
    is always external and supplied by the user.

## 5. Baseline results (real runs, v1)

- Baseline run: 35 minutes, 6 findings (5 MEDIUM, 1 LOW), overall MEDIUM
  badge.
- Two repeated runs against the same target (33m50s and 50m11s): the
  deterministic core was strictly identical (same confirmed findings, same
  MEDIUM badge, same consolidated 401/403 finding across 22 paths), only
  the speculative layer (number of leads proposed by the LLM, duration)
  varied. This is proof of the deterministic core's reproducibility, not
  of generality.
- Observed time breakdown: about 5% for the security tools, about 95% for
  local model inference. This is the exact problem the v2 model change
  aims to reduce.

## 6. First real v2 deployment (Parrot OS, 8 GB of RAM, 2026-09-18)

Unlike section 4 (v1 incidents), this section documents the reconstructed
v2's first real `docker compose up --build`, against a DVWA target. Two
findings worth keeping in mind to avoid rediscovering them in a future
session.

1. **Incorrect `gobuster` release asset naming.** The Dockerfile assumed,
   by analogy with `ffuf`, that `gobuster`'s GitHub assets followed the
   `gobuster_Linux_amd64.tar.gz` scheme. The build failed with a 404:
   `gobuster` actually names its assets `gobuster_Linux_x86_64.tar.gz` (and
   `gobuster_Linux_arm64.tar.gz`), with a capital "L" and `x86_64` rather
   than `amd64` — a scheme different from `ffuf`'s
   (`ffuf_<version>_linux_amd64.tar.gz`), even though both had been written
   by analogy with each other with no individual verification. Fixed after
   direct verification via
   `gh api repos/OJ/gobuster/releases/tags/<version>`. Lesson: verify each
   tool's actual naming individually via the GitHub API before writing it
   into the Dockerfile, never assume a tool follows the same scheme as
   another one in the same Dockerfile.
2. **The RAM budget, not just the disk budget, is a real constraint.**
   `qwen3.5:9b` (6.6 GB on disk, confirmed) used up nearly all the RAM
   available on an 8 GB machine: Ollama's logs reported
   `total="7.4 GiB" available="7.0 GiB"` in CPU mode, leaving little
   headroom for the rest of the stack (the `framework` container, ChromaDB,
   nmap/gobuster/nikto/sqlmap tool processes, plus the OS and Docker
   themselves). CLAUDE.md, section 8, had so far only budgeted disk space
   (target 8-10 GB) — a number under that ceiling doesn't guarantee the
   default model fits comfortably in RAM. Fix: `qwen3.5:4b` (3.4 GB on
   disk, confirmed via `ollama.com/library`) recommended and documented
   (CLAUDE.md, section 3) for any machine with ~8 GB of total RAM; it
   already beats `qwen3:8b` on the tool-calling benchmark cited in section
   3, for less than half its estimated RAM. No code change needed, only
   `OLLAMA_MODEL_MAIN` changes.
3. **A false CRITICAL confirmed against the framework's own target,
   combining a poorly chosen target and a parsing bug.** A mission targeted
   the host machine's LAN IP (suggested to reach DVWA published on that
   same machine); `nmap` found port 8000 open there — the framework's own
   port, not DVWA on 8080, which was never reached. `exploit_agent` then
   tested `http://<host>:8000/?id=1` (its own root route) with `sqlmap`,
   which reported a negative result ("parameter 'id' is NOT injectable").
   `tools/sqlmap_tool.py`'s parsing nonetheless classified this result as
   "vulnerable" because of a buggy check:
   `"parameter" in stdout and "injectable" in stdout`, true for both a
   positive and a negative message. Result: a fully fabricated CRITICAL
   "SQL injection confirmed" finding, propagated up to the overall risk
   badge. Fixed: a single unambiguous positive signal (`"is vulnerable"`
   checked line by line, never a combination of independent keywords over
   the whole output). See CLAUDE.md, section 2, for the generalized rule.

## 7. Comparison with a v1 snapshot and adoptions (2026-09-18)

The user provided a snapshot of their old v1 project
(`reference/v1-legacy-project/`, not versioned, outside this repo) for
comparison. This isn't the "final corrected" v1 described in section 4 —
its own `docs/CHANGELOG-CORRECTIONS.md` lists partial fixes, and several
incidents documented in section 4 are still present as-is in this snapshot
(`nmap_tool.py` without `-Pn`, unconditional `sudo`, `cap_severity` still
missing from 3 out of 5 agents). To be treated as a source of ideas, not as
a reference to copy as-is. Six elements were kept and ported into this
repo:

- **Capping transparency note** (`core/state.py::Finding.__post_init__`):
  when `cap_severity` actually reduces a severity, a visible note is now
  added to the finding's description instead of a silent cap.
- **Context shared between phases** (`MissionState.scratch`): `enum_agent`
  publishes the accessible URLs it discovered, `exploit_agent` consumes
  them directly instead of blindly re-scanning `tool_results`.
- **Streaming updates** (`core/orchestrator.py::run_mission`): switch from
  `graph.ainvoke` to `graph.astream(..., stream_mode="values")` with an
  `on_progress` callback, so the dashboard receives an update after each
  phase rather than only once at the end.
- **DNS enumeration during reconnaissance** (`agents/recon_agent.py`):
  `dnspython` was already a declared dependency (CLAUDE.md section 8) but
  never used; added a reverse DNS lookup (PTR) on an IP, or A/MX/NS on a
  hostname, always as a `Lead`, never a `Finding`. A pitfall hit
  immediately while testing this: `dns.resolver.Resolver().resolve()` is
  synchronous/blocking; a first direct call from the agent's coroutine
  froze the entire asyncio loop (so the API and dashboard, not just the
  mission) until the DNS timeout expired. Fixed with `asyncio.to_thread`.
  See CLAUDE.md, section 2.
- **Mission cancellation** (`api/routes/missions.py`): switch from
  `BackgroundTasks` to `asyncio.create_task` with a `_running_tasks`
  registry, added `POST /{id}/abort` and `DELETE /{id}` (409 if still
  running). This is directly the gap felt during this session: without a
  handle on the task, the only way to stop a running mission was to kill
  the whole container. Nuance tested under real conditions: cancellation is
  only honored at the next truly asynchronous `await` point, not
  instantly — a blocking call already in progress (e.g. `dns.resolver`
  inside an `asyncio.to_thread`) continues until its own timeout before
  the cancellation is delivered to the coroutine. `tools/base.py::_run`
  now catches `CancelledError` to explicitly kill the running external
  subprocess (nmap, gobuster, ...) rather than leave it orphaned; this is
  the most frequent path during a real mission and it reacts promptly.
- **Optional perimeter guardrail**
  (`core/state.py::is_target_in_allowed_ranges`, `ALLOWED_TARGET_RANGES`):
  disabled by default (the MVP must work against any external target, so
  no implicit restriction to private ranges), can be enabled to lock one's
  own missions to a known lab.

Dropped from this v1 with no replacement: `evasion_level` (out of MVP
scope, see `PROJECT.md`) and speculative config (`hydra_path`,
`masscan_path`, etc., with no corresponding tool).

LLM-driven phase routing had initially been dropped without being offered
as a choice to the user — corrected after they pointed out that dynamic
adaptation to findings was part of the original goal. Adopted in a form
cheaper than v1's: instead of a dedicated LLM call before every transition
(the most likely explanation behind the "~95% of time on inference" from
section 5), each agent (recon/enum/exploit) simply adds a
`next_phase_suggestion` field to the JSON of its already-existing
end-of-phase summary - no extra inference call. `core/orchestrator.py::_route`
reads `MissionState.last_decision` (a schema field never used until now) in
priority over the default linear order, but `enforce_progression` remains
the sole final judge, exactly as before. A suggestion can skip an
intermediate phase (e.g. recon → exploit directly); if nothing routes
around it afterward, the safety net comes back to it on its own as soon as
that phase becomes "the first uncompleted one" - explicitly tested
(`tests/test_orchestrator.py`).

The dashboard was then entirely rebuilt (`templates/dashboard.html`) with
v1's dark "command center" aesthetic (Orbitron/Share Tech Mono fonts,
three-column layout, per-phase progress track, per-severity stat cards,
findings/leads/attack-chain/info tabs, live activity feed) without
touching the orchestrator, the agents, or the deterministic core — the only
backend change is additive (`_mission_summary` returns extra keys:
`attack_chain`, `operator`, richer findings/leads/target detail), so no
existing test could break. Deliberate simplifications compared to v1: no
`evasion_level` slider (no corresponding field, out of MVP scope), a single
mission-creation form instead of v1's duplicate quick-form + modal, and a
client-side synthesized activity feed by comparing successive API
responses rather than v1's granular WebSocket event types (separate
finding/step/log).

## 8. Unreachable DVWA target: loopback-only port binding (2026-09-18)

A mission targeting the host machine's LAN IP only found the framework's
own port (8000), never DVWA on 8080, even though DVWA was indeed running in
a container on the same machine. Cause: DVWA's compose file (supplied by
the user, outside this repo) published the port with
`"127.0.0.1:8080:80"`. This prefix restricts publishing to the **host
machine's** loopback interface; traffic coming from another container (the
`framework`) and arriving on the host's real LAN IP is never forwarded to a
socket bound only to `127.0.0.1`. This isn't a framework bug — `nmap`
correctly sees this port as closed from that vantage point, which is the
truth for that specific network path. Two possible fixes were communicated
to the user without imposing one: remove the `127.0.0.1:` prefix (simple,
but exposes DVWA to the whole LAN) or connect the `framework` container to
DVWA's Docker network and target it by service name (keeps DVWA
loopback-only, needs no port in the target field since `recon_agent`'s full
scan finds the real internal port). Kept for memory: when setting up a
containerized test target, always check the published port's interface
binding, not just that it's published.

## 9. Comparison with a v0 snapshot and adoptions (2026-09-18)

`reference/v0-legacy-project/` (not versioned, outside this repo) is a
snapshot even earlier than v1 — before Docker was even introduced. Larger
than v1 (~8000 lines) and accompanied by 21 pairs of real reports
(html+pdf), a sample far richer than v1's two PDFs. Four elements kept,
none overlapping with what had already been adopted from v1:

- **Findings/leads deduplication**
  (`core/state.py::MissionState.add_finding`/`add_lead`): a normalized key
  (title, affected component, severity) for findings, (title, source) for
  leads. The same tool can re-report the same thing twice in a mission;
  neither v1 nor this repo protected against that before this — v0's own
  test suite (`TestFindingDeduplication`, `TestDedupTrailingSlash`) shows
  they actually ran into it in practice.
- **Robust JSON extraction** (`agents/base_agent.py::_extract_json`):
  markdown fences stripped, `json.loads(..., strict=False)` (tolerates
  literal control characters, a frequent failure cause on a small model),
  brace-counting isolation if stray text follows the JSON, trailing-comma
  cleanup as a last resort. Replaces a simple regex + a single `json.loads`
  attempt. Directly strengthens the reliability of the leads, summaries,
  and `next_phase_suggestion` already built this session, which used to
  silently degrade to `{}` on a parsing failure.
- **Explicit `recursion_limit`** passed to `graph.astream()`
  (`core/orchestrator.py::run_mission`), on top of the already-existing
  `orchestration_cycles` counter — avoids implicitly relying on
  LangGraph's undocumented default limit.
- **`GET /health`** (`main.py`): checks Ollama connectivity and exposes it
  to the dashboard, whose status light until then only reflected the
  WebSocket connection — no visible signal existed when Ollama is
  unreachable, even though every `ask_llm` silently degrades to `{}` in
  that case.

Two findings noted but not ported: v0 lets the LLM draft the findings'
content directly (title, description, severity), which forced it to build
an elaborate "ground truth" cross-checking machinery in `enum_agent` to
catch cases where the LLM's text didn't match the tools' actual status
codes — v2 avoids this entire class of bug by construction, since no agent
ever lets the LLM write a finding's content. And a sampled real report
shows an LLM-drafted executive summary announcing "three critical
vulnerabilities" while the structured data contained no CRITICAL at all —
the deterministic badge and table were correct, only the free text
exaggerated; no simple structural fix exists for this specific point, kept
in mind as a known blind spot.

## 10. Real-deployment LLM routing regression, and report enrichment (2026-09-18)

**Phase order broken by a skip suggestion.** A real mission executed
phases in the order recon, exploit, enum, postexploit, report instead of
the expected linear order. Confirmed cause: recon's `next_phase_suggestion`
(section 7 above) proposed "exploit", a skip honored by
`enforce_progression` since only the "already completed" case was blocked,
not a forward skip to a phase never yet run. The safety net did catch
"enum" later (documented and tested behavior at the time), but the damage
was done: `exploit_agent` runs relying on
`state.scratch["enum"]["candidate_urls"]`, absent since enum hadn't run
yet — the agent fell back to its generic fallback (`/?id=1` per HTTP port)
instead of testing the real parameterized paths enumeration would have
discovered, genuinely reducing the number of vectors tested. Fixed:
`enforce_progression` (`core/state.py`) now only honors a direct skip to
"report" (early completion, never problematic since nothing downstream
depends on it); any other skip suggestion is redirected to the real next
phase. The recon/enum/exploit prompts were reworded to stop inviting a
suggestion that would be rejected anyway. Tests updated accordingly
(`test_enforce_progression_rejects_a_forward_skip_suggestion`,
`test_run_mission_rejects_a_forward_skip_suggestion`, plus a dedicated test
confirming that the one remaining allowed skip - to "report" - still
works).

**Report enriched based on v1's style.** The user found the v2 report
(from the first minimal template, section 10 of `CLAUDE.md`) less complete
and less presentable than v1's. A direct read of
`reference/v1-legacy-project/redteam-framework/templates/report.html` and
`report_agent.py` (never done in detail during previous comparisons, which
had only skimmed this file): cover page, executive summary + "key risks",
per-severity stat grid, findings grouped by severity with CVE/tags/
remediation, an enriched leads section, an attack-chain table, a
recommendations section (immediate actions + per-finding recommendation), a
technical metadata table. Ported into `templates/report.html` and
`agents/report_agent.py` while fully preserving the deterministic
architecture: `overall_risk` and the per-severity grouping remain computed
in code, never asked of the LLM; only `executive_summary`, `key_risks` and
`immediate_actions` come from a single LLM call (same guarantees as the
previous report), with a deterministic fallback if the LLM replies with
nothing usable (`ReportAgent._fallback_executive_summary`/
`_fallback_immediate_actions`, the latter derived directly from
`Finding.remediation` ordered by severity). A gap discovered along the way:
no agent had ever populated `Finding.remediation` before this, the field
existed but always stayed empty — a "recommendations per finding" section
would therefore have been empty no matter how rich the template. Fixed by
adding a generic, deterministic remediation text (never drafted by the
LLM) at every finding-creation site: nmap-vuln script, consolidated denied
paths, accessible paths, Nikto findings, confirmed SQL injection.

## 11. Blind exploit against an authenticated target (DVWA), and adding a session cookie (2026-09-18)

Even after the two previous fixes, a real report against DVWA
(192.168.1.33:8000 and :8080) produced no exploitation finding at all
despite 2 sqlmap runs (one per HTTP port). Diagnosed from the number of
tools executed (11 = 3 nmap + 3x2 enum + 2 sqlmap, consistent with a
generic per-port fallback rather than a truly discovered URL):
`exploit_agent._candidate_urls()` only keeps `enum` paths containing a `?`
(query parameter), but `gobuster`/`ffuf` with a standard wordlist
(`common.txt`) never produce parameterized paths - only path segments
(`/login.php`, `/admin`). The filter is therefore systematically empty in
practice, and exploit always falls back to its generic `/?id=1` guess on
the root. Even when finding a real page, DVWA requires form-based
authentication plus a `security=low` cookie before its vulnerable pages
(`/vulnerabilities/sqli/?id=...`) respond - no generic wordlist will
discover them, and the framework so far had no way to authenticate.

Fixed by adding an optional `session_cookie` (`Target.session_cookie`,
`MissionCreateRequest.session_cookie`): the operator logs in once via a
browser (and sets DVWA's security level to "low"), pastes the obtained
cookie into the mission form, and that cookie is passed as-is to
`gobuster -c`, `ffuf -b`, `nikto -Header "Cookie: ..."` and
`sqlmap --cookie` - each tool's native flag, with no login automation or
CSRF token extraction on the framework's side. Deliberately simpler choice
than generically automating the login form: every application handles its
login flow differently (CSRF tokens, multi-step, MFA), whereas a session
cookie is the standard way a pentester already runs an authenticated scan
manually. The cookie is never exposed in the clear in an API response or a
report - only a boolean `authenticated`/"Session authenticated" indicator
is shown. This only solves part of the problem: see the discussion on
additional tools/vectors to consider (HTML crawler, `nuclei`, XSS/RCE/
upload vectors) for full DVWA coverage.

## 12. PDF generation failure: WeasyPrint/pydyf incompatibility (2026-09-18)

A real report failed to generate its PDF (HTML fallback) with `'super'
object has no attribute 'transform'`. Confirmed by research: a known
incident ([Kozea/WeasyPrint#2620](https://github.com/Kozea/WeasyPrint/issues/2620))
- `weasyprint==62.3` (initially pinned) sets no upper bound on its `pydyf`
dependency, so `pip install` picks up a recent `pydyf` version (>= 0.11.0)
whose API changed (`Stream.transform` renamed/removed), incompatible with
WeasyPrint 62.x's code which still calls it via
`super().transform(...)`. Fixed the right way (fix forward, don't pin an
old dependency indefinitely): `requirements.txt` moves to
`weasyprint==70.0`, a version where the bug is resolved on WeasyPrint's own
side, on top of including a recent security fix (CVE-2026-55073). Not fully
verifiable on the Windows development machine used for this session: it
never had the native Pango/GObject libraries installed at all (a different
failure, already documented elsewhere), so only a clean install of
`weasyprint==70.0` + `pydyf==0.12.1` with no dependency conflict could be
confirmed here - real PDF generation needs to be revalidated inside the
container (which does have the native libraries via the Dockerfile).

## 13. HTML crawler: finding real pages with parameters (2026-09-18)

Following the addition of the session cookie (section 11), the remaining
blocker to reaching DVWA's vulnerable pages: `gobuster`/`ffuf` with a
standard wordlist only guess path segments (`/login.php`, `/admin`), never
the parameters a page actually expects (`/vulnerabilities/sqli/?id=1`).
Added `tools/crawler_tool.py`: an async HTTP client (httpx, already a
dependency) that follows same-host `<a href>` links and synthesizes a
testable URL from the fields of every `<form>` encountered - a GET form
becomes a URL with parameters (reuses the existing `candidate_urls`
pipeline), a POST form is kept separately
(`state.scratch["enum"]["post_forms"]`) since `sqlmap` tests it via
`--data`, never via a plain URL. Doesn't inherit from `BaseTool`: it isn't
an external subprocess, the `build_command`/`_run` machinery around a CLI
binary doesn't apply. `agents/exploit_agent.py` was factored
(`_test_sqlmap`) to test both candidate types (URLs and POST forms) without
duplicating the finding-creation logic. New dependency: `beautifulsoup4`
(pure `html.parser` backend, no `lxml`/C extension, consistent with the
project's avoidance of heavy dependencies).

## 14. `nuclei`, and a bug discovered in the capping transparency note (2026-09-18)

Added `tools/nuclei_tool.py`: broad coverage of known patterns (default
credentials, exposed panels, security headers, common CVEs) via community
templates, each match carrying its own evidence (a reproduction curl
command). Release asset naming verified via the GitHub API before writing
(`nuclei_<version>_linux_<arch>.zip` - a `.zip`, unlike gobuster/ffuf's
`.tar.gz`, hence adding `unzip` to the Dockerfile) and CLI flags confirmed
via the official documentation (`-jsonl` for output, `-H` for a custom
header - nuclei has no dedicated cookie flag, unlike gobuster/ffuf/sqlmap).
Wired into `enum_agent.py`, one `Finding` per match (no
`consolidate_denied_paths`-style consolidation: different templates are
distinct issues, not repeated noise).

**A real bug discovered while testing the integration.** A nuclei
"critical" match was correctly capped to MEDIUM (`cap_severity` worked),
but the transparency note added in section 7 (v1) never showed up. Cause:
each agent called `cap_severity(...)` itself *before* constructing the
`Finding`, so `Finding.__post_init__` already received a pre-capped
severity - `requested_severity == self.severity` internally, so nothing to
report, even when a real cap had indeed just happened one step earlier. The
note could therefore never trigger under normal operation, only in the
defense-in-depth case where an agent would forget the explicit call
(exactly incident #10 - the case we hope never happens). Fixed by removing
the explicit `cap_severity(...)` call from every `Finding`-construction
site (`recon_agent.py`, `enum_agent.py`, `exploit_agent.py`): agents now
pass the "intended" severity as-is, and `Finding.__post_init__` remains the
sole enforcement point, structurally impossible to bypass. CLAUDE.md,
sections 2 and 10, updated to reflect that capping is no longer a
discipline expected of each agent but a single structural guarantee - a
strengthening, not a loosening.

## 15. `dalfox` (XSS) and `commix` (command injection) (2026-09-18)

Last piece of the plan to expand exploitation vectors beyond SQL injection
alone. Both tools' naming/CLI flags were verified before writing, not
assumed:

- **`dalfox`**: `scan` subcommand, `-f jsonl` for JSON Lines output,
  `--headers "Cookie: ..."` (no dedicated cookie flag, like nuclei). dalfox
  only prints a JSON entry for an actually confirmed vulnerability (unlike
  sqlmap/commix, which print a diagnostic regardless of the result): "at
  least one entry parsed" is therefore a reliable positive signal here,
  with no need for an explicit positive keyword. Release asset naming
  verified via the GitHub API: `dalfox-vX.Y.Z-linux-x86_64.tar.gz` (the
  tag's "v" is kept in the filename, unlike `ffuf`) and `aarch64` rather
  than `arm64` for the ARM variant - a fourth naming scheme, different from
  the other three Go-binary-based tools in this Dockerfile.
- **`commix`**: architecture and CLI conventions directly inspired by
  sqlmap (same convention authors), confirmed by reading the source code
  (`src/core/parse/cmdline.py` for the `-u`/`--url`, `--batch`, `--cookie`,
  `--data` flags; `src/core/controller/checks.py` for the exact positive
  signal) rather than assumed by analogy. Positive signal: the exact
  phrase `"is vulnerable"` (like sqlmap); the negative case explicitly
  uses `"false positive"`/`"unexploitable"`, never that phrase - the same
  pitfall fixed on sqlmap (section 6) avoided here from the start.

Both are tested in `exploit_agent.py` alongside sqlmap, on the same
candidates (`candidate_urls` and `post_forms` discovered by enum/crawler),
under the same rule with no exception: `exploited=True` only on tool
confirmation, never on the LLM's opinion. `dalfox` isn't applied to POST
forms (no confirmed raw-POST-payload flag for this use case - left out of
scope rather than guessing an unverified flag).

**A real build failure: dalfox's internal archive structure not
verified.** The asset name and per-architecture naming had been confirmed
via the GitHub API, but not the archive's internal structure -
`tar -xzf ... dalfox` failed with `tar: dalfox: Not found in archive`.
Cause: unlike gobuster/ffuf/nuclei, which place their binary at the
archive's root, dalfox nests it in a versioned subfolder
(`dalfox-v3.2.3-linux-x86_64/dalfox`). Fixed with
`tar --strip-components=1` into a dedicated extraction folder rather than a
fixed filename - robust regardless of the exact subfolder name, and
manually verified before shipping the fix (real extraction tested, binary
confirmed as valid ELF x86-64). Lesson generalized in CLAUDE.md, section 2:
verify both the asset name AND the archive's internal structure, not just
one of the two.

Deliberately left out of scope for this round (decision made with the
user): file upload and file inclusion vulnerabilities have no dedicated
tool equivalent to sqlmap/dalfox/commix; file inclusion (LFI/RFI) is
already partially covered by the existing `nuclei` templates, and file
upload requires application-specific logic that doesn't generalize
cleanly.

## 16. False CRITICAL confirmed on dalfox: outdated generic documentation (2026-09-18)

A real mission against DVWA (authenticated via a session cookie, crawler
and nuclei working) produced two fabricated `CRITICAL "XSS confirmed"`
findings, with empty `EVIDENCE` fields (`param= payload=`) - an immediate
sign something was wrong in the parsing, not in dalfox itself.

**Root cause.** The documentation consulted before writing
`tools/dalfox_tool.py` (general web search, not the source code) described
dalfox's old Go CLI. The `hahwul/dalfox` repo has since been fully rewritten
in Rust (confirmed via `gh api repos/hahwul/dalfox --jq .language`): the
JSON `"type"` field there is a four-value enum
(`src/scanning/result/mod.rs`, read directly) - `"V"` (Verified, the only
real exploitable confirmation), `"R"` (Reflected, "not a vulnerability
assertion" per the project's own documentation), `"A"` (DOM XSS detection
via static analysis, a method label) and `"I"` (Informational, e.g. an
outdated library). The initial code treated "any parsed JSON line" as a
confirmation (`vulnerable = bool(findings)`), never checking this field -
exactly the same bug class as the sqlmap false positive (section 6), but
this time caused by outdated external documentation rather than a logic
shortcut.

**Fixed** by strictly filtering on `type == "V"` for a confirmed `Finding`
(`exploited=True`), and promoting `type == "R"` (reflected, unconfirmed) to
a `Lead` - a lead to verify manually, never a scored finding, on the same
model as the low-confidence OS guess in `recon_agent.py`. `"A"` and `"I"`
are ignored (neither proof nor an actionable lead for this project). The
cookie flag was also fixed along the way: `--cookies` (documented in the
repo's current CLI reference), not `--headers "Cookie: ..."` which
belonged to the old CLI.

**Lesson generalized.** External documentation (web, README, generic help)
can describe an outdated version of a tool that has since changed
implementation language - always check
`gh api repos/<owner>/<repo> --jq '.language'` and read the real source
code of the field that determines a positive/negative signal before
writing a parser, not just its CLI flags. See CLAUDE.md, section 2.

## 17. Three anomalies from the same authenticated mission: incomplete feed, empty attack chain, false nikto finding (2026-09-18)

A subsequent mission against the same target (DVWA, session cookie)
surfaced three distinct symptoms in a single iteration.

**1. Missing `[EXPLOIT] Phase terminee` line in the live feed.**
`templates/dashboard.html::_diffAndLog` only logged the LAST newly
completed phase on every poll
(`(data.completed_phases||[])[cur.completed_phases - 1]`), unlike the
`findings`/`errors` branches in the same code which already looped over
`.slice(prev).forEach(...)`. When `exploit` (nothing to report, so fast)
and `postexploit` completed within the same polling window, only
`postexploit`'s line survived. Fixed by looping over every newly completed
phase, like the other branches.

**2. Empty "exploit" cell in the attack-chain table.** `recon_agent.py`,
`enum_agent.py` and `exploit_agent.py` wrote
`llm_summary.get("summary", "")` with no fallback: when the end-of-phase
LLM summary call returned nothing usable, the cell rendered empty.
`postexploit_agent.py` already had a deterministic fallback for its
"nothing exploited" case; the same principle was applied to the other
three agents (e.g. exploit: "No vulnerability confirmed by tool proof on
the vectors tested (sqlmap, dalfox, commix)." when neither the LLM nor a
real exploit produced text). The symptom already existed in section 16's
report (row 5 "exploit" empty), simply masked by the two fabricated dalfox
findings next to it.

**3. False MEDIUM finding "Nikto Findings" with `requires a value`
evidence.** The most serious root cause of the three: `tools/nikto_tool.py`
passed `-Header "Cookie: ..."` for authentication, but nikto 2.5.0 **has no
`-Header` option** (verified in the real `GetOptions` of
`program/plugins/nikto_core.plugin` in the `sullo/nikto` repo, tag
`2.5.0` - absent from the full list). An invalid CLI option makes
`GetOptions` fail and calls `usage()`, which prints the full help screen
then `exit $is_failure` with `$is_failure` undefined (`shift` on an empty
list) - numified to `0` in Perl, so perceived as a **success** on the
`is_success()` side. The last line of that help screen (`+ requires a
value`, a legend explaining the `+` suffix used throughout the option
list) starts with `"+ "` and therefore passed `parse_output`'s filter,
becoming a fabricated generic nikto "finding" - on every authenticated
mission, on every HTTP port, with no error ever logged anywhere (exit code
0). No real nikto scan had ever taken place against an authenticated
target until this fix.
Fixed by using the actually documented mechanism (`nikto.conf.default`,
the `STATIC-COOKIE` key) via `-Option "STATIC-COOKIE=..."` (the only flag
that lets you override a config key on the command line, splitting only on
the first `=`), with each `name=value` pair quoted and semicolon-separated
for a multi-value cookie. `parse_output` now explicitly filters out
`"+ requires a value"` as a safety net in case a future invalid option
makes nikto fall into `usage()` again.

**Lesson generalized.** A tool that silently fails at its own
argument-parsing level (exit code 0 despite an invalid CLI) is a more
dangerous trap than an outright crash: nothing signals it anywhere in the
mission state. The same verification discipline as for dalfox (section 16)
applies to CLI flags, not just output format: read the tool's real
`GetOptions`/argument parser before assembling a command, never guess a
flag name by analogy with another tool (`-Header` exists in other
scanners, not in nikto).

## 18. Reducing mission time: intra-phase concurrency and performance bounds (2026-09-18)

Real missions against DVWA (nikto now working, section 17) took 71 to 87
minutes each - too long to iterate on. None of these changes alter what a
tool finds, only how long a mission takes to find it.

**Main structural cause: everything ran sequentially even though most
steps are independent.** `enum_agent.py` awaited gobuster, then ffuf, then
nikto, then the crawler, then nuclei, one after another, twice (once per
HTTP port) - 10 chained external subprocesses even though none of the 5
tools on a given port reads another's output. Same finding in
`exploit_agent.py`: sqlmap, dalfox and commix ran sequentially for every
candidate URL, and an authenticated mission with a rich crawl can produce
dozens of candidate URLs. Fixed with `asyncio.gather()`: the 5 tools on a
port now run concurrently in `enum_agent.py`, and the 3 vectors for a URL
concurrently in `exploit_agent.py`, with an `asyncio.Semaphore`
(`EXPLOIT_MAX_CONCURRENT_URLS`, default 5) to never launch an unbounded
burst of subprocesses if `candidate_urls` is long. `asyncio.gather()`
returns its results in the order of the tasks passed, not completion
order - so result processing stays deterministic and the existing tests
didn't need rewriting, only completing (`agent._settings` didn't exist on
agents built via `__new__()` in the tests, needed since `exploit_agent.py`
now reads `self._settings.exploit_max_concurrent_urls`).

**nmap `-p-` stays complete, but faster.** The port scan (`-p- -sV`) is the
only one that sweeps all 65535 ports - necessary for the MVP validation
criterion on a non-standard port (CLAUDE.md, section 11) - and must
therefore never lose scope to save time. `-T4 --min-rate 1000` speed up
that same full scan without reducing its coverage (`docker-compose`/the
real network environment will determine whether this aggressiveness is
appropriate; revisit if a target's IDS/IPS starts dropping packets at this
rate).

**nikto with no worst-case bound.** Nikto never has a default time limit
and can legitimately take several minutes on a verbose site. Its own
`-maxtime` flag (already spotted while reading its `usage()`, section 17)
is now systematically passed (`NIKTO_MAX_TIME`, default `180s`): bounds
the worst case, changes nothing on a normal target that finishes before
that.

**gobuster/ffuf with low internal parallelism.** Both ran with their
conservative defaults (10 and 40 threads) outside any shared-load context.
Bumped to 50/80 threads each, a reasonable choice now that they run
concurrently with each other (and with nikto/crawler/nuclei) rather than
alone.

**LLM call with no generation cap or safety timeout.** Every prompt in
this project explicitly asks for short JSON (a few sentences, a few short
lists), but `ChatOllama` had neither `num_predict` nor a timeout: a
CPU-only local model that rambles past what's needed had no bound, and a
stuck call could have frozen a phase indefinitely. Added `num_predict`
(`LLM_NUM_PREDICT`, default 512) and `client_kwargs={"timeout": ...}`
(`LLM_TIMEOUT_SECONDS`, default 180s, passed to the underlying `ollama`
client, itself based on httpx) in `agents/base_agent.py`.

**Lesson generalized.** Immediate sequentiality ("I write `await` at every
step") is often a default choice, not a necessity: check which steps
actually depend on another's result before chaining them. Here, none did
within a phase - only the order BETWEEN phases (recon before enum before
exploit) is a real dependency, already protected by `enforce_progression`.

## 19. Real mission after the concurrency work: first real confirmed exploits, and one candidate URL tested twice (2026-09-18/19)

First complete mission after section 18: 25m14s (down from 71-87 minutes
before), and above all the first real exploits confirmed by tool proof on
DVWA (3 SQL injections via sqlmap, 2 XSS via dalfox type `V`, five correct
CRITICALs, all correctly deduplicated in the findings). The session
cookie/authenticated crawl finally work together as intended (section 17's
hypothesis confirmed).

**But the attack chain showed two identical dalfox entries** for the same
two exploited XSS URLs (`fi/?page=file3.php` and `xss_r/?name=1`), while
the findings themselves stayed correct (a single CRITICAL each, thanks to
`add_finding`'s deduplication). Cause: `exploit_agent.py::run()` called
`self._candidate_urls(state)` on every iteration of its loop over the
target's HTTP ports, while this method already returns the COMPLETE list
of candidate URLs aggregated by `enum_agent.py` across ALL HTTP ports at
once (each URL already carries its own scheme/host/port). With 2 matching
HTTP ports (8000 and 8080), the entire candidate list was therefore
retested twice - once per port - a bug that predates section 18 (present
in the original sequential code too), simply invisible before because no
real vulnerability had yet been confirmed to make it visible in the attack
chain (which is never deduplicated, unlike findings/leads).

**Fixed** by separating already-absolute candidates (the normal case,
tested exactly once regardless of the number of HTTP ports) from relative
paths coming from the legacy `tool_results` fallback (tested per port for
lack of knowing their origin port, historical behavior unchanged). The gain
isn't just cosmetic: every duplicate was a real extra request sent to the
target, not just an extra report line.

**Lesson generalized.** A function that already aggregates over the entire
relevant scope (here: all HTTP ports) must never be called again from
inside a loop that iterates over that same scope - the sign that a
duplicate exists can stay invisible as long as no downstream
deduplication path (here, `add_finding`) silently neutralizes it; always
check the non-deduplicated log (`attack_chain`) rather than relying only on
lists that already filter duplicates out.

## 20. Security audit of the framework itself (2026-09-19)

Once the offensive cycle was proven correct over several real missions
(sections 17 to 19), an audit explicitly deferred since the start of this
reconstruction (see session memory): does the framework expose anything it
shouldn't, is it vulnerable itself?

**The most consequential: no authentication on the API/dashboard, exposed
on every network interface.** `docker-compose.yml` publishes
`"8000:8000"`, which binds to `0.0.0.0` on the host side by default -
reachable from any device on the same network as the operator's machine,
not just `localhost`. No FastAPI route required anything before this fix.
`REQUIRE_AUTHORIZATION` only checks for the presence of a non-empty string
in `authorization_ref` - a note for traceability, never a technical
control. Combined, this meant that anyone reaching port 8000 could launch
a real mission (scan + exploitation) against any target of their choosing,
bounded only by `ALLOWED_TARGET_RANGES` (empty by default = no
restriction). Fixed with an optional shared key (`API_KEY`, empty by
default so it doesn't break an existing deployment on the first pull)
checked by a FastAPI dependency applied to every `/api/*` router
(`api/dependencies.py::require_api_key`), accepted via the `X-API-Key`
header (the dashboard's fetch calls) or the `?api_key=` parameter (a
fallback for the report's direct `<a href>` download link, which can't set
a custom header). `/health` and the dashboard HTML itself stay open (no
sensitive data). A warning is logged at startup if `API_KEY` stays empty.

**Session cookie: no confirmed leak, but no structural guarantee either.**
The API (`_mission_summary()`) and the report already only ever exposed
`authenticated: bool(...)`, never the raw cookie - correct from the
design stage. The `Cookie: ***` visible in the PDF's nuclei evidence
actually comes from nuclei's own built-in redaction (verified in its
source code, `pkg/output/output.go`), not a mechanism of this project.
`sqlmap`/`dalfox`/`commix`/`nikto` have no equivalent guarantee on their
raw output: nothing structurally prevented a verbose mode or an error
message from one of these tools from echoing the sent cookie into text
that ends up in `Finding.evidence`/`description` or `Lead.rationale`.
Fixed in defense in depth: `MissionState.add_finding`/`add_lead` now strip
any literal occurrence of the session cookie from those fields before
storage, at the same single structural point as deduplication (same
pattern as `cap_severity`/`Finding.__post_init__`, section 2).

**Deliberately deferred, to document in the README for a later pickup
rather than handled here:**
- The container runs as root (no `USER` directive in the Dockerfile) -
  partially justified (SYN scanning requires raw sockets), but
  `NMAP_SCAN_MODE=connect` already exists for operating without elevated
  privileges if switching to a non-root user is desired.
- No dependency vulnerability audit (`requirements.txt`) was performed -
  would require network access from the audit environment to do properly
  (e.g. `pip-audit`).
- The `/ws/missions` websocket remains unauthenticated (it only broadcasts
  `mission_id`/`status`/`current_agent`, no sensitive content; browsers
  don't set a custom header on a WebSocket connection, a query-param-side
  protection would be needed if this is ever hardened).

**Lesson generalized.** A security tool that tests external targets must
hold itself to the same standard on its own exposure surface as what it
audits in others - the complete absence of authentication on the control
plane is exactly the kind of "MEDIUM: missing headers" finding this
framework would report on a target itself, except here the consequence
(launching real attacks on behalf of an unauthorized third party) is far
more serious than an information leak.
