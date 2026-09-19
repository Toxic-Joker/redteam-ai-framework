# RedTeam AI Framework: project document

Stable document, not to be modified across development sessions. It defines
the "why" and the "for whom" of the project. The technical "how"
(architecture, pitfalls to avoid, model choice, build order) lives in
`CLAUDE.md`. The full history of the first version lives in
`docs/HISTORY.md`.

## Mission

Provide a multi-agent Red Team orchestration framework that automates the
repetitive phases of a penetration test (reconnaissance, enumeration,
exploitation, post-exploitation, reporting), relying on a local language
model for synthesis and contextual reasoning, without ever letting that
model decide alone on the critical elements of the deliverable (severity,
overall risk, report structure).

## Guiding principle (non-negotiable)

The language model is **consultative**. It proposes, summarizes, drafts,
and suggests leads. Every consequential decision (a finding's severity, the
overall risk calculation, the report structure) is **deterministic**,
hard-coded, grounded in the evidence produced by the tools (HTTP status
codes, real output from nmap/gobuster/nikto/sqlmap). A security report is
never governed by an LLM's opinion.

This principle doesn't depend on the quality of the chosen model. Even with
a reliable model, separating decision authority remains the rule: it serves
the deliverable's auditability and governance, not just compensation for a
weak model.

## Who this project is for

- **Pentesters / Red Team**: time savings on repetitive phases (recon,
  enumeration, reporting), to focus on high-value exploitation.
- **SOC / Blue Team**: a reproducible, replayable exposure baseline,
  comparable over time, with few false positives thanks to the separation
  between confirmed findings and speculative leads.
- **Governance, Risk and Compliance (GRC)**: a deterministic risk score and
  an auditable report, defensible during an audit.
- **Hardening / lessons-learned**: a consolidated deliverable that feeds
  directly into remediation cycles.

## MVP scope (v1)

- Fully automated cycle: reconnaissance, enumeration, cautious exploitation
  (proof required before any high severity), post-exploitation, PDF report
  generation.
- Web interface: enter the target and authorization reference, follow the
  mission in real time, download the report.
- Works against any external target (not just on a local network),
  including when ICMP discovery is blocked.
- Strict separation between confirmed findings (affect the risk score) and
  speculative leads (never affect the risk score).
- One-command deployment (`docker compose up`) on a fresh machine, with no
  manual intervention.

## Out of scope for the MVP (explicit non-goals)

- Measured evasion against real EDR/XDR solutions. Evasion levels remain a
  configurable parameter, not validated.
- Proven generality across multiple targets/OSes. Reproducibility (same
  result on the same target) is an MVP goal; generality (behavior across
  heterogeneous targets) is not.
- Complete legal guardrails beyond the mandatory authorization reference and
  logging.
- Quantified measurement of time saved compared to a manual audit. Secondary
  goal once the MVP is stable: compare mission time before/after a model
  change.

## Non-negotiable constraints

- Docker-first from the first commit, not added afterward.
- No vulnerable target bundled in `docker-compose.yml`. The target is always
  external.
- Language model run locally (confidentiality constraint, non-negotiable).
- Total size budget (images + model weights): real target 8 to 10 GB, safety
  ceiling of 25 GB never to be exceeded.

## Definition of success

See the "MVP validation criteria" section of `CLAUDE.md` for the full
technical list. In summary: a mission always completes, a finding without
proof of exploitation never exceeds MEDIUM, the overall risk is reproducible
from one run to another on the same target, and `git clone` followed by
`docker compose up --build` works with no manual intervention on a fresh
machine.

## Related documents

- `CLAUDE.md`: technical blueprint (architecture, Docker/network pitfalls to
  avoid, model choice, directory layout, build order). Read automatically by
  Claude Code at every work session on this repo.
- `docs/HISTORY.md`: full retrospective of the project's first version
  (EFREI Master's thesis, defended): what was tried, what broke, what was
  fixed.
