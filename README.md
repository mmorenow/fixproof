# FixProof

**Decide vulnerability report triage by execution, not by similarity.**

FixProof turns every security finding that has a proof of concept into a replayable test. To check whether a new report is the same bug as an earlier one, it runs the new PoC on the version of the app *without* the earlier fix and on the version *with* it:

- Works without the fix, fails with it → **duplicate** (same fix).
- Still works with the fix → **new bug or bypass**.
- Fails on both → **not reproduced**, sent to a human.

The same engine tells you whether a report is real today, whether it's already fixed (and in which version), and whether an old bug has come back.

> The LLM proposes, execution decides.

## Who it's for

Teams that receive security findings without big-platform tooling: open-source maintainers, small PSIRTs, internal AppSec teams, and pentesters running retests. It's self-hosted and vendor-agnostic, and works with your own model keys or a local model.

## Status

Design phase. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full pipeline, tech stack and roadmap.

## Repo layout

```
README.md               this file
docs/ARCHITECTURE.md    how it works, components, phases, demo
docs/research/          background research (industry, academic, data, practitioner pain)
```
