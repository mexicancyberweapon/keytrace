# KeyTrace handoff

Updated October 11, 2026. Keep this file focused on current state and next steps;
historical results belong in [PROJECT.md](docs/PROJECT.md).

## Goal and working preferences

CSE 467 research prototype: determine whether source context and static flow improve
secret detection and intended-use classification with an LLM. Preserve all four
proposal RQs. The user wants a small, understandable repo and a current handoff.
Update this file after substantive work, recording only verified results.
`AGENTS.md` records this ongoing maintenance requirement for future tasks.

The user declined scheduled handoff checks; the hourly automation was deleted.
Update this file during substantive project work only, as required by AGENTS.md.
Do not recreate a recurring check unless the user asks for one.

## Where things belong

| Location | Purpose |
|---|---|
| `main.py`, `scanner.py`, `detection.py` | CLI, bounded AST flow analysis, literal assessments |
| `classification.py` | Redacted requests and prediction validation |
| `evaluation/` | Scoring, model protocol, baseline normalization, CredData import, artifact capture |
| `tests/` | 62 regression tests |
| `datasets/synthetic/` | 20 invented development cases |
| `datasets/creddata/` | Ignored local pilot, source, metadata, licenses, provenance |
| `docs/INTERMEDIATE_REPORT.md` | Report draft with methods/results for each RQ |
| `docs/PROJECT.md` | Research background, historical and current results |
| `docs/EXPERIMENTS.md` | Data contracts and experimental procedures |
| `docs/ARTIFACTS.md` | Separate submission inventory and reproduction instructions |
| `output/intermediate/` | Ignored report evidence: four results, summary, test log, metadata |

The offline pipeline needs only Python's standard library (validated on 3.13.5;
README specifies 3.10+). No environment installation is needed to scan prepared data.

## Verified implementation and results

Input Python is parsed, never executed. Supported analysis includes assignment and
reassignment, same-module parameters/returns, selected containers/string operations,
import aliases, approximate branches/loops, named attributes, recognized unittest
setup/helpers, and selected HTTP/OAuth, SSH, database, and HMAC sinks. Test entry
points are opt-in; ordinary uncalled functions are not assumed to execute.

Candidate discovery covers credential names, defaults/comparisons, selected positional
arguments, private-key blocks, selected token formats, and credential-bearing URLs.
Neutral literals can become candidates when they reach supported sensitive arguments.
Evidence assessments distinguish positive, explicit placeholder/example negatives,
and null decisions needing review. Values and exported string literals are redacted.
Confidence is heuristic, not calibrated. No live credential checks occur.

Current development results, `--entry-points tests`:

| Data / decision policy | TP | FP | TN | FN |
|---|---:|---:|---:|---:|
| Synthetic / flow | 10 | 2 | 7 | 1 |
| Synthetic / evidence | 11 | 1 | 8 | 0 |
| CredData / flow | 9 | 8 | 278 | 128 |
| CredData / evidence | 102 | 47 | 239 | 35 |

CredData evidence precision 68.5%, recall 74.5%, F1 71.3%; candidate recall 102/137.
Synthetic candidate recall 11/11 and evidence purpose accuracy 17/20. CredData purpose
is unannotated and excluded from purpose scoring. Evidence abstains on 13 CredData
and one synthetic case; current metrics count these as negative decisions.
Default evaluation policy remains `flow`; CLI scans show both assessments and flows.
These are development results, not held-out evidence or proof of LLM benefit.

No actual LLM, Gitleaks, or TruffleHog experiment has run in this workspace. Existing
model tests use mocks. The local Ollama/provider adapter is unimplemented. Ollama
with Qwen3 8B was discussed, not installed/validated; prior hardware inspection
showed about 32 GB RAM and i7-1185G7, with GPU acceleration unestablished.

## Data and limitations

CredData revision `0b1940e171725ad8937311120b191602608a4801`; pilot repositories are
docker-py (`69d49010`), requests-oauthlib (`c9b945fa`), and paramiko (`533c47c6`).
423 labels (137 positive/286 negative) in 60 files; original 459 labels excluded 30
ambiguous same-line candidates and 6 multiline candidates. Preserve T-positive,
F/X-negative labels and `purpose_labeled:false`. Never change labels/exclusions to
improve scores. Imported cases match by file/line, not general spans.

Retain source, metadata, import-summary hashes, licenses and provenance. Dataset use
is authorized; transmitting raw data to hosted models is not. Do not dump candidate
values in tool output. SecretBench permission was user-reported, but no SecretBench
data was downloaded. Rebuild notes, including the upstream Python compatibility
patch, are in EXPERIMENTS.md; one-time downloader machinery was already removed.

Limits include general object/dynamic/cross-file resolution, mutation aliases,
exception paths, comprehensions, variadic binding, fixed-point analysis, imported
fixtures, pytest, and lifecycle effects. Documentation/configuration spans and
neutral unused literals can be missed. An absent flow is not proof of safety.
Higher evidence recall comes with more false alarms than the flow-only policy.

## Intermediate report and next steps

The instructor requires evidence of at least 30% completed work, complete methods
for every RQ, results so far per RQ, deviations, a remaining schedule, and separate
code/data/log artifacts. The draft includes every section without inventing a
completion percentage or model results. Owners are proposed from the original
proposal; team contributions and any independent baseline runs need confirmation.
Reported deadlines: October 14 intermediate and November 30 final; confirm with course.

1. Review the draft with teammates, confirm owners/contributions and submission
   format, and deliver the ignored dataset/log artifacts through the course channel.
2. Before LLM experiments, fix the prompt's blanket test/example rejection rule to
   respect CredData labels, and match warning information between context/hybrid
   conditions for a controlled flow ablation. These are pending protocol fixes.
3. Implement the local adapter, pilot a small development sample, and freeze model,
   settings, prompts, hardware/runtime records, and failure handling.
4. Run pinned baselines on the same snapshot; review unmatched findings.
5. Prepare repository-disjoint held-out data and independent purpose/flow annotations;
   execute frozen experiments and write measured findings. Do not tune on held-out data.

## Reproduce and maintain

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m evaluation.capture
```

Capture refreshes the four evaluation reports, source hashes, metadata, and test log
in `output/intermediate/`. Preserve a dated copy before replacing submitted evidence.
Git alone omits that folder and CredData. The regeneration code is now versionable
in `evaluation/capture.py`; inventory instructions are in `docs/ARTIFACTS.md`.

October 11 cleanup removed stale bytecode and consolidated this handoff's repeated
historical sections. Moved the reusable capture script and artifact instructions
out of ignored output; updated references. Core application code and datasets were
preserved. Historical results remain in PROJECT.md.

No commits have been created during this work. Existing modified and untracked files
include the implementation/docs/tests, and earlier sample deletions were authorized.
User changes to `.gitignore` predate this work; preserve them. Do not reset the tree,
remove the ignored submission evidence, or recreate old downloader/duplicate folders.
