# KeyTrace: Intermediate Report

**CSE 467 — Data & Information Security**  
**Team:** Liam Nolan, Rogelio Corrales, Vansh Sinha, Colin Murnane, Cooper Lake  
**Draft date:** October 11, 2026

## 1. Objective and progress

KeyTrace investigates whether source-code context and static program-flow evidence
can improve secret detection and inference of a credential's intended use. The
prototype parses Python without executing it, extracts candidate literals, traces
supported source-to-use paths, and produces redacted findings. A planned LLM stage
will classify candidates using source context with and without flow information.

Completed work includes a working static analyzer, two static decision policies,
20 synthetic development cases, a 423-case obfuscated CredData Python pilot, an
evaluation pipeline, model request/response interfaces, baseline-output importers,
and 62 passing regression tests. The project has progressed beyond design to an
implemented and evaluated subsystem. Based on these completed deliverables, the
project has completed **at least 30% of the planned work**. This is a milestone
assessment supported by working code, development-data results, and automated
tests—not a claim that 30% of the research hypothesis has been proven. Actual LLM
inference, external scanner runs, and held-out experiments remain outstanding.

The current pipeline is:

**Python source → candidate extraction → bounded static analysis → static
assessment or planned LLM classification → evaluation against labels.**

Evidence for the intermediate milestone is summarized below.

| Work area | Completed evidence |
|---|---|
| Core implementation | Python candidate extraction, bounded source-to-use tracing, redacted reporting, and two static decision policies |
| Data and evaluation | Synthetic development manifest, prepared CredData pilot, scoring pipeline, model request/response contract, and baseline-output normalization |
| Validation | 62 passing regression tests and recorded preliminary synthetic and CredData metrics |
| Work still pending | Local-model execution, real Gitleaks/TruffleHog runs, independent held-out evaluation, error analysis, and final reporting |

The two implemented static policies are: (1) **flow**, which predicts a secret when
a candidate reaches a supported sensitive argument; and (2) **evidence**, which
assesses credential-like literal contents and names independently of reachability,
suppresses explicit placeholders/examples, and abstains on ambiguous metadata or
resource references. A sensitive use is not proof that a credential is live.

The rest of this report maps directly to the requested deliverable: Section 2
defines the shared experimental design; Sections 3–6 give a complete method and
results so far for every research question; Section 7 records deviations from the
initial plan; Section 8 schedules the remaining work; and Appendix B inventories
the separately delivered codebase, datasets, and logs.

## 2. Shared experimental design

### Data and experimental units

The current development data contains 20 synthetic cases (11 positives, 9 negatives)
and 423 CredData cases (137 positives, 286 negatives) in 60 Python files from
three repositories: docker-py, requests-oauthlib, and paramiko. The pilot preserves
CredData labels: T maps to positive; F and X map to negative. Of 459 original Python
labels, 30 were excluded for multiple candidates on a line and six for multiline
candidates. Exclusions were established during import, not according to detection
success. Synthetic positive values are invented and invalid; they simulate roles.

A case is a labeled source-file/line location. Multiple extracted candidates at
that location are aggregated to a single prediction. This is line-level evaluation,
not a general span-level benchmark. Unmatched external-tool findings will be listed
for review, not automatically counted as false positives. Detection rates apply
to labeled candidates, not every line of code in the repositories.

For final evaluation, we plan a separate, repository-disjoint CredData Python set,
targeting at least three additional repositories and 200 eligible cases, including
at least 50 positives and 50 negatives if available. Selection will use language,
label availability, and repository identity, never scanner success. Record any
shortfall rather than adjusting the selection after inspecting results. Deduplicate
source hashes and near-identical fixtures across splits. Freeze the manifests,
exclusions, implementation, prompts, and configurations before inspecting held-out
predictions. Current pilot cases will remain development-only.

### Analysis conditions and controls

All tools will scan the same filesystem snapshot without online credential
verification. KeyTrace's primary condition uses explicit `tests` entry points:
recognized unittest methods and setup are modeled statically. Module-only mode
will be a separate sensitivity analysis. Unsupported imports, cross-file calls,
dynamic behavior, and incomplete object analysis can prevent flow recovery.

The planned model will run locally through an Ollama adapter. Select the exact
model artifact using development-only feasibility tests, then record its digest,
quantization, prompt version, context limit, generation settings, and hardware.
Use temperature zero where supported and three repeated context/hybrid runs to
measure residual variability. Model selection and adapter implementation are pending.

Context and hybrid conditions will use identical extracted candidates, source
context, model settings, and output schema. Hybrid adds flow traces. For a strict
flow ablation, analysis warnings must be matched between the two conditions; the
current exporter adds warnings only in hybrid mode, so this control must be
implemented before final experiments. Do not interpret the current exporter as a
completed controlled ablation.

The exporter masks string/bytes contents and removes comments; identifiers and paths
remain visible. Context includes overlapping top-level statements, capped at 12,000
characters, rather than a minimal program slice. Use the same redaction and context
budget in both conditions and record truncation. This experiment evaluates reasoning
from redacted context, not a model's ability to validate original token contents.
Case identifiers and ground-truth labels must not be included in model messages.

### Scoring and annotation

Report TP, FP, TN, FN, precision = TP/(TP+FP), recall = TP/(TP+FN), F1,
FPR = FP/(FP+TN), and FNR = FN/(FN+TP). Undefined ratios remain undefined.
Report candidate-generation recall separately: an LLM cannot recover an omitted
candidate. Full-set scores include extraction misses; conditional scores cover
only discovered candidates. Missing predictions and explicit abstentions count as
negative in the current binary scoring convention, with their counts reported
separately. Invalid model output fails the run and is logged; it is not silently
converted into a successful negative prediction.

CredData's detection labels can include credentials in tests. Preserve those labels
rather than automatically declaring all test code negative. The present model prompt
instructs the model to reject test/example values; revise that rule before CredData
experiments to distinguish explicit dummy values from credentials merely located
in tests. This protocol correction is pending, and no model results are claimed.

Intended-use annotation will use `authentication`, `api_token`, `database`,
`cryptographic_key`, `test_example`, `non_secret`, and `unknown`. Prefer a specific
supported use (database or cryptographic key) over generic authentication; use
`api_token` for explicit API-key/token roles, and `authentication` otherwise.
Document multiple uses and select the primary demonstrated use; unresolved cases
remain unknown. Two teammates will independently label purpose and flow structure,
without seeing system predictions, then adjudicate disagreements and retain the
original labels and agreement counts. CredData detection labels remain unchanged.

## 3. RQ1: How are sensitive credentials represented and propagated through source code?

### Complete method

Characterize source representation, propagation, and sensitive use separately.
Representation categories will include direct string/bytes literal, container or
configuration literal, concatenation/formatting, and runtime/environment-derived
value. Propagation tags will include assignment/alias, container access, argument
passing, return value, and object attribute. Sink tags will include HTTP
authentication/API access, database authentication, and cryptographic use. Tags may
overlap, so their percentages need not sum to 100%.

Manually annotate every eligible case in the frozen held-out set using the two-reviewer
procedure. For environment-derived values, record the pattern but do not label the
environment-variable name as a hardcoded secret. Such values are currently outside
the detector's hardcoded-literal target and will be reported as a coverage limitation.

Compare recovered traces with reviewed source-to-use paths. Report representation
and propagation counts, candidate-generation recall, proportion of labeled locations
with a recovered sensitive use, and warning frequency. Separate genuinely unused
values from cases with unsupported or ambiguous paths; absence of an analyzer trace
alone does not demonstrate absence of a use. Review unmatched or incorrect traces
and summarize their failure categories. Report counts by repository as well as pooled.

### Results so far

The analyzer handles assignments/reassignment, same-module parameter and return
flows, selected container and string operations, recognized unittest setup/helpers,
and selected HTTP/OAuth, SSH, database, and HMAC operations. All 62 regression tests
pass. It discovers candidates at all 11 synthetic positive locations and 102/137
CredData positive locations (74.5%). On the CredData pilot, the flow policy identifies
17 labeled locations: 9 positives and 8 negatives. These are recovered sensitive-use
locations, not 17 proven live credentials. A complete manually adjudicated frequency
study of representation and propagation patterns has not yet been performed.

## 4. RQ2: To what extent does source-code context and program-flow information improve the precision and recall of automated secret detection?

### Complete method

Run Gitleaks and TruffleHog as traditional-tool reference conditions, then compare
context-only and context-plus-flow LLM classification. The main controlled comparison
is the paired context/hybrid ablation described in Section 2; comparisons against
other tools provide context but cannot by themselves isolate the effect of flow.
Include both implemented static policies as additional reference conditions.

For each model condition, evaluate the same candidate pool and report both full-set
and conditional precision, recall, F1, FPR, FNR, and abstention rate. Tabulate paired
outcomes: errors corrected by hybrid and errors introduced by hybrid. Stratify results
by whether a flow was available, repository, and annotated representation. Across
three repetitions, report mean and range; also report per-repository differences.
With few repositories, avoid broad statistical-generalization claims. Any expanded
candidate extractor will be evaluated as a separate experiment, not silently mixed
into one model condition.

### Results so far

Only static reference conditions have been evaluated. On the CredData pilot, flow
scoring achieves 52.9% precision and 6.6% recall. Evidence scoring achieves 68.5%
precision and 74.5% recall, but increases false positives from 8 to 47. The policy
change captures many unused or untraced credential-like literals. It is not evidence
that adding flow or an LLM improves classification. Context/hybrid results are pending.

## 5. RQ3: How accurately can the intended use of a potential credential be inferred from source-code context?

### Complete method

Use the independently adjudicated purpose labels and taxonomy in Section 2.
Classify the same candidates using source context alone and source context plus flow,
with identical model settings and redaction. Compare against a static inferred-purpose
reference based on supported sinks and literal evidence.

Report purpose accuracy, labeled-case denominator, per-category precision/recall,
and a confusion matrix. Report unknown predictions and abstentions separately.
Provide full-set accuracy (including extraction misses as unknown predictions) and
accuracy conditional on candidate discovery. Report performance on all purpose-labeled
cases and separately on detection-positive cases so that numerous non-secret examples
do not conceal errors in credential-use inference. Purpose categories are not equivalent
to secret/non-secret labels: a value's role does not establish whether it is genuine.

### Results so far

Static evidence scoring matches the synthetic purpose labels on 17/20 cases (85%);
flow scoring matches 10/20 (50%). These are development fixtures designed around
supported behaviors, not independent evidence of real-code purpose accuracy.
CredData purpose labels are not yet annotated and are deliberately excluded from
purpose scoring. No LLM intended-use results are available. Per-category metrics and
the proposed reviewed held-out annotations remain to be completed.

## 6. RQ4: How does a hybrid static-analysis and LLM approach compare with existing secret scanners?

### Complete method

Compare Gitleaks, TruffleHog, KeyTrace flow, KeyTrace evidence, context-only LLM,
and hybrid LLM on identical frozen source snapshots and labels. Pin tool versions
and configurations, record scan failures and exclusions, and disable online credential
verification. Normalize baseline locations using the existing importers; audit unmatched
findings before interpreting results. Tool-native candidate discovery remains part
of each end-to-end system, unlike RQ2's fixed-pool model ablation.

Report full-set detection metrics, per-repository results, and error categories.
Measure wall-clock time on the same machine, separating model startup from warm
inference and including candidate extraction in total pipeline time. Report median
and range over three runs, hardware, and available token counts. Local inference
has no hosted API charge, but runtime and resource use must still be reported.
Do not compare baseline tools on purpose labels they do not produce. Use reviewed
error examples to explain complementary strengths and weaknesses rather than
claiming universal superiority from pooled scores.

### Results so far

Gitleaks and TruffleHog output normalization and the model adapter protocol have
unit coverage. Actual baseline tools and the local LLM have not been run in this
workspace; no cross-tool ranking or hybrid improvement is established. The static
results in Appendix A provide the initial reference conditions for this comparison.

## 7. Deviations from the initial plan

| Original plan | Current change and reason |
|---|---|
| SecretBench was a candidate benchmark. | Used an available obfuscated CredData Python pilot plus controlled synthetic fixtures to develop a reproducible local pipeline. SecretBench was not required by the proposal, and no SecretBench results are claimed. |
| Baseline setup/runs scheduled September 21–October 4. | No completed baseline runs are recorded here. Work prioritized dataset preparation, static implementation, and offline scoring. Baselines are rescheduled before full experiments; teammates must confirm whether separate results exist. |
| Static source-to-use tracing as the primary implemented signal. | Added explicit unittest entry points after module-only analysis recovered no labeled pilot flows; many relevant paths reside in tests. The entry-point assumption is now recorded in reports. |
| Compare traditional, context-aware, and flow-aware approaches. | Added a literal-evidence static comparator after the flow-only policy missed many positives. This improves coverage but introduces more false alarms and does not replace the planned LLM ablation. |
| Small declaration/flow/sink slices for the LLM. | Current requests use redacted overlapping top-level statements with a 12,000-character cap. This simplifies initial export but may remove useful literal evidence or truncate context; controlled model evaluation remains pending. |
| Examine environment and dynamically constructed credentials. | Current detection targets hardcoded Python literals and bounded supported flows. Environment patterns will be characterized as a coverage limitation rather than reported as detected hardcoded values. |

## 8. Remaining schedule

Owners below are proposed assignments carried forward from the original proposal,
not claims of completed individual contributions. The team should confirm them.
The intermediate deadline of October 14 and final deadline of November 30 are
based on the team's supplied schedule.

| Dates (2026) | Task and concrete deliverable | Primary / support |
|---|---|---|
| Oct 11–14 | Review this report, verify artifact logs and dataset access, confirm individual contributions, and submit the intermediate package. | Rogelio / Liam |
| Oct 15–18 | Complete pinned baseline runs on development data; audit normalized/unmatched findings. Define annotation guide and freeze held-out repository selection. | Colin / Rogelio |
| Oct 19–25 | Implement local adapter; run a small feasibility pilot; freeze model/settings and correct prompt label policy and warning controls. | Cooper / Vansh |
| Oct 26–Nov 1 | Integrate hybrid pipeline, complete independent annotations/adjudication, freeze experiments, and prepare scheduled presentation material. | Vansh / Colin; Liam and Rogelio annotate |
| Nov 2–8 | Run all frozen conditions on held-out data; retain predictions, failures, version records, and runtime logs. | Colin / Liam |
| Nov 9–15 | Complete repeated runs, paired comparisons, purpose confusion matrices, and per-repository summaries. | Vansh / Cooper |
| Nov 16–22 | Review errors and limitations; write findings for each RQ without tuning on held-out results. | Rogelio / Colin |
| Nov 23–29 | Complete final report, figures, reproducibility package, and presentation. | Cooper / Liam |
| Nov 30 | Final review and report submission; confirm course deadline. | Liam / Cooper |
| Dec 1–4 | Final presentation preparation/delivery according to assigned course slot. | Entire team |

If local inference is too slow, reduce the development model or evaluation workload
before freezing the experiment, disclose the change, and keep comparisons paired.
Do not silently omit failed runs or replace the held-out set after seeing outcomes.

## Appendix A. Detailed preliminary results

All rows below use `--entry-points tests` and the same current implementation.

| Dataset / policy | N | TP | FP | TN | FN | Precision | Recall | F1 | Abstentions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Synthetic / flow | 20 | 10 | 2 | 7 | 1 | 83.3% | 90.9% | 87.0% | 0 |
| Synthetic / evidence | 20 | 11 | 1 | 8 | 0 | 91.7% | 100% | 95.7% | 1 |
| CredData / flow | 423 | 9 | 8 | 278 | 128 | 52.9% | 6.6% | 11.7% | 0 |
| CredData / evidence | 423 | 102 | 47 | 239 | 35 | 68.5% | 74.5% | 71.3% | 13 |

Evidence-policy FPR/FNR are 11.1%/0% on synthetic and 16.4%/25.5% on CredData.
Abstentions count as negative decisions in this table. Full confusion information,
case-level predictions, warnings, dataset fingerprints, and test output are in the
separate supporting files. These datasets were used for development; none of the
numbers establish held-out performance or the project's LLM hypothesis.

## Appendix B. Separate supporting artifacts

The codebase, datasets, and logs are submitted separately from this report, as
required. `docs/ARTIFACTS.md` contains the detailed inventory and reproduction
command.

| Artifact | Contents | Delivery location |
|---|---|---|
| Codebase | Scanner, detection and classification modules, evaluation tools, regression tests, README, and experiment documentation | Version-controlled repository |
| Synthetic dataset | 20 invented Python fixtures and their manifest | `datasets/synthetic/` in the repository |
| CredData pilot | Prepared obfuscated sources, manifest, metadata, licenses, exclusions, and provenance | Separate retained `datasets/creddata/` package |
| Evaluation results and logs | Four evaluation JSON reports, summary, verbose test log, run metadata, dataset fingerprints, and source hashes | Separate retained `output/intermediate/` package |
| Reproduction workflow | Script and commands that regenerate the result package | `evaluation/capture.py` and `docs/ARTIFACTS.md` |

The prepared CredData material and generated output are intentionally ignored by
Git, so a repository-only hand-in is incomplete. They are not present in the fresh
clone used for this review and must be copied from the team's retained package or
regenerated before submission. Dataset licensing and course-delivery restrictions
still apply; the data should not be made public merely to make the Git repository
self-contained.

## Sources and provenance

- Team proposal: *Keytrace Proposal CSE467.pdf*, supplied by the team; research
  questions and original work allocation are retained here.
- Local implementation and experimental records: this repository and the separate
  `output/intermediate/` artifacts regenerated for this draft.
- CredData upstream: https://github.com/Samsung/CredData, revision
  `0b1940e171725ad8937311120b191602608a4801`; local provenance and licenses retained.

Literature citations from the proposal should be bibliographically verified before
being reused in the final report. This draft makes no new literature-result claims.
