# Project and progress

- **Name:** Keytrace
- **Repository:** https://github.com/mexicancyberweapon/keytrace
- **Course:** CSE 467 — Data & Information Security
- **Team:** Liam Nolan, Rogelio Corrales, Vansh Sinha, Colin Murnane, Cooper Lake
- **Starting language:** Python. Other languages are possible future work.

Keytrace is a research-oriented **context- and flow-aware secret scanner**. Traditional scanners such as Gitleaks and TruffleHog find candidate credentials through patterns, entropy, and other heuristics. Keytrace aims to track how candidate values are created, assigned, passed through functions, and used in security-sensitive operations. A planned LLM component will interpret local source-code context and summarized program flow to classify candidates and infer their intended uses.

**Core hypothesis, not an established result:** Program-flow evidence and LLM semantic reasoning might reduce false positives while preserving recall. The project must measure this rather than assume it.

## Research questions

Keep the four original questions separate unless the team explicitly changes the proposal. RQ2 and RQ4 overlap in metrics but have distinct emphases.

1. **RQ1:** How are sensitive credentials represented and propagated through source code?
2. **RQ2:** To what extent does source-code context and program-flow information improve the precision and recall of automated secret detection?
3. **RQ3:** How accurately can the intended use of a potential credential be inferred from source-code context?
4. **RQ4:** How does a hybrid static-analysis and LLM approach compare with existing secret scanners?

RQ1 characterizes flows; RQ2 isolates the value of adding context/flow; RQ3 studies intended-use labels; RQ4 evaluates full systems and their relative strengths and weaknesses.

## Current state

The Python scanner supports assignments, same-module function arguments and returns,
local scopes, reassignment, common string operations, basic containers, and selected
HTTP authentication, database, and HMAC uses. Branches and loops are approximated.
Directory scanning, redacted JSON reports, model request export/import, baseline
normalization, and scoring are implemented. Input programs are never executed.

There are 62 regression tests, including command-line experiment roundtrips. Actual
LLM and baseline-scanner experiments have not run. The model test uses mock output.
The Ollama adapter still needs implementation.

## Initial development results (module entry points)

| Measure | Synthetic fixtures | CredData Python pilot |
|---|---:|---:|
| Cases | 20 | 423 |
| Positive / negative labels | 11 / 9 | 137 / 286 |
| True positives / false positives | 9 / 2 | 0 / 0 |
| True negatives / false negatives | 7 / 2 | 286 / 137 |
| Precision | 81.8% | Undefined |
| Recall / F1 | 81.8% / 81.8% | 0% / 0% |
| Candidate-generation recall | 90.9% (10/11) | 62.8% (86/137) |
| Intended-use accuracy | 45% (9/20) | Not annotated |

Neither dataset is a held-out evaluation. Synthetic credentials are invented and
invalid; positive labels simulate a credential's role. Static positives mean a
candidate reached a supported sensitive use, not that a live credential was proven.
Synthetic failures include neutral names, unused credentials, and test values at
sensitive sinks.

The external pilot spans 60 files in three repositories. It originally contained
459 Python labels; 30 were excluded for multiple candidates on one line and six for
multiline candidates. Original T/F/X labels are preserved (T positive, F/X negative).
Candidates were found at 164 labeled locations, but no supported sensitive-use
flows were found. 59 files emitted analysis warnings. Class methods, framework entry
points, and cross-file flows are outside current coverage; these results must not
be interpreted as absence of secrets. Purpose labels require separate review.

## Coverage update: explicit unittest entry points

`--entry-points tests` now models recognized unittest classes, setup, and same-class
helpers with independent state per test. Known HTTP/OAuth sessions, authentication
wrappers, Paramiko password calls, named attributes, `with` bodies, and dictionary
access/unpacking are supported within the bounded analysis. Findings identify the
assumed framework entry point. Uncalled ordinary functions remain inactive.

On the same 423 pilot labels, this mode yields **TP=9, FP=8, TN=278, FN=128**:
precision **52.9%**, recall **6.6%**, F1 **11.7%**. Candidate recall remains **62.8%**;
candidates appear at 167 labeled locations. Synthetic scores are unchanged and all
45 tests pass. Current module-only pilot scoring still produces zero findings.

This improves coverage but does not establish good real-world detection or any LLM
benefit. The gain includes an explicit change in entry-point assumptions, not only
new sink rules. General object methods, imported fixtures, cross-file flows, pytest
entry points, setUpClass, and teardown remain unsupported. Context-manager effects
are not modeled. Both pilot datasets remain development-only.

## Latest literal-evidence detection (October 10)

The scanner now assesses literal evidence separately from recovered flows. The
`evidence` policy recognizes unused named credentials, comparisons and defaults,
passphrases, private-key blocks, selected token formats, and credential-bearing
URLs. Supported sensitive arguments can promote neutrally named literals via their
provenance. Explicit placeholders/examples are suppressed; metadata and possible
resource references can abstain. The code never checks credential validity.

Same unchanged development datasets, `--entry-points tests`:

| Dataset / policy | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Synthetic / evidence | 11 | 1 | 8 | 0 | 91.7% | 100% | 95.7% |
| Synthetic / flow | 10 | 2 | 7 | 1 | 83.3% | 90.9% | 87.0% |
| CredData / evidence | 102 | 47 | 239 | 35 | 68.5% | 74.5% | 71.3% |
| CredData / flow | 9 | 8 | 278 | 128 | 52.9% | 6.6% | 11.7% |

Evidence mode abstains on 13 pilot cases and one synthetic case; the existing
scoring convention counts abstentions as negative decisions. Candidate recall is
102/137 on CredData and 11/11 on synthetic. CredData purpose remains unannotated;
synthetic evidence purpose accuracy is 17/20. All 62 regression tests pass.

This is a decision-policy change, not solely better flow recovery. Recall improved
substantially, but the evidence policy produces more false alarms than the flow
baseline. Both datasets were used for development; these are not held-out results.
No labels, exclusions, or source files were changed to improve scores. Broad
embedded-text matching was evaluated and removed because it increased false alarms
without improving pilot recall. Documentation/configuration spans, unknown formats,
unsupported flows, and ambiguous test credentials remain errors to investigate.

## Remaining work

1. Improve real-code flow coverage using development cases and regression tests.
2. Implement the local-model adapter; pin model and settings and measure runtime.
3. Run Gitleaks, TruffleHog, static-only, context-only, and hybrid conditions on the
   same data. Record failures, runtime, and model cost where relevant.
4. Prepare repository-disjoint held-out cases; independently review intended-use
   labels, analyze errors, and test whether flow evidence improves predictions.
5. Write the report and presentation from measured results and the course rubric.

See [EXPERIMENTS.md](EXPERIMENTS.md) for commands, scoring policies, and data setup.
The scanner remains heuristic, with no general object, cross-file, mutation-alias,
exception-path, or fixed-point analysis. Redaction removes string contents and
comments from model context, but leaves identifiers and filenames visible.

## Data handling

Keep downloaded datasets and credentials out of Git. Use synthetic values in tests.
Do not send raw restricted data to external models without the required permission.
An authentication use supports a purpose inference but does not prove a real secret;
a true secret can also exist without a recoverable sink.

## Course milestones

The user provided the following course schedule; **confirm current deadlines independently**.

| Date | Milestone / Planned Work |
|---|---|
| Sep 9, 2026 | Proposal due |
| Sep 14 | Proposal presentation |
| Sep 21–Oct 4 | Baseline tools and labeled dataset |
| Oct 5–18 | Static-flow analyzer |
| **Oct 14** | **Intermediate report due** |
| Oct 19–Nov 1 | LLM classification and integration |
| Oct 26 / Oct 28 | Project presentation days |
| Nov 2–15 | Experiments and metrics |
| Nov 16–29 | Error analysis and report writing |
| **Nov 30** | **Final report due** |
| Dec 2 / Dec 4 | Final presentation days |

For the intermediate report, prioritize a reproducible prototype, tests, and preliminary evaluation.

## Proposal references

- Basak et al. (2023), *A Comparative Study of Software Secrets Reporting by Secret Detection Tools*. https://arxiv.org/abs/2307.00714
- Han et al. (2024), *A Credential Usage Study: Flow-Aware Leakage Detection in Open-Source Projects*. https://www.semanticscholar.org/paper/0541fb550f39283920f21bcfa14441844a14035d
- Rahman et al. (2025), *Secret Breach Detection in Source Code with Large Language Models*. https://arxiv.org/abs/2504.18784
- Soltaniani & Ghafari (2026), *Learning to Detect Hardcoded Secrets*. https://link.springer.com/article/10.1007/s10664-026-10929-w

These are cited research directions from the earlier proposal. Recheck details before writing formal scholarly citations.
