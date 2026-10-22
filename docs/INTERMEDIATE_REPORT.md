# KeyTrace Intermediate Report

**CSE 467, Data and Information Security**

**Team** Liam Nolan, Rogelio Corrales, Vansh Sinha, Colin Murnane, Cooper Lake

**Draft date** October 11, 2026

## 1. Objective and progress

KeyTrace asks whether source code context and program flow can improve secret
detection and help identify how a credential is used. The prototype parses Python
without running it. It finds possible credential literals, traces supported paths
to sensitive uses, and redacts values in its reports. A planned LLM step will
classify candidates with context alone and with added flow information.

So far, the team has built the static analyzer, two decision policies, 20 synthetic
development cases, a 423 case CredData Python pilot, the evaluation tools, the model
input and output format, baseline importers, and 62 regression tests. These working
and tested parts show that the project has completed at least 30% of its planned
work. Local LLM runs, Gitleaks and TruffleHog runs, held-out testing, and final error
analysis are still pending.

The flow policy marks a candidate positive when it reaches a supported sensitive
argument. The evidence policy also considers literal format and variable names. It
rejects clear placeholders and examples, and returns unknown for unclear metadata
or file references. Neither policy checks whether a credential is live.

## 2. Shared experimental design

### Data

The current development data has 20 synthetic cases with 11 positives and 9
negatives. It also has 423 CredData cases with 137 positives and 286 negatives.
Those cases come from 60 Python files in docker-py, requests-oauthlib, and paramiko.
CredData marks T as positive and F or X as negative. The importer excluded 30 labels
that shared a line with another candidate and 6 multiline labels. The team set these
rules before scoring the scanner. All synthetic credential values are invented and
invalid.

Each case points to one source file and line. If KeyTrace finds several candidates
on that line, the evaluator combines them into one prediction. The results therefore
measure labeled lines rather than exact text spans. We will review external tool
findings that do not match a labeled line instead of counting them as false positives.

For the final test, we plan to create a separate CredData set from at least three
more repositories. We will aim for 200 usable cases, including at least 50 positives
and 50 negatives if the data allows it. We will choose cases by language, available
labels, and repository. Scanner results will not affect selection. We will also
remove duplicate or nearly identical files across the development and held-out sets.
Before viewing final predictions, we will lock the manifests, exclusions, code,
prompts, and settings.

### Test conditions

All tools will scan the same files without trying credentials online. The main
KeyTrace condition will enable recognized `unittest` methods and setup code as test
entry points. A separate run will use module entry points only. Unsupported imports,
cross-file calls, dynamic behavior, and incomplete object tracking may hide flows.

The planned model will run locally through an Ollama adapter. Development tests will
select the exact model. We will record the model digest, quantization, prompt version,
context limit, generation settings, and hardware. We will use temperature zero when
the model supports it and repeat each context and hybrid run three times.

The context and hybrid tests will use the same candidates, source context, model
settings, and output format. The hybrid test will add flow traces. The current
exporter also adds analysis warnings only to the hybrid test. Before final testing,
we must give both tests the same warnings so that flow is the only difference.

The exporter replaces string and byte values with `[REDACTED]` and removes comments.
It keeps identifiers and file paths. Context includes any top-level statement that
overlaps the selected line, up to 12,000 characters. We will use the same redaction
and context limit in both model tests and record any truncation. Model input will
not contain case IDs or ground-truth labels.

### Scoring and labels

We will report TP, FP, TN, FN, precision, recall, F1, false positive rate, and false
negative rate. We will also report candidate recall because the LLM cannot classify
a candidate that KeyTrace never finds. Full-set scores include missed candidates.
Conditional scores include only cases where KeyTrace found a candidate. The scorer
counts missing predictions and abstentions as negative decisions, and reports both
counts separately. Invalid model output stops the run and appears in the log.

CredData may label credentials in test code as positive. We will keep those labels.
The current model prompt rejects all test and example values, so we must revise it
before the CredData experiment. The new wording should reject clear dummy values
without rejecting a credential only because it appears in a test.

Purpose labels use `authentication`, `api_token`, `database`, `cryptographic_key`,
`test_example`, `non_secret`, and `unknown`. We will choose the most specific use
shown in the source. Two teammates will label purpose and flow without seeing system
predictions. They will compare their labels, resolve disagreements, and record the
original labels and agreement counts. We will not change CredData detection labels.

## 3. RQ1: How are sensitive credentials represented and propagated through source code?

### Complete method

We will label three parts of each case. Representation labels will cover direct
string or byte literals, container or configuration values, joined or formatted
strings, and runtime or environment values. Flow labels will cover assignments,
aliases, container access, function arguments, returns, and object attributes. Use
labels will cover HTTP authentication, API access, database login, and cryptographic
operations. A case may have more than one label.

Two teammates will review every held-out case. They will record environment-based
patterns but will not treat an environment variable name as a hardcoded secret.
They will compare reviewed source paths with KeyTrace traces. We will report label
counts, candidate recall, recovered sensitive uses, warnings, and results by
repository. We will also separate truly unused values from flows that KeyTrace could
not follow and review wrong or missing traces by error type.

### Results so far

The analyzer handles assignments, reassignments, same-module arguments and returns,
selected containers and string operations, recognized unittest setup and helpers,
and selected HTTP, OAuth, SSH, database, and HMAC calls. All 62 regression tests
pass. KeyTrace finds candidates at all 11 synthetic positive locations and 102 of
137 CredData positive locations, or 74.5%. On CredData, the flow policy marks 17
labeled locations positive. Nine are labeled positive and eight are labeled negative.
The team has not yet completed the manual count of representation and flow patterns.

## 4. RQ2: To what extent does source code context and program flow improve precision and recall?

### Complete method

We will run Gitleaks and TruffleHog as reference tools. We will then compare LLM
classification with context alone against classification with context plus KeyTrace
flows. Both LLM tests will use the same candidate pool, model, prompt, redaction,
and settings. This comparison will show whether the added flow changes results. The
flow and evidence policies will provide two more static reference points.

For each model test, we will report full-set and conditional precision, recall, F1,
false positive rate, false negative rate, and abstentions. We will count cases that
the hybrid test fixes and cases that it makes worse. We will also break results down
by flow availability, repository, and representation type. For the three repeated
runs, we will report the mean and range. If we change candidate extraction, we will
report it as a separate experiment.

### Results so far

Only the static policies have results. On CredData, the flow policy reaches 52.9%
precision and 6.6% recall. The evidence policy reaches 68.5% precision and 74.5%
recall, but false positives rise from 8 to 47. The evidence policy finds many
credential-like literals that lack a recovered flow. These numbers do not show that
flow or an LLM improves classification. The context and hybrid tests remain pending.

## 5. RQ3: How accurately can source code context identify a credential's intended use?

### Complete method

We will use the reviewed purpose labels from Section 2. The same model will classify
each candidate with context alone and with context plus flow. Both tests will use the
same settings and redaction. We will compare them with the purpose that KeyTrace
infers from supported uses and literal evidence.

We will report purpose accuracy, the number of labeled cases, results for each
purpose, and a confusion matrix. We will list unknown answers and abstentions. We
will report accuracy for the full set and for candidates that KeyTrace found. We
will also report results for all labeled cases and for positive credentials alone.
A correct use label does not prove that a credential is real.

### Results so far

The evidence policy matches 17 of 20 synthetic purpose labels, or 85%. The flow
policy matches 10 of 20, or 50%. The synthetic cases test supported behavior and do
not measure performance on new repositories. CredData does not yet have reviewed
purpose labels, so the evaluator leaves those cases out of purpose scoring. No LLM
purpose results are available.

## 6. RQ4: How does the hybrid approach compare with existing secret scanners?

### Complete method

We will compare Gitleaks, TruffleHog, KeyTrace flow, KeyTrace evidence, the context
LLM, and the hybrid LLM on the same files and labels. We will record tool versions,
settings, failures, and exclusions, and turn off online credential checks. The
existing importers will match baseline findings to labeled lines. We will review
unmatched findings before drawing conclusions.

We will report full-set detection scores, results by repository, and common error
types. We will time three runs on the same computer. Timing will separate model
startup from later requests and will include candidate extraction. We will report
the median, range, hardware, and token counts. Gitleaks and TruffleHog do not predict
purpose, so we will compare them only on secret detection.

### Results so far

Tests cover the Gitleaks and TruffleHog importers and the model adapter format. The
team has not run the real baseline tools or local LLM in this workspace. We therefore
have no cross-tool ranking or evidence that the hybrid method improves results.
Appendix A lists the current static results.

## 7. Changes from the initial plan

| Original plan | Change and reason |
|---|---|
| Consider SecretBench as a benchmark | We used an available obfuscated CredData Python pilot and synthetic cases to build the local pipeline. The proposal did not require SecretBench, and this report makes no SecretBench claims. |
| Run baseline tools from September 21 to October 4 | The team first prepared data, built the scanner, and added offline scoring. Baseline runs now come before the full experiment. Teammates still need to confirm whether they ran separate baselines. |
| Use source to use tracing as the main signal | Module-only analysis found no labeled CredData flows, so we added explicit unittest entry points. Reports now record that setting. |
| Compare traditional, context, and flow approaches | We added the evidence policy after flow-only scoring missed many positives. It improves recall but also adds false positives. It does not replace the planned LLM comparison. |
| Send small code slices to the LLM | Current requests send redacted top-level statements with a 12,000 character limit. This was simpler to build, but it may hide values or cut off context. We still need to test it. |
| Examine environment and generated credentials | Current detection focuses on hardcoded Python literals and supported flows. We will report environment patterns as a limitation. |

## 8. Remaining schedule

The owners below come from the original proposal. The team still needs to confirm
them and record each member's completed work. The schedule uses the team's reported
October 14 intermediate deadline and November 30 final deadline.

| Dates in 2026 | Task and output | Primary and support |
|---|---|---|
| Oct 11 to 14 | Review the report, verify logs and dataset access, confirm contributions, and submit the intermediate package | Rogelio and Liam |
| Oct 15 to 18 | Run pinned baseline tools on development data, review unmatched findings, write the annotation guide, and choose held-out repositories | Colin and Rogelio |
| Oct 19 to 25 | Build the local adapter, run a small pilot, choose the model and settings, and fix the prompt and warning controls | Cooper and Vansh |
| Oct 26 to Nov 1 | Connect the hybrid pipeline, finish annotation and review, lock the experiment, and prepare presentation material | Vansh and Colin, with Liam and Rogelio annotating |
| Nov 2 to 8 | Run every condition on held-out data and save predictions, failures, versions, and timing logs | Colin and Liam |
| Nov 9 to 15 | Finish repeat runs, paired comparisons, purpose confusion matrices, and repository summaries | Vansh and Cooper |
| Nov 16 to 22 | Review errors and limitations and write findings for each RQ | Rogelio and Colin |
| Nov 23 to 29 | Finish the final report, figures, reproducibility package, and presentation | Cooper and Liam |
| Nov 30 | Review and submit the final report after confirming the deadline | Liam and Cooper |
| Dec 1 to 4 | Prepare and give the final presentation | Entire team |

If local inference runs too slowly, we will reduce the development model or workload
before we lock the final experiment. We will report that change and keep both LLM
tests matched. We will also keep failed runs and avoid changing the held-out set
after seeing results.

## Appendix A. Preliminary results

All rows use `--entry-points tests` and the same code version.

| Dataset and policy | N | TP | FP | TN | FN | Precision | Recall | F1 | Abstentions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Synthetic flow | 20 | 10 | 2 | 7 | 1 | 83.3% | 90.9% | 87.0% | 0 |
| Synthetic evidence | 20 | 11 | 1 | 8 | 0 | 91.7% | 100% | 95.7% | 1 |
| CredData flow | 423 | 9 | 8 | 278 | 128 | 52.9% | 6.6% | 11.7% | 0 |
| CredData evidence | 423 | 102 | 47 | 239 | 35 | 68.5% | 74.5% | 71.3% | 13 |

The evidence policy has an 11.1% false positive rate and 0% false negative rate on
the synthetic data. On CredData, those rates are 16.4% and 25.5%. The scorer counts
abstentions as negative decisions. Separate files contain the full predictions,
warnings, dataset fingerprints, and test output. Both datasets supported development,
so these results do not measure held-out performance or prove the LLM hypothesis.

## Appendix B. Separate code, data, and logs

The course submission should include these items separately from the report.
`docs/ARTIFACTS.md` lists the files and reproduction command.

| Item | Contents | Location |
|---|---|---|
| Code | Scanner, detection and classification modules, evaluation tools, tests, README, and experiment documentation | Version-controlled repository |
| Synthetic data | 20 invented Python cases and their manifest | `datasets/synthetic/` in the repository |
| CredData pilot | Obfuscated sources, manifest, metadata, licenses, exclusions, and provenance | Separate `datasets/creddata/` package |
| Results and logs | Four evaluation reports, summary, test log, run metadata, dataset fingerprints, and source hashes | Separate `output/intermediate/` package |
| Reproduction files | Script and instructions that rebuild the result package | `evaluation/capture.py` and `docs/ARTIFACTS.md` |

Git ignores the CredData and generated output folders. This fresh clone does not
contain them. The team must copy them from its saved package or regenerate them
before submission. The team should follow the dataset license and course delivery
rules instead of publishing the data in the public repository.

## Sources

- *Keytrace Proposal CSE467.pdf*, supplied by the team
- This repository and its separate `output/intermediate/` records
- CredData revision `0b1940e171725ad8937311120b191602608a4801` from
  https://github.com/Samsung/CredData

The team should verify proposal references before using them in the final report.
