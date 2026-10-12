# Experiment protocol

## Dataset contract

A manifest is a JSON object with `cases`, a list of objects:

```json
{"id":"case-001","path":"example.py","line":2,"is_secret":true,"purpose":"authentication","representation":"function","split":"development"}
```

Locations are 1-based source lines relative to the manifest directory. IDs and
file/line pairs must be unique. One labeled candidate per source line is required;
multiple discovered candidates on that line are aggregated. The purpose vocabulary
is `authentication`, `api_token`, `database`, `cryptographic_key`, `test_example`,
`non_secret`, and `unknown`. Define one primary purpose during annotation; for
example, use `api_token` for explicit API-key headers and `authentication` for
otherwise unspecified authentication. Ambiguous labels require adjudication.

The bundled manifest is entirely development data. Before research experiments,
create separate development and held-out manifests, splitting by source repository
or template family to avoid near-duplicate leakage. The runner evaluates every
case in the supplied manifest; it does not automatically filter the `split` field.
Use independent human review for secret and purpose labels and record disagreements.
For real-world data, obtain authorized source and labels before importing it.
Do not put real credentials, private source, API keys, or raw tool reports in Git.

## Static experiment and LLM inputs

```bash
python3 -m evaluation.run datasets/synthetic/manifest.json --output output/static-results.json --requests output/llm-requests.jsonl
```

Results include TP/FP/TN/FN, precision, recall, F1, false-positive/negative rates,
purpose accuracy/confusion, and per-case predictions. Labels with `purpose_labeled: false` are excluded from purpose metrics; the denominator is reported as `purpose_labeled_n`. Undefined ratios are JSON
null. Missing predictions count as negative; explicit abstentions are counted and
also treated as negative for binary metrics. Report abstention rates alongside
accuracy, since this policy penalizes abstentions on positive examples.

Candidate-generation recall is measured separately. Conditional metrics use the
subset discovered by **KeyTrace's candidate extractor**, including when scoring
imported predictions. Use the full-set metrics for cross-tool comparisons.
Duplicates at the same labeled location collapse to one decision. Record and review
unmatched baseline findings; they are not automatically treated as false positives
because they lack labels. Candidate-level FPR applies only to the labeled negative
set, not to every source line in a repository.

Context and hybrid modes share the exact system prompt and redacted local context.
Hybrid adds traces and analysis warnings. The current local-context window includes
whole overlapping top-level statements (including a whole function), capped at
12,000 characters. All string/bytes literal contents and comments are removed via
AST rewriting; identifiers and file names remain. Inspect exported inputs before
using private source. Redaction itself changes available evidence and must be
reported as an experimental limitation. Ground truth labels are not included in
model messages. A candidate without a trace can still be classified by the LLM.

## LLM adapter or offline response import

An adapter executable reads one request JSON object from stdin. It should pass
`messages` to the selected model and print only a JSON prediction:

```json
{"is_secret":null,"purpose":"unknown","rationale":"Insufficient evidence"}
```

Do not pass the surrounding request IDs as extra model evidence. Pin the exact
model version and generation settings in the adapter/configuration; use the same
settings for both modes. This repository does not select a model or transmit any
source to a provider automatically.

```bash
python3 -m evaluation.classify output/llm-requests.jsonl --mode context --model-id EXACT_MODEL_VERSION --output output/context-predictions.json --adapter /path/to/model-adapter
python3 -m evaluation.classify output/llm-requests.jsonl --mode hybrid --model-id EXACT_MODEL_VERSION --output output/hybrid-predictions.json --adapter /path/to/model-adapter
python3 -m evaluation.run datasets/synthetic/manifest.json --predictions output/hybrid-predictions.json --output output/hybrid-results.json
```

For offline import, each response JSONL row must have `case_id`, `candidate_id`,
`mode`, and `prediction`. Replace `--adapter ...` with `--responses PATH`. Exactly
one response per exported request in the selected mode is required. Model IDs,
request hashes, mode, and adapter runtime are recorded alongside predictions.
Model token usage/cost and generation settings must be recorded separately by the
adapter. Invalid responses fail the run rather than silently becoming negatives.
A mock adapter is used only in a protocol unit test; it is not a model experiment.

## External baselines

Install and pin tool versions separately. Neither tool is included in this repo.
Capture version strings, commands, configurations, and runtime with results.
Run filesystem scans over the **same source snapshot**, not Git history. For the
synthetic dataset, use detection without online credential verification.

Example commands (run from the repository root; `output/` must exist):

```bash
gitleaks dir datasets/synthetic --report-format json --report-path output/gitleaks.json --redact
trufflehog filesystem datasets/synthetic --json --no-verification > output/trufflehog.jsonl
python3 -m evaluation.baselines gitleaks datasets/synthetic/manifest.json output/gitleaks.json --output output/gitleaks-predictions.json
python3 -m evaluation.baselines trufflehog datasets/synthetic/manifest.json output/trufflehog.jsonl --output output/trufflehog-predictions.json
python3 -m evaluation.run datasets/synthetic/manifest.json --predictions output/gitleaks-predictions.json --output output/gitleaks-results.json
```

Gitleaks commonly exits nonzero when it finds secrets; distinguish that from tool
failure. Import accepts Gitleaks `File`/`StartLine` JSON and TruffleHog
`SourceMetadata.Data.Filesystem.file`/`line` JSONL. Relative paths must be relative
to the manifest directory; absolute paths beneath that directory also work. Review
`.unmatched.json` output and normalize other path roots before scoring. Raw reports
may contain credentials; the importer only retains location and detection status.
These tools do not predict the project's purpose taxonomy, so their purpose score
is not a meaningful comparison. Compare their binary detection metrics.

Command references: [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
and [TruffleHog README](https://github.com/trufflesecurity/trufflehog/blob/main/README.md).
The interfaces have unit coverage, but real baseline binaries have not been run in
this environment.

## Research questions and comparisons

- RQ1: Manually categorize representations and propagation patterns. Report counts
  and the proportion with recoverable flows; absence of a trace is not absence of use.
- RQ2: Compare context-only and hybrid on the same extracted candidates with the same
  model/prompt settings to isolate the added flow evidence. Also report full-set
  performance including extraction misses.
- RQ3: Compare purpose accuracy and per-category confusion against adjudicated labels.
- RQ4: Compare Gitleaks, TruffleHog, static-use heuristic, context-only, and hybrid on
  the same held-out cases. Include runtime, model cost, and error categories.

Do not tune prompts or implementation on the held-out evaluation. Repeat model runs
if nondeterminism matters; report variability and dataset limitations. No improvement
over existing tools should be claimed until those experiments have actually run.


## Local CredData pilot

The prepared pilot is in `datasets/creddata/python-pilot/`. Its manifest, source
files, licenses, import summary, and hashes are retained. Original selected metadata
is in `datasets/creddata/metadata/`; the pinned upstream revision, snapshot mapping,
and compatibility patch are in `datasets/creddata/provenance.json`. All downloaded
data remains ignored by Git. [Project status](PROJECT.md) records the results.

```bash
python3 -m evaluation.run datasets/creddata/python-pilot/manifest.json --output output/creddata-static-results.json
```

The pilot uses repository IDs `69d49010`, `c9b945fa`, and `533c47c6` (docker-py,
requests-oauthlib, and paramiko), chosen for manageable Python development coverage.
This selection is not representative sampling. CredData's positive-label policy can
include test credentials; do not silently substitute our synthetic label policy.
The prepared source is upstream-obfuscated, not a guarantee that every possible
sensitive string has been removed.

One-time download machinery, original snapshots, duplicate obfuscated files,
installation environment, and logs were removed during cleanup. They are not needed
to scan or score the prepared pilot. To rebuild or expand it, retrieve
[CredData](https://github.com/Samsung/CredData) at the revision in provenance, select
the snapshot entries and corresponding metadata, and run its official downloader
and obfuscation step in a separate working directory. The preparation used
`pybase62==1.0.0` and a Python 3.13 compatibility patch to `meta_row.py`: check
`sys.version_info[:2] >= (3, 14)` before importing `annotationlib`, and pass `cls`
to `get_annotations` rather than `cls.__class__`. Preserve the original licenses.
Then import the already-obfuscated checkout into a fresh output directory:

```bash
python3 -m evaluation.creddata /path/to/prepared/CredData --output datasets/creddata/new-pilot
```

The importer preserves labels and records exclusions for ambiguous line matches,
multiline candidates, and unparseable files. It sets `purpose_labeled: false` until
purpose labels are reviewed; unknown purposes do not count as correct predictions.


## Entry-point comparison

Use `--entry-points module` (default) for module paths or `--entry-points tests`
for recognized unittest methods with setup. Pass the same mode when producing
context-only and hybrid requests. Reports record `entry_points`, and findings record
`entry_point`. Modeled tests are assumed entry points, not observed executions.
Do not compare the old module-only result to tests mode without disclosing this
methodology change. The same dataset labels and exclusions apply in both modes.

```bash
python3 -m evaluation.run datasets/creddata/python-pilot/manifest.json --entry-points tests --output output/creddata-test-results.json --requests output/creddata-test-requests.jsonl
```

## Literal evidence versus flow policy

`evaluation.run --decision-policy flow` retains the original default: a supported
sensitive-use flow predicts positive. `--decision-policy evidence` uses candidate
assessments even without a flow and suppresses explicit placeholders/examples.
Ambiguous metadata/resource references return null. No candidate predicts negative
for scoring, but absence of detection is not a safety guarantee. The report records
`decision_policy`, a distinct `mode`, and per-case reasons. Imported predictions
still override static decisions and are marked `imported_predictions`.

```bash
python3 -m evaluation.run datasets/creddata/python-pilot/manifest.json --entry-points tests --decision-policy evidence --output output/creddata-evidence.json
python3 -m evaluation.run datasets/synthetic/manifest.json --decision-policy evidence --output output/synthetic-evidence.json
```

The source scanner's JSON includes assessments and flow findings separately;
false/null assessments do not erase observed flow evidence. Null means review,
not a confident false-positive classification. Existing metrics count null as
negative and report abstentions separately. Confidence is categorical and uncalibrated.
Use identical data and entry points when comparing policies. The latest numbers
are in PROJECT.md; no model or baseline-tool results are implied by this policy.
