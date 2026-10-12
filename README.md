# KeyTrace

A research prototype for Python credential detection using static source-to-use
traces and optional LLM classification. Input Python is parsed, never executed.
The research hypothesis is that context and flow may improve classification;
this repository does not establish that hypothesis yet.

## Quick start

Python 3.10+; no third-party Python packages are required for the offline pipeline.
Development was tested on Python 3.13.5.

```bash
python3 main.py datasets/synthetic/header_alias.py
python3 main.py datasets/synthetic --format json --output output/scan.json
python3 -m unittest discover -s tests -v
python3 -m evaluation.run datasets/synthetic/manifest.json --output output/static-results.json --requests output/llm-requests.jsonl
```

The scanner accepts a file or directory, skips common dependency directories,
reports parse errors per file, and returns exit status 1 if any file fails.
Reports redact candidate values. Findings contain source locations, call-site
parameter bindings, return steps, sink arguments, and inferred use categories.
Candidates without a known sensitive use remain in the candidate list.
Reports also include `assessments`: potential secrets, likely false alarms, or
`null` decisions needing review, each with a categorical reason. Confidence labels
are heuristic evidence strengths, not calibrated probabilities. No credentials are
contacted or validated. Text output shows both assessments and sensitive-use traces.

## Where things live

```text
main.py             Command-line entry point
scanner.py          Python candidate and flow analysis
detection.py        Literal evidence and placeholder/reference assessment
classification.py   Redacted LLM requests and response validation
evaluation/         Dataset importers, model runner, and scoring
tests/              Automated regression tests
datasets/synthetic/ Small committed development fixtures
datasets/creddata/  Prepared local pilot and provenance (ignored by Git)
docs/               Experiment instructions and project status
```

`output/` holds ignored generated results. Preserve `output/intermediate/` for
the report submission; regenerate it with `python3 -m evaluation.capture`.
No installation environment is needed for scanning, tests, or offline scoring.

## Supported analysis

- String/bytes-literal discovery using credential names, dictionary keys, keyword
  arguments, defaults, comparisons, and selected positional parameters. Private-key
  blocks, selected token formats, and credential-bearing URLs work with neutral names.
  Candidate discovery also visits uncalled functions;
  sensitive-use findings require a call path.
- Neutral literals retain internal provenance and become candidates when they reach
  a supported sensitive argument. Ordinary URL arguments do not trigger this rule.
- Simple/chained assignments, annotated assignments, container literals, constant
  indexing, dictionary item assignments, and tuple/list unpacking.
- Same-module named functions, positional/keyword parameters, keyword-only
  parameters, defaults, return values, and bounded nested calls.
- Concatenation, f-strings, and approximate propagation through common string methods.
- Branch merging, early returns, and approximate zero/one-iteration loop analysis.
- Opt-in unittest entry points with isolated per-test setup and same-class helper calls.
- Named object attributes, known HTTP/OAuth sessions, Basic/Digest auth wrappers,
  selected Paramiko password calls, dictionary `get`/`update`, and literal `**kwargs`.
- Import aliases; authentication headers and `auth=` in `requests`/`httpx` module
  calls; password keywords in selected database connectors; `hmac.new` keys.

A sensitive use is evidence of intended use, **not proof of a genuine credential**.
Evaluation defaults to the original flow policy. Use `--decision-policy evidence`
to assess hardcoded literals independently of reachability and suppress explicit
placeholders/examples. Credential metadata and possible file/URL references need
review. Test filenames alone do not suppress credentials.
The scanner is not a replacement for a production secret scanner.

## Limits

Neutral names without recognizable contents or a supported flow can still be missed.
Format recognition covers only a small set of patterns and does not prove validity.
Embedded configuration/docstring spans and dynamically generated credentials remain
limitations. Environment-derived values are not hardcoded
secret candidates. No cross-file calls, general object/method resolution, closures,
variadic argument binding, dynamic dispatch, mutation alias tracking, exception
paths, comprehensions, or full control-flow analysis are supported. Function default
values are approximated at call time. Import aliases are collected module-wide.
Assignments that shadow imports are conservatively unresolved. Branch conditions
are not evaluated, loops do not reach a fixed point, and recursion is cut off.
Warnings identify many unsupported operations; absence of warnings is not a
completeness guarantee. Alternative traces may collapse to one representative path.

## Experiments

See [the experiment protocol](docs/EXPERIMENTS.md) for data labels, baseline
normalization, model adapter execution, scoring, and the held-out evaluation plan.
See [project status](docs/PROJECT.md) for research questions, verified results,
course milestones, and remaining work.

The 20 cases in `datasets/synthetic` are **development fixtures**. All values are
invented and invalid; positive labels simulate credentials. They test pipeline
behavior, not real-world detection quality, and must not be called held-out results.
No input fixture needs its imported packages installed because it is never executed.

## CredData pilot

A local obfuscated Python pilot is now prepared. See [experiment instructions](docs/EXPERIMENTS.md#local-creddata-pilot) for provenance and commands, and [project status](docs/PROJECT.md) for results. Downloaded data stays outside Git.

## Framework entry points

The default scans module execution paths. To model recognized `unittest.TestCase`
methods as framework entry points, opt in explicitly:

```bash
python3 main.py datasets/creddata/python-pilot/source --entry-points tests --format json --output output/creddata-scan.json
python3 -m evaluation.run datasets/creddata/python-pilot/manifest.json --entry-points tests --output output/creddata-test-results.json
```

Each test gets fresh setup state. Findings record the assumed test entry point;
reports record the selected mode. This is static modeling, not test execution.
Arbitrary uncalled functions and unrelated classes remain inactive. Imported base
fixtures, pytest discovery, decorators, setUpClass, teardown, general object aliases,
and context-manager side effects are not modeled. Known session types are required
for object-method sinks; a method merely named `connect` or `get` is not enough.
The changed entry-point assumptions must be stated alongside evaluation results.

## Detection evaluation

```bash
python3 -m evaluation.run datasets/creddata/python-pilot/manifest.json --entry-points tests --decision-policy evidence --output output/creddata-evidence.json
```

This is a different decision policy from the flow baseline; reports identify both
policy and entry-point assumptions. See the latest measured results in PROJECT.md.

## Report and continuation

- [Intermediate report](docs/INTERMEDIATE_REPORT.md): draft organized by research question.
- [Submission artifacts](docs/ARTIFACTS.md): separate code/data/log inventory and reproduction.
- [Handoff](HANDOFF.md): current verified state, limitations, and next actions.

Keep reusable code in `evaluation/`, documentation in `docs/`, regression tests in
`tests/`, and generated results in `output/`. Update the handoff after substantive
changes; keep historical experiments in PROJECT.md rather than duplicating them.
