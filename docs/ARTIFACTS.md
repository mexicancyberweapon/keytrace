# Intermediate report supporting artifacts

The report document is `docs/INTERMEDIATE_REPORT.md`. Generated files are in
`output/intermediate/`. These are separate experimental
artifacts, not LLM results. Run from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m evaluation.capture
```

Requires the retained local CredData pilot and standard-library Python environment.
This command refreshes the files below. Archive a dated copy before a later rerun
if preserving the original submission is necessary.

- `synthetic-flow.json`, `synthetic-evidence.json`: all 20 synthetic cases.
- `creddata-flow.json`, `creddata-evidence.json`: all 423 eligible pilot cases.
- `summary.json`: metrics, dataset fingerprints, and flow-coverage counts.
- `tests.log`: verbose output from the complete regression suite.
- `run-metadata.json`: timestamp, Python/platform, source hashes, Git status and HEAD.
  The working tree is uncommitted: HEAD alone does not reproduce this implementation.
- `evaluation/capture.py`: versionable regeneration workflow; never executes dataset code.

Submit the codebase separately with the report and these logs. Include `main.py`,
`scanner.py`, `detection.py`, `classification.py`, `evaluation/`, `tests/`, and the
synthetic dataset. Include README and experiment documentation for reproduction.
Do not include `.git`, bytecode caches, unrelated local files, or model downloads.

The prepared external dataset is retained separately at
`datasets/creddata/python-pilot/` (sources, manifest, import summary, and licenses),
with upstream metadata, LICENSE, and provenance under `datasets/creddata/`.
It is ignored by Git, as is this output folder. A Git-only submission will omit both.
For course dataset delivery, use the permitted course channel and retain licenses;
do not publish the source dataset simply to make a public repository self-contained.
No raw dataset values are included in the generated evaluation reports.

Before hand-in, confirm named task owners, individual contributions, deadline,
required document format, and whether teammates have independent baseline results.
No fabricated LLM results or percentage-completion estimate is included.
