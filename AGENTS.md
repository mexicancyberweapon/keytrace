# Repository working agreements

- Read `HANDOFF.md` before substantial work. Update it after meaningful code,
  experiment, dataset, or report changes, including verified validation and next steps.
  Keep it concise; put experiment history in `docs/PROJECT.md`.
- Keep reusable experiment tools in `evaluation/`, documentation in `docs/`, and
  generated outputs in `output/`. Avoid duplicate status documents and setup clutter.
- Preserve `output/intermediate/` submission evidence and `datasets/creddata/` sources,
  labels, provenance, and licenses during cleanup, even though they are ignored by Git.
- Never invent test/model/baseline results or change dataset labels to improve scores.
  Do not print credential values or transmit raw datasets to hosted models.
- Prefer `PYTHONDONTWRITEBYTECODE=1` for Python validation to avoid cache clutter.
