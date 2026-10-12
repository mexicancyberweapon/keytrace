"""Import an already-obfuscated CredData checkout as a Python development pilot."""
import argparse
import ast
import csv
import hashlib
import json
import shutil
import tokenize
from collections import Counter, defaultdict
from pathlib import Path


def prepare(checkout, output):
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError('Output already exists; choose a fresh directory')
    rows = []
    for metadata in sorted((checkout / 'meta').glob('*.csv')):
        with metadata.open(newline='', encoding='utf-8') as handle:
            for row in csv.DictReader(handle):
                if row['FilePath'].lower().endswith('.py'):
                    rows.append(row)
    if not rows:
        raise ValueError('No Python metadata found')
    # Existing scorer matches one labeled candidate per line, so ambiguous spans
    # are explicitly excluded rather than silently conflated.
    groups = defaultdict(list)
    for row in rows:
        groups[(row['FilePath'], int(row['LineStart']))].append(row)
    excluded = []
    cases = []
    files = {}
    validation = {}
    for (relative, line), group in sorted(groups.items()):
        reason = None
        if len(group) > 1:
            reason = 'multiple_candidates_on_line'
        row = group[0]
        if not reason and int(row['LineEnd']) != line:
            reason = 'multiline_candidate'
        if not reason and row['GroundTruth'] not in {'T', 'F', 'X'}:
            reason = 'unsupported_label'
        path = (checkout / relative).resolve()
        if not path.is_relative_to(checkout / 'data'):
            reason = 'invalid_path'
        if not reason and relative not in validation:
            try:
                with tokenize.open(path) as handle:
                    source = handle.read()
                ast.parse(source)
                validation[relative] = (None, len(source.splitlines()))
            except (OSError, UnicodeError, SyntaxError) as exc:
                validation[relative] = (type(exc).__name__, 0)
        if not reason:
            failure, line_count = validation[relative]
            reason = failure or ('invalid_line' if not 1 <= line <= line_count else None)
        if reason:
            excluded.extend({'id': row['Id'], 'reason': reason} for row in group)
            continue
        target = Path('source') / Path(relative).relative_to('data')
        files[target] = path
        cases.append({'id': f"creddata-{row['Id']}", 'path': target.as_posix(), 'line': line,
                      'is_secret': row['GroundTruth'] == 'T', 'purpose': 'unknown',
                      'purpose_labeled': False, 'representation': 'unreviewed',
                      'split': 'development', 'repository_id': row['RepoName'],
                      'original_ground_truth': row['GroundTruth'], 'original_category': row['Category'],
                      'original_start_column': row['ValueStart'], 'original_end_column': row['ValueEnd']})
    if not cases:
        raise ValueError('No compatible cases remain')
    output.mkdir(parents=True)
    for target, path in files.items():
        destination = output / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    for repo in {case['repository_id'] for case in cases}:
        for path in (checkout / 'data' / repo).iterdir():
            if 'licen' in path.name.lower() or 'copying' in path.name.lower():
                destination = output / 'licenses' / repo / path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                if path.is_dir():
                    shutil.copytree(path, destination)
                else:
                    shutil.copy2(path, destination)
    hashes = {target.as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for target, path in files.items()}
    summary = {'input_python_labels': len(rows), 'included_cases': len(cases),
               'positive_cases': sum(case['is_secret'] for case in cases),
               'negative_cases': sum(not case['is_secret'] for case in cases),
               'source_files': len(files), 'repository_count': len({c['repository_id'] for c in cases}),
               'exclusions_by_reason': dict(Counter(row['reason'] for row in excluded)),
               'excluded_cases': excluded, 'source_sha256': hashes,
               'label_policy': 'T positive; F and X negative. Original labels retained. Purpose not annotated.',
               'split_policy': 'Development pilot only; not an independent held-out evaluation.'}
    (output / 'manifest.json').write_text(json.dumps({'description': 'CredData obfuscated Python development pilot', 'cases': cases}, indent=2) + '\n')
    (output / 'import-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checkout', type=Path, help='CredData working copy containing meta/ and obfuscated data/')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    summary = prepare(args.checkout, args.output)
    print(json.dumps({k: v for k, v in summary.items() if k not in {'excluded_cases', 'source_sha256'}}, indent=2))


if __name__ == '__main__':
    main()
