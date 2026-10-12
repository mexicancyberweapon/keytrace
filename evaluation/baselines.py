"""Normalize Gitleaks JSON or TruffleHog filesystem JSONL against labeled locations."""
import argparse
import json
from pathlib import Path
from evaluation.run import load_dataset


def normalize(tool, records, labels, root):
    root = Path(root).resolve()
    locations = {(label['path'], label['line']): label['id'] for label in labels}
    predictions = {label['id']: {'is_secret': False, 'purpose': 'unknown'} for label in labels}
    unmatched = []
    for record in records:
        if tool == 'gitleaks':
            filename, line = record['File'], record['StartLine']
        else:
            metadata = record['SourceMetadata']['Data'].get('Filesystem')
            if not metadata:
                raise ValueError('Only TruffleHog filesystem reports are supported')
            filename, line = metadata['file'], metadata['line']
        path = Path(filename)
        if path.is_absolute():
            try:
                path = path.resolve().relative_to(root)
            except ValueError:
                unmatched.append({'file': str(path), 'line': int(line)})
                continue
        normalized = path.as_posix()
        case_id = locations.get((normalized, int(line)))
        if case_id:
            predictions[case_id]['is_secret'] = True
        else:
            unmatched.append({'file': normalized, 'line': int(line)})
    return predictions, unmatched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', choices=['gitleaks', 'trufflehog'])
    parser.add_argument('manifest', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    labels = load_dataset(args.manifest)
    content = args.report.read_text()
    records = json.loads(content) if args.tool == 'gitleaks' else [json.loads(line) for line in content.splitlines() if line.strip()]
    predictions, unmatched = normalize(args.tool, records, labels, args.manifest.parent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(predictions, indent=2) + '\n')
    args.output.with_suffix('.unmatched.json').write_text(json.dumps(unmatched, indent=2) + '\n')
    print(f'Normalized {len(records)} findings; {len(unmatched)} unmatched locations. Review unmatched findings before comparison.')


if __name__ == '__main__':
    main()
