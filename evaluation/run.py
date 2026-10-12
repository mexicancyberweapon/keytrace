"""Run static evaluation, export LLM requests, or score normalized predictions."""
import argparse
import hashlib
import json
import tokenize
from pathlib import Path
from classification import build_request
from evaluation.metrics import score, divide
from scanner import scan_file, PURPOSES


def load_dataset(manifest):
    manifest = Path(manifest).resolve()
    labels = json.loads(manifest.read_text())['cases']
    seen = set()
    locations = set()
    for label in labels:
        if label['id'] in seen or (label['path'], label['line']) in locations:
            raise ValueError("Dataset IDs and file/line locations must be unique")
        seen.add(label['id'])
        locations.add((label['path'], label['line']))
        if type(label['is_secret']) is not bool or label['purpose'] not in PURPOSES:
            raise ValueError("Invalid ground truth label")
        path = (manifest.parent / label['path']).resolve()
        if not path.is_relative_to(manifest.parent):
            raise ValueError("Dataset source must be within the manifest directory")
        if not path.is_file() or type(label['line']) is not int:
            raise ValueError("Invalid source location")
        with tokenize.open(path) as source:
            if not 1 <= label['line'] <= len(source.read().splitlines()):
                raise ValueError("Invalid source location")
    return labels


def run(manifest, predictions=None, entry_points="module", decision_policy="flow"):
    if decision_policy not in {'flow', 'evidence'}:
        raise ValueError('decision_policy must be flow or evidence')
    manifest = Path(manifest)
    labels = load_dataset(manifest)
    scanners = {path: scan_file(manifest.parent / path, path, entry_points=entry_points) for path in sorted({label['path'] for label in labels})}
    static = {}
    requests = []
    discovered = set()
    for label in labels:
        scanner = scanners[label['path']]
        candidates = [c for c in scanner.candidates.values() if c['line'] == label['line']]
        if candidates:
            discovered.add(label['id'])
        findings = [f for f in scanner.findings if f['source_line'] == label['line']]
        static[label['id']] = {'is_secret': bool(findings), 'purpose': findings[0]['purpose'] if findings else 'unknown'}
        if decision_policy == 'evidence':
            assessments = [a for a in scanner.assessments() if a['line'] == label['line']]
            chosen = next((a for a in assessments if a['is_secret'] is True),
                          next((a for a in assessments if a['is_secret'] is None), None))
            if chosen is None and assessments:
                chosen = assessments[0]
            static[label['id']] = ({'is_secret': chosen['is_secret'], 'purpose': chosen['purpose'], 'reason': chosen['reason']}
                                   if chosen else {'is_secret': False, 'purpose': 'unknown', 'reason': 'no_candidate'})
        for candidate in candidates:
            for mode in ('context', 'hybrid'):
                request = build_request(scanner, candidate, mode)
                request['case_id'] = label['id']
                requests.append(request)
    if predictions is not None:
        if not isinstance(predictions, dict):
            raise ValueError("Predictions must be an object keyed by case ID")
        for prediction in predictions.values():
            if not isinstance(prediction, dict) or 'is_secret' not in prediction:
                raise ValueError("Each prediction must include is_secret")
            if prediction['is_secret'] is not None and type(prediction['is_secret']) is not bool:
                raise ValueError("is_secret must be boolean or null")
            if prediction.get('purpose', 'unknown') not in PURPOSES:
                raise ValueError("Unknown purpose label")
        unknown = set(predictions) - {label['id'] for label in labels}
        if unknown:
            raise ValueError(f"Predictions have unknown case IDs: {sorted(unknown)}")
    selected = static if predictions is None else predictions
    positive_ids = {label['id'] for label in labels if label['is_secret']}
    digest = hashlib.sha256(manifest.read_bytes())
    for path in sorted(scanners):
        digest.update(path.encode())
        digest.update((manifest.parent / path).read_bytes())
    report = {'schema_version': 1, 'entry_points': entry_points, 'decision_policy': decision_policy, 'dataset_sha256': digest.hexdigest(),
              'mode': ('static_sensitive_use_heuristic' if decision_policy == 'flow' else 'static_literal_evidence_heuristic') if predictions is None else 'imported_predictions',
              'metrics': score(labels, selected),
              'candidate_generation_recall': divide(len(discovered & positive_ids), len(positive_ids)),
              'conditional_metrics_on_discovered_candidates': score([l for l in labels if l['id'] in discovered], selected),
              'cases': [{'id': l['id'], 'actual': {'is_secret': l['is_secret'], 'purpose': l['purpose']},
                         'candidate_found': l['id'] in discovered, 'prediction': selected.get(l['id'])} for l in labels],
              'warnings': {path: s.warnings for path, s in scanners.items() if s.warnings}}
    return report, requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--predictions', type=Path, help='Normalized case-ID to prediction JSON object')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--requests', type=Path, help='Export redacted context and hybrid requests as JSONL')
    parser.add_argument("--entry-points", choices=["module", "tests"], default="module")
    parser.add_argument("--decision-policy", choices=["flow", "evidence"], default="flow", help="Keep the original flow baseline or classify literal evidence independently of call reachability")
    args = parser.parse_args()
    predictions = json.loads(args.predictions.read_text()) if args.predictions else None
    report, requests = run(args.manifest, predictions, entry_points=args.entry_points, decision_policy=args.decision_policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    if args.requests:
        args.requests.parent.mkdir(parents=True, exist_ok=True)
        args.requests.write_text(''.join(json.dumps(r) + '\n' for r in requests))
    print(json.dumps(report['metrics'], indent=2))


if __name__ == '__main__':
    main()
