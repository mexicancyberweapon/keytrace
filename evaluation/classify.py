"""Run a user-configured JSON-in/JSON-out model adapter, or import its responses.

The adapter receives one redacted request on stdin and returns the classifier JSON
on stdout. It can wrap a local or hosted model. No provider is selected implicitly.
"""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from classification import validate_prediction


def aggregate(responses):
    predictions = {}
    for response in responses:
        case_id = response['case_id']
        incoming = validate_prediction(response['prediction'])
        current = predictions.get(case_id)
        # Multiple candidates on one labeled line: positive > abstention > negative.
        rank = {True: 2, None: 1, False: 0}
        if current is None or rank[incoming['is_secret']] > rank[current['is_secret']]:
            predictions[case_id] = incoming
    return predictions


def execute(requests, command, timeout):
    responses = []
    for request in requests:
        started = time.monotonic()
        result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise ValueError(f"Adapter failed for {request['candidate_id']} with exit code {result.returncode}; stderr omitted to avoid leaking data")
        prediction = validate_prediction(json.loads(result.stdout))
        responses.append({'case_id': request['case_id'], 'candidate_id': request['candidate_id'],
                          'mode': request['mode'], 'prediction': prediction,
                          'elapsed_seconds': time.monotonic() - started})
    return responses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('requests', type=Path)
    parser.add_argument('--mode', choices=['context', 'hybrid'], required=True)
    parser.add_argument('--model-id', required=True, help='Exact model/version used for this experiment')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--responses', type=Path, help='Import response JSONL instead of running an adapter')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--adapter', nargs=argparse.REMAINDER, help='Executable and arguments; put this last')
    args = parser.parse_args()
    if bool(args.responses) == bool(args.adapter):
        parser.error('Choose exactly one of --responses or --adapter')
    requests = [json.loads(line) for line in args.requests.read_text().splitlines() if line.strip()]
    requests = [r for r in requests if r['mode'] == args.mode]
    expected = {(r['case_id'], r['candidate_id'], r['mode']) for r in requests}
    if len(expected) != len(requests):
        parser.error('Duplicate requests')
    if args.responses:
        responses = [json.loads(line) for line in args.responses.read_text().splitlines() if line.strip()]
        responses = [r for r in responses if r['mode'] == args.mode]
    else:
        responses = execute(requests, args.adapter, args.timeout)
    actual = [(r['case_id'], r['candidate_id'], r['mode']) for r in responses]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        parser.error('Responses must match every request exactly once for the selected mode')
    predictions = aggregate(responses)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(predictions, indent=2) + '\n')
    metadata = {'model_id': args.model_id, 'mode': args.mode, 'request_count': len(requests),
                'requests_sha256': hashlib.sha256(args.requests.read_bytes()).hexdigest(),
                'elapsed_seconds': sum(r.get('elapsed_seconds', 0) for r in responses),
                'execution': 'import' if args.responses else 'adapter'}
    args.output.with_suffix('.metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(f'Validated predictions for {len(predictions)} labeled cases')


if __name__ == '__main__':
    main()
