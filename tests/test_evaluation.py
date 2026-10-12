import json
import sys
import tempfile
import unittest
from pathlib import Path
from classification import build_request, validate_prediction
from evaluation.baselines import normalize
from evaluation.classify import aggregate, execute
from evaluation.metrics import score
from evaluation.run import run
from test_scanner import scan


class EvaluationTests(unittest.TestCase):
    def test_metrics_and_missing_predictions(self):
        labels = [{'id': str(i), 'is_secret': secret, 'purpose': 'unknown'} for i, secret in enumerate([True, True, False, False])]
        result = score(labels, {'0': {'is_secret': True}, '2': {'is_secret': True}})
        self.assertEqual([result[k] for k in ('tp', 'fp', 'tn', 'fn')], [1, 1, 1, 1])
        self.assertEqual(result['f1'], 0.5)
        self.assertEqual(result['missing'], 2)
        self.assertIsNone(score([], {})['precision'])

    def test_modes_and_redaction(self):
        s = scan('import requests\napi_key="never-export-this"\nrequests.get("private-url",auth=api_key)')
        candidate = next(iter(s.candidates.values()))
        context = build_request(s, candidate, 'context')
        hybrid = build_request(s, candidate, 'hybrid')
        self.assertNotIn('never-export-this', json.dumps(hybrid))
        self.assertNotIn('private-url', json.dumps(context))
        self.assertNotIn('flows', json.loads(context['messages'][1]['content']))
        self.assertIn('flows', json.loads(hybrid['messages'][1]['content']))

    def test_response_validation(self):
        for value in [None, {}, {'is_secret': 1, 'purpose': 'unknown', 'rationale': ''}, {'is_secret': True, 'purpose': 'made-up', 'rationale': ''}]:
            with self.assertRaises(ValueError):
                validate_prediction(value)
        self.assertIsNone(validate_prediction({'is_secret': None, 'purpose': 'unknown', 'rationale': 'Uncertain'})['is_secret'])

    def test_baseline_normalization_and_duplicates(self):
        labels = [{'id': 'a', 'path': 'a.py', 'line': 2}, {'id': 'b', 'path': 'b.py', 'line': 1}]
        records = [{'File': 'a.py', 'StartLine': 2, 'Secret': 'do-not-copy'}] * 2
        predictions, unmatched = normalize('gitleaks', records, labels, '/tmp')
        self.assertTrue(predictions['a']['is_secret'])
        self.assertFalse(predictions['b']['is_secret'])
        self.assertFalse(unmatched)
        self.assertNotIn('do-not-copy', json.dumps(predictions))
        predictions, _ = normalize('trufflehog', [{'SourceMetadata': {'Data': {'Filesystem': {'file': '/tmp/a.py', 'line': 2}}}}], labels, '/tmp')
        self.assertTrue(predictions['a']['is_secret'])

    def test_mock_adapter_contract(self):
        # This only validates the subprocess protocol, never claims model accuracy.
        with tempfile.TemporaryDirectory() as directory:
            adapter = Path(directory) / 'mock.py'
            adapter.write_text('import json,sys\nrequest=json.load(sys.stdin)\nprint(json.dumps({"is_secret":None,"purpose":"unknown","rationale":"mock"}))\n')
            responses = execute([{'case_id': 'a', 'candidate_id': 'c', 'mode': 'context'}], [sys.executable, str(adapter)], 2)
            self.assertIsNone(aggregate(responses)['a']['is_secret'])

    def test_synthetic_evaluation_reproducible(self):
        manifest = Path(__file__).resolve().parents[1] / 'datasets/synthetic/manifest.json'
        first, requests = run(manifest)
        second, _ = run(manifest)
        self.assertEqual(first, second)
        self.assertEqual(first['metrics']['n'], 20)
        self.assertTrue(requests)
        self.assertNotIn('synthetic-credential', json.dumps(requests))
        self.assertTrue(all('is_secret' not in request for request in requests))

    def test_evidence_policy_and_unknown_policy(self):
        manifest = Path(__file__).resolve().parents[1] / 'datasets/synthetic/manifest.json'
        result, _ = run(manifest, decision_policy='evidence')
        self.assertEqual(result['mode'], 'static_literal_evidence_heuristic')
        cases = {case['id']: case['prediction'] for case in result['cases']}
        self.assertTrue(cases['unused_secret']['is_secret'])
        self.assertTrue(cases['neutral_name']['is_secret'])
        self.assertFalse(cases['test_fixture']['is_secret'])
        with self.assertRaises(ValueError):
            run(manifest, decision_policy='invalid')


if __name__ == '__main__':
    unittest.main()
