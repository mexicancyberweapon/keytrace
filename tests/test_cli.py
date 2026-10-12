import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def command(self, *arguments):
        return subprocess.run([sys.executable, *arguments], cwd=ROOT, text=True, capture_output=True)

    def test_scan_json_and_missing_path(self):
        good = self.command('main.py', 'datasets/synthetic/header_alias.py', '--format', 'json')
        self.assertEqual(good.returncode, 0, good.stderr)
        result = json.loads(good.stdout)
        self.assertEqual(len(result['files'][0]['findings']), 1)
        self.assertNotIn('synthetic-credential', good.stdout)
        missing = self.command('main.py', '/nonexistent-keytrace-input', '--format', 'json')
        self.assertEqual(missing.returncode, 1)
        self.assertTrue(json.loads(missing.stdout)['errors'])

    def test_offline_experiment_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            manifest = 'datasets/synthetic/manifest.json'
            initial = self.command('-m', 'evaluation.run', manifest, '--output', str(out/'static.json'), '--requests', str(out/'requests.jsonl'))
            self.assertEqual(initial.returncode, 0, initial.stderr)
            requests = [json.loads(line) for line in (out/'requests.jsonl').read_text().splitlines()]
            responses = [{**{key: r[key] for key in ('case_id', 'candidate_id', 'mode')}, 'prediction': {'is_secret': None, 'purpose': 'unknown', 'rationale': 'Protocol test only'}} for r in requests]
            (out/'responses.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in responses))
            for mode in ('context', 'hybrid'):
                classified = self.command('-m', 'evaluation.classify', str(out/'requests.jsonl'), '--mode', mode, '--model-id', 'mock-not-a-model', '--responses', str(out/'responses.jsonl'), '--output', str(out/f'{mode}.json'))
                self.assertEqual(classified.returncode, 0, classified.stderr)
                scored = self.command('-m', 'evaluation.run', manifest, '--predictions', str(out/f'{mode}.json'), '--output', str(out/f'{mode}-results.json'))
                self.assertEqual(scored.returncode, 0, scored.stderr)
                result = json.loads((out/f'{mode}-results.json').read_text())
                self.assertGreater(result['metrics']['abstained'], 0)
                self.assertEqual(result['metrics']['tp'], 0)


if __name__ == '__main__':
    unittest.main()
