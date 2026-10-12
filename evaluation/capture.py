"""Run from this repository: python3 -m evaluation.capture."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/intermediate'
OUT.mkdir(parents=True, exist_ok=True)
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
from evaluation.run import run
from scanner import scan_file

env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
completed = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], env=env, capture_output=True, text=True)
(OUT/'tests.log').write_text(completed.stdout + completed.stderr)
if completed.returncode:
    raise SystemExit('Tests failed; inspect tests.log')
summaries = {}
for name, manifest in [('synthetic', 'datasets/synthetic/manifest.json'), ('creddata', 'datasets/creddata/python-pilot/manifest.json')]:
    for policy in ('flow', 'evidence'):
        report, _ = run(manifest, entry_points='tests', decision_policy=policy)
        (OUT/f'{name}-{policy}.json').write_text(json.dumps(report, indent=2)+'\n')
        summaries[f'{name}-{policy}'] = {'metrics':report['metrics'], 'candidate_generation_recall':report['candidate_generation_recall'], 'dataset_sha256':report['dataset_sha256']}
    labels = json.loads(Path(manifest).read_text())['cases']
    scanners = {p:scan_file(Path(manifest).parent/p, p, entry_points='tests') for p in sorted({l['path'] for l in labels})}
    locations = {(p,f['source_line']) for p,s in scanners.items() for f in s.findings}
    summaries[name+'-coverage'] = {'files':len(scanners), 'files_with_warnings':sum(bool(s.warnings) for s in scanners.values()), 'labeled_locations_with_flow':sum((l['path'],l['line']) in locations for l in labels)}
(OUT/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
paths = sorted([*ROOT.glob('*.py'), *ROOT.glob('evaluation/*.py'), *ROOT.glob('tests/*.py'), *ROOT.glob('datasets/synthetic/*')])
hashes = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
metadata = {'recorded_at_utc':datetime.now(timezone.utc).isoformat(), 'python':platform.python_version(), 'platform':platform.platform(), 'command':'PYTHONDONTWRITEBYTECODE=1 python3 -m evaluation.capture', 'entry_points':'tests', 'source_sha256':hashes, 'git_head':subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True).stdout.strip(), 'git_status':subprocess.run(['git','status','--short'],capture_output=True,text=True).stdout, 'note':'Working tree is uncommitted; source hashes identify evaluated files. No LLM or external scanner was run.'}
(OUT/'run-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
print(json.dumps({k:v for k,v in summaries.items() if k.endswith('coverage')},indent=2))
print('Saved four reports, summary, test log, and reproducibility metadata.')
