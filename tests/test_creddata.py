import csv
import json
import tempfile
import unittest
from pathlib import Path
from evaluation.creddata import prepare
from evaluation.metrics import score
from evaluation.run import load_dataset


class CredDataTests(unittest.TestCase):
    def test_import_preserves_labels_and_reports_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / 'upstream'
            (checkout / 'meta').mkdir(parents=True)
            source = checkout / 'data' / 'repo' / 'src' / 'file.py'
            source.parent.mkdir(parents=True)
            source.write_text('api_key="invented"\nx="placeholder"\ny="example"\na,b="one","two"\nz="multiline"\n')
            (checkout / 'data/repo/LICENSE').write_text('Fixture license')
            fields = ['Id','FileID','RepoName','FilePath','LineStart','LineEnd','GroundTruth','Category','ValueStart','ValueEnd']
            with (checkout / 'meta/repo.csv').open('w') as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for identity, line, end, label in [('1',1,1,'T'),('2',2,2,'F'),('3',3,3,'X'),('4',4,4,'T'),('5',4,4,'F'),('6',5,6,'T')]:
                    writer.writerow(dict(zip(fields, [identity,'file','repo','data/repo/src/file.py',line,end,label,'Token',0,8])))
            output = root / 'prepared'
            summary = prepare(checkout, output)
            self.assertEqual(summary['included_cases'], 3)
            self.assertEqual(summary['positive_cases'], 1)
            self.assertEqual(summary['exclusions_by_reason'], {'multiple_candidates_on_line':2, 'multiline_candidate':1})
            cases = load_dataset(output / 'manifest.json')
            self.assertEqual([c['original_ground_truth'] for c in cases], ['T','F','X'])
            self.assertTrue(all(not c['purpose_labeled'] for c in cases))
            self.assertIsNone(score(cases, {})['purpose_accuracy'])
            self.assertTrue((output / 'licenses/repo/LICENSE').exists())
            self.assertNotIn('invented', (output / 'manifest.json').read_text())
            with self.assertRaises(ValueError):
                prepare(checkout, output)

    def test_unannotated_purpose_does_not_inflate_accuracy(self):
        cases = [{'id':'a','is_secret':True,'purpose':'unknown','purpose_labeled':False},
                 {'id':'b','is_secret':False,'purpose':'non_secret'}]
        metrics = score(cases, {'a':{'is_secret':True,'purpose':'unknown'}, 'b':{'is_secret':False,'purpose':'unknown'}})
        self.assertEqual(metrics['purpose_labeled_n'], 1)
        self.assertEqual(metrics['purpose_accuracy'], 0)


if __name__ == '__main__':
    unittest.main()
