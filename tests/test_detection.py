import json
import unittest
from test_scanner import scan
from detection import literal_evidence


class DetectionTests(unittest.TestCase):
    def test_unused_credential_still_assessed(self):
        s = scan('def unused():\n password="invented-credential"')
        self.assertFalse(s.findings)
        self.assertTrue(s.assessments()[0]['is_secret'])

    def test_defaults_unpacking_and_dictionary_assignment(self):
        s = scan('def f(password="invented-a", *, passphrase="invented-b"):\n pass\nusername, password = "alice", "invented-c"\nconfig={}\nconfig["password"]="invented-d"')
        self.assertEqual(len(s.candidates), 4)
        self.assertTrue(all(a['is_secret'] for a in s.assessments()))

    def test_comparison_and_lookup_key(self):
        s = scan('if supplied_password == "invented-credential":\n pass\nx=config["password"]')
        self.assertEqual(len(s.candidates), 1)
        self.assertEqual(s.assessments()[0]['line'], 1)

    def test_local_parameter_and_auth_wrapper(self):
        s = scan('from requests.auth import HTTPBasicAuth\ndef f(password):\n pass\nf("invented-a")\ndef unused():\n return HTTPBasicAuth("alice", "invented-b")')
        self.assertEqual(len(s.candidates), 2)

    def test_metadata_and_prompts_not_credential_values(self):
        s = scan('secret_name="database credential"\npassword=getpass("Type your password")\ntoken=os.getenv("SERVICE_TOKEN")')
        self.assertEqual(len(s.candidates), 1)
        self.assertIsNone(s.assessments()[0]['is_secret'])
        for name in ('secret_id', 'token_placement', 'auth_magic'):
            self.assertIsNone(literal_evidence('invented-metadata', name)['is_secret'])

    def test_placeholder_suppressed_even_at_sink(self):
        s = scan('import requests\npassword="${PASSWORD}"\nrequests.get("url",auth=password)')
        self.assertEqual(len(s.findings), 1)
        self.assertFalse(s.assessments()[0]['is_secret'])
        self.assertTrue(s.assessments()[0]['sensitive_use_found'])

    def test_test_filename_does_not_suppress_credential(self):
        s = scan('test_password="invented-credential"')
        self.assertTrue(s.assessments()[0]['is_secret'])
        self.assertFalse(literal_evidence('dummy-value', 'example_password')['is_secret'])

    def test_content_discovery_with_neutral_names_and_redaction(self):
        values = ['-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----',
                  'postgresql://alice:invented-password@localhost/db', 'ghp_' + 'aB3c' * 9]
        for value in values:
            with self.subTest(kind=value[:5]):
                s = scan('x=' + repr(value))
                self.assertTrue(s.assessments()[0]['is_secret'])
                self.assertNotIn(value, json.dumps(s.report()))
                self.assertNotIn('invented-password', s.context(1))

    def test_public_key_and_ordinary_url_not_detected(self):
        s = scan('x="-----BEGIN PUBLIC KEY-----"\ny="https://example.invalid/path"')
        self.assertFalse(s.candidates)

    def test_url_placeholder_and_invalid_url(self):
        self.assertFalse(literal_evidence('postgres://user:${PASSWORD}@localhost/db', '')['is_secret'])
        self.assertIsNone(literal_evidence('https://[malformed', ''))

    def test_bytes_passphrase_and_camelcase_name(self):
        s = scan('passphrase=b"invented-bytes"\nclientSecret="invented-secret"')
        self.assertEqual(len(s.candidates), 2)

    def test_credential_location_needs_review(self):
        for value in ['/etc/keys/service.pem', 'https://example.invalid']:
            self.assertIsNone(literal_evidence(value, 'private_key')['is_secret'])

    def test_neutral_literal_promoted_only_at_sensitive_argument(self):
        s = scan('import requests\nvalue="invented-neutral"\nrequests.get("url",auth=value)')
        self.assertEqual(len(s.findings), 1)
        self.assertTrue(s.assessments()[0]['is_secret'])
        self.assertEqual(s.assessments()[0]['reason'], 'literal_reaches_sensitive_argument')
        self.assertFalse(scan('import requests\nvalue="invented-neutral"\nrequests.get(value)').candidates)

    def test_replacement_literal_has_its_own_provenance(self):
        s = scan('import requests\nvalue="old-value"\nvalue="replacement-value"\nrequests.get("url",auth=value)')
        self.assertEqual([f['source_line'] for f in s.findings], [3])

    def test_neutral_literal_through_function(self):
        s = scan('import requests\ndef send(value):\n requests.get("url",auth=value)\nsend("invented-neutral")')
        self.assertEqual(len(s.findings), 1)
        self.assertEqual(s.findings[0]['source_line'], 4)

    def test_generic_documentation_text_is_not_credential_assignment(self):
        self.assertFalse(scan('doc="The password: a user provided value"').candidates)


if __name__ == '__main__':
    unittest.main()
