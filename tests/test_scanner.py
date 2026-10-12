import ast
import json
import tempfile
import unittest
from pathlib import Path
from scanner import KeytraceScanner, scan_path


def scan(source):
    return KeytraceScanner(source=source).visit(ast.parse(source))


class FlowTests(unittest.TestCase):
    def test_direct_and_alias(self):
        s = scan('import requests as r\napi_key="dummy-secret"\ntoken=api_key\nh={"Authorization":token}\nr.get("url",headers=h)')
        self.assertEqual(len(s.findings), 1)
        self.assertEqual(s.findings[0]['sink'], 'requests.get')
        self.assertNotIn('dummy-secret', json.dumps(s.report()))

    def test_function_argument_and_return(self):
        s = scan('''import requests

def prepare(value):
    return "Bearer " + value

def send(value):
    headers = {"Authorization": prepare(value)}
    requests.get("url", headers=headers)

api_key = "dummy-secret"
send(api_key)
''')
        self.assertEqual(len(s.findings), 1)
        kinds = [step['kind'] for step in s.findings[0]['trace']]
        self.assertIn('parameter', kinds)
        self.assertIn('return', kinds)

    def test_reassignment(self):
        s = scan('import requests\napi_key="dummy-secret"\nh={"Authorization":api_key}\nh={}\nrequests.get("url",headers=h)')
        self.assertFalse(s.findings)

    def test_clean_alias_reassignment(self):
        s = scan('import requests\napi_key="dummy-secret"\nx=api_key\nx=None\nrequests.get("url",auth=x)')
        self.assertFalse(s.findings)

    def test_url_not_authentication(self):
        self.assertFalse(scan('import requests\napi_key="dummy-secret"\nrequests.get(api_key)').findings)

    def test_uncalled_function(self):
        self.assertFalse(scan('import requests\ndef unused():\n api_key="dummy-secret"\n requests.get("url",auth=api_key)').findings)

    def test_caller_locals_do_not_leak(self):
        s = scan('''import requests
x = None
def inner():
    requests.get("url", auth=x)
def outer():
    api_key = "dummy-secret"
    x = api_key
    inner()
outer()
''')
        self.assertFalse(s.findings)

    def test_keyword_only_and_defaults(self):
        s = scan('import requests\ndef send(*, token="dummy-secret"):\n requests.get("url",auth=token)\nsend()')
        self.assertEqual(len(s.findings), 1)

    def test_dictionary_update_and_fstring(self):
        s = scan('import requests\napi_key="dummy-secret"\nh={}\nh["Authorization"]=f"Bearer {api_key}"\nrequests.get("url",headers=h)')
        self.assertEqual(len(s.findings), 1)

    def test_branch_and_early_return(self):
        s = scan('''import requests
api_key="dummy-secret"
def choose(value, condition):
    if condition:
        return value
    return None
x=choose(api_key, True)
requests.get("url",auth=x)
''')
        self.assertEqual(len(s.findings), 1)

    def test_both_branches_clear(self):
        s = scan('import requests\napi_key="dummy-secret"\nx=api_key\nif condition:\n x=None\nelse:\n x=None\nrequests.get("url",auth=x)')
        self.assertFalse(s.findings)

    def test_recursion_is_bounded(self):
        s = scan('def recurse(x):\n return recurse(x)\napi_key="dummy-secret"\nrecurse(api_key)')
        self.assertTrue(any('Recursion' in warning for warning in s.warnings))

    def test_other_sink_categories(self):
        s = scan('import psycopg2\nimport hmac\npassword="dummy-db"\nprivate_key="dummy-key"\npsycopg2.connect(password=password)\nhmac.new(private_key)')
        self.assertEqual({f['purpose'] for f in s.findings}, {'database', 'cryptographic_key'})

    def test_context_redacts_all_literals_and_comments(self):
        source = 'import requests\napi_key="dummy-secret" # another-secret\nurl="private-url"\nrequests.get(url,auth=api_key)'
        s = scan(source)
        context = s.context(2)
        for secret in ['dummy-secret', 'another-secret', 'private-url']:
            self.assertNotIn(secret, context)
        self.assertIn('requests.get', context)

    def test_shadowed_import_is_not_a_known_sink(self):
        s = scan('import requests\napi_key="dummy"\nrequests=None\nrequests.get("url",auth=api_key)')
        self.assertFalse(s.findings)
        self.assertTrue(s.warnings)

    def test_two_calls_do_not_share_parameters(self):
        s = scan('import requests\ndef send(value):\n requests.get("url",auth=value)\napi_key="dummy"\nsend(api_key)\nsend(None)')
        self.assertEqual(len(s.findings), 1)

    def test_tuple_auth_and_string_method(self):
        s = scan('import requests\npassword="dummy"\nx=password.encode()\nrequests.get("url",auth=("user",x))')
        self.assertEqual(len(s.findings), 1)

    def test_uncalled_candidate_is_still_discovered(self):
        s = scan('def unused():\n api_key="dummy"')
        self.assertEqual(len(s.candidates), 1)
        self.assertFalse(s.findings)

    def test_multiline_and_fstring_context_redaction(self):
        source = 'api_key="""first-secret\nsecond-secret"""\nvalue=f"hidden-prefix{api_key}"'
        s = scan(source)
        context = s.context(2)
        for secret in ('first-secret', 'second-secret', 'hidden-prefix'):
            self.assertNotIn(secret, context)

    def test_directory_parse_error_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'good.py').write_text('api_key="dummy"')
            (root / 'bad.py').write_text('def (')
            scanners, errors = scan_path(root)
            self.assertEqual(len(scanners), 1)
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]['error'], 'SyntaxError')


if __name__ == '__main__':
    unittest.main()
