import ast
import unittest
from scanner import KeytraceScanner


def scan(source, mode='module'):
    return KeytraceScanner(source=source, entry_points=mode).visit(ast.parse(source))


class CoverageTests(unittest.TestCase):
    def test_unittest_setup_helper_and_default_mode(self):
        source = '''import unittest
import requests
class TestClient(unittest.TestCase):
    def setUp(self):
        self.api_key = "invented"
        self.session = requests.Session()
    def send(self):
        self.session.get("url", headers={"Authorization": self.api_key})
    def test_send(self):
        self.send()
'''
        self.assertFalse(scan(source).findings)
        s = scan(source, 'tests')
        self.assertEqual(len(s.findings), 1)
        self.assertEqual(s.findings[0]['entry_point'], 'unittest:TestClient.test_send')
        self.assertEqual(s.findings[0]['sink'], 'requests.Session.get')

    def test_tests_are_isolated_and_helpers_are_not_entry_points(self):
        s = scan('''from unittest import TestCase
import requests
class Example(TestCase):
    def test_first(self):
        self.api_key="invented"
    def test_second(self):
        requests.get("url",auth=self.api_key)
    def unused(self):
        password="invented"
        requests.get("url",auth=password)
''', 'tests')
        self.assertFalse(s.findings)

    def test_unrelated_class_is_not_test_framework(self):
        s = scan('''import requests
class TestSomething:
    def test_send(self):
        password="invented"
        requests.get("url",auth=password)
''', 'tests')
        self.assertFalse(s.findings)

    def test_inherited_setup(self):
        s = scan('''from unittest import TestCase
import requests
class Base(TestCase):
    def setUp(self):
        self.password="invented"
class Child(Base):
    def test_send(self):
        requests.get("url",auth=self.password)
''', 'tests')
        self.assertEqual(len(s.findings), 1)

    def test_session_auth_and_reassignment(self):
        s = scan('''import requests
password="invented"
s=requests.Session()
s.auth=("user",password)
s.get("url")
s.auth=None
s.get("url")
''')
        self.assertEqual(len(s.findings), 1)
        self.assertEqual(s.findings[0]['line'], 5)

    def test_session_constructor_alone_is_not_use(self):
        s = scan('''from requests_oauthlib import OAuth2Session
client_secret="invented"
s=OAuth2Session(client_secret=client_secret)
''')
        self.assertFalse(s.findings)

    def test_oauth_fetch_inside_with(self):
        s = scan('''from requests_oauthlib import OAuth2Session
s=OAuth2Session()
client_secret="invented"
with context():
    s.fetch_token("url",client_secret=client_secret)
''')
        self.assertEqual(len(s.findings), 1)
        self.assertEqual(s.findings[0]['argument'], 'client_secret')

    def test_basic_auth_and_unpacked_kwargs(self):
        s = scan('''import requests
from requests.auth import HTTPBasicAuth
password=b"invented"
options=dict(auth=HTTPBasicAuth("user",password))
requests.get("url",**options)
''')
        self.assertEqual(len(s.findings), 1)

    def test_known_ssh_object(self):
        s = scan('''import paramiko
s=paramiko.SSHClient()
password="invented"
s.connect("host",password=password)
''')
        self.assertEqual(len(s.findings), 1)

    def test_unknown_object_not_a_sink(self):
        s = scan('''s=UnknownClient()
password="invented"
s.connect("host",password=password)
''')
        self.assertFalse(s.findings)

    def test_session_url_not_credential_use(self):
        s = scan('''import requests
s=requests.Session()
api_key="invented"
s.get(api_key)
''')
        self.assertFalse(s.findings)

    def test_dictionary_get(self):
        s = scan('''import requests
credentials={"password":"invented"}
x=credentials.get("password")
requests.get("url",auth=x)
''')
        self.assertEqual(len(s.findings), 1)

    def test_replacing_session_clears_old_attributes(self):
        s = scan('import requests\ns=requests.Session()\npassword="invented"\ns.auth=password\ns=requests.Session()\nrequests.get("url",auth=s.auth)\ns.get("url")\n')
        self.assertFalse(s.findings)

    def test_setup_helper_clears_session_state(self):
        s = scan('import unittest\nimport requests\nclass Example(unittest.TestCase):\n def setUp(self):\n  self.s=requests.Session()\n  self.password="invented"\n  self.s.auth=self.password\n def reset(self):\n  self.s=requests.Session()\n def test_clean(self):\n  self.reset()\n  requests.get("url",auth=self.s.auth)\n  self.s.get("url")\n', 'tests')
        self.assertFalse(s.findings)

    def test_bad_entry_point_mode(self):
        with self.assertRaises(ValueError):
            scan('', 'everything')


if __name__ == '__main__':
    unittest.main()
