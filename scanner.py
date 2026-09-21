import ast
import math
from collections import defaultdict

SUSPICIOUS_NAMES = {
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "access_key",
    "private_key",
    "auth",
}

SENSITIVE_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
}


def get_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_name(node.value)

        if parent:
            return f"{parent}.{node.attr}"

        return node.attr

    return None


class KeytraceScanner(ast.NodeVisitor):
    def __init__(self):
        self.candidates = {}
        self.flows = defaultdict(list)
        self.findings = []

    def is_suspicious_name(self, name):
        name = name.lower()
        return any(word in name for word in SUSPICIOUS_NAMES)

    def visit_Assign(self, node):
        if len(node.targets) != 1:
            self.generic_visit(node)
            return

        target = node.targets[0]

        if not isinstance(target, ast.Name):
            self.generic_visit(node)
            return

        target_name = target.id

        # api_key = "abc123"
        if isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                if self.is_suspicious_name(target_name):
                    self.candidates[target_name] = {
                        "value": node.value.value,
                        "source": target_name,
                        "line": node.lineno,
                    }

        # token = api_key
        elif isinstance(node.value, ast.Name):
            source_name = node.value.id

            if source_name in self.candidates:
                self.candidates[target_name] = self.candidates[source_name]
                self.flows[source_name].append(target_name)

        # headers = {"Authorization": token}
        elif isinstance(node.value, ast.Dict):
            for key, value in zip(node.value.keys, node.value.values):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and isinstance(value, ast.Name)
                ):
                    source_name = value.id

                    if (
                        "authorization" in key.value.lower()
                        and source_name in self.candidates
                    ):
                        self.candidates[target_name] = self.candidates[source_name]
                        self.flows[source_name].append(target_name)

        self.generic_visit(node)

    def visit_Call(self, node):
        function_name = get_name(node.func)

        if function_name not in SENSITIVE_SINKS:
            self.generic_visit(node)
            return

        variables = []

        for arg in node.args:
            if isinstance(arg, ast.Name):
                variables.append(arg.id)

        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Name):
                variables.append(keyword.value.id)

        for variable in variables:
            if variable in self.candidates:
                self.flows[variable].append(function_name)

                candidate = self.candidates[variable]

                self.findings.append({
                    "candidate": candidate["value"],
                    "source": candidate["source"],
                    "sink": function_name,
                    "line": node.lineno,
                })

        self.generic_visit(node)


def scan_file(filename):
    with open(filename, "r") as f:
        source = f.read()

    tree = ast.parse(source)

    scanner = KeytraceScanner()
    scanner.visit(tree)

    return scanner