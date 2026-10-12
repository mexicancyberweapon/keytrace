"""Bounded, same-module Python credential-flow analysis. Never executes input code."""
import ast
import copy
import hashlib
import tokenize
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from detection import credential_name, literal_evidence

AUTH_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "api-key"}
HTTP_MODULES = {"requests", "httpx"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
PURPOSES = {"authentication", "api_token", "database", "cryptographic_key", "test_example", "non_secret", "unknown"}


def get_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


@dataclass
class Value:
    traces: dict = field(default_factory=dict)
    fields: dict = field(default_factory=dict)
    types: frozenset = field(default_factory=frozenset)

    def all_traces(self):
        result = dict(self.traces)
        for value in self.fields.values():
            result.update(value.all_traces())
        return result


def merge(*values):
    result = Value()
    for value in values:
        result.types = result.types | value.types
        result.traces.update(value.traces)
        for key, item in value.fields.items():
            result.fields[key] = merge(result.fields.get(key, Value()), item)
    return result


class KeytraceScanner:
    def __init__(self, filename="<memory>", source="", max_depth=12, entry_points="module"):
        if entry_points not in {"module", "tests"}:
            raise ValueError("entry_points must be module or tests")
        self.entry_points = entry_points
        self.entry_point = "module"
        self.current_class = None
        self.classes = {}
        self.filename = filename
        self.source = source
        self.max_depth = max_depth
        self.candidates = {}
        self.literal_sources = {}
        self.flows = defaultdict(list)
        self.findings = []
        self.warnings = []
        self.env = {}
        self.functions = {}
        self.aliases = {}
        self.active = []
        self._findings = set()

    def warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def is_suspicious_name(self, name):
        return credential_name(name)

    def step(self, value, name, line, kind="assignment"):
        value = copy.deepcopy(value)
        for cid, trace in value.traces.items():
            previous = trace[-1]["name"]
            if name not in self.flows[previous]:
                self.flows[previous].append(name)
            value.traces[cid] = trace + [{"name": name, "line": line, "kind": kind}]
        value.fields = {key: self.step(item, f"{name}[{key!r}]", line, kind) for key, item in value.fields.items()}
        return value

    def literal(self, node, hint):
        if not isinstance(node.value, (str, bytes)) or not node.value:
            return Value()
        evidence = literal_evidence(node.value, hint)
        cid = hashlib.sha256(f"{self.filename}:{node.lineno}:{node.col_offset}".encode()).hexdigest()[:16]
        self.literal_sources[cid] = (node, hint)
        if evidence is not None:
            self.candidates.setdefault(cid, {"id": cid, "file": self.filename, "line": node.lineno,
                                        "column": node.col_offset, "source": hint or "literal", "value": "[REDACTED]",
                                        "assessment": evidence})
        return Value({cid: [{"name": hint or "literal", "line": node.lineno, "kind": "source"}]})

    def visit(self, tree):
        self.functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.discover(tree)
        self.classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
        self.block(tree.body, self.env)
        if self.entry_points == "tests":
            self.analyze_tests()
        return self

    def expr(self, node, env, hint=""):
        if node is None:
            return Value()
        if isinstance(node, ast.Constant):
            return self.literal(node, hint)
        if isinstance(node, ast.Name):
            return copy.deepcopy(env.get(node.id, Value()))
        if isinstance(node, ast.Dict):
            fields = {}
            for key, val in zip(node.keys, node.values):
                if key is None:
                    fields.update(self.expr(val, env).fields)
                elif isinstance(key, ast.Constant):
                    fields[key.value] = self.expr(val, env, str(key.value))
                else:
                    self.warn("Dynamic dictionary keys are not tracked precisely.")
                    self.expr(val, env)
            return Value(fields=fields)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return Value(fields={i: self.expr(item, env, ("password" if i == 1 else "") if hint == "auth" else hint) for i, item in enumerate(node.elts)})
        if isinstance(node, ast.Subscript):
            value = self.expr(node.value, env)
            if isinstance(node.slice, ast.Constant):
                return copy.deepcopy(value.fields.get(node.slice.value, Value()))
            self.warn("Dynamic indexing is approximated by merging all container values.")
            return Value(value.all_traces())
        if isinstance(node, ast.BinOp):
            values = [self.expr(node.left, env, hint), self.expr(node.right, env, hint)]
            return Value(merge(*values).all_traces())
        if isinstance(node, ast.JoinedStr):
            return Value(merge(*(self.expr(item, env, hint) for item in node.values)).all_traces())
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value, env, hint)
        if isinstance(node, (ast.IfExp, ast.BoolOp)):
            parts = node.values if isinstance(node, ast.BoolOp) else [node.body, node.orelse]
            return merge(*(self.expr(part, env, hint) for part in parts))
        if isinstance(node, ast.Call):
            return self.call(node, env)
        if isinstance(node, ast.Attribute):
            name = get_name(node)
            if name in env:
                return copy.deepcopy(env[name])
            return copy.deepcopy(self.expr(node.value, env).fields.get(node.attr, Value()))
        else:
            self.warn(f"Unsupported expression: {type(node).__name__}.")
        return Value()

    def assign(self, target, value, env, line):
        if isinstance(target, (ast.Name, ast.Attribute)) and get_name(target):
            prefix = get_name(target) + "."
            for key in list(env):
                if key.startswith(prefix):
                    del env[key]
        if isinstance(target, ast.Name):
            env[target.id] = self.step(value, target.id, line)
        elif isinstance(target, ast.Attribute) and get_name(target):
            name = get_name(target)
            env[name] = self.step(value, name, line)
            parent = get_name(target.value)
            if parent in env:
                env[parent].fields[target.attr] = self.step(value, name, line)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and isinstance(target.slice, ast.Constant):
            container = copy.deepcopy(env.get(target.value.id, Value()))
            container.fields[target.slice.value] = self.step(value, ast.unparse(target), line)
            env[target.value.id] = container
        elif isinstance(target, (ast.Tuple, ast.List)):
            for i, item in enumerate(target.elts):
                self.assign(item, value.fields.get(i, Value()), env, line)
        else:
            self.warn("Unsupported assignment target.")

    def block(self, nodes, env):
        returns = Value()
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                hint = get_name(targets[0]) or ""
                value = self.expr(node.value, env, hint)
                for target in targets:
                    self.assign(target, value, env, node.lineno)
            elif isinstance(node, ast.AugAssign):
                value = Value(merge(self.expr(node.target, env), self.expr(node.value, env)).all_traces())
                self.assign(node.target, value, env, node.lineno)
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env)
            elif isinstance(node, ast.Return):
                return merge(returns, self.step(self.expr(node.value, env), "return", node.lineno, "return")), True
            elif isinstance(node, ast.If):
                self.expr(node.test, env)
                left, right = copy.deepcopy(env), copy.deepcopy(env)
                lv, lr = self.block(node.body, left)
                rv, rr = self.block(node.orelse, right)
                returns = merge(returns, lv, rv)
                continuations = [e for e, stopped in [(left, lr), (right, rr)] if not stopped]
                if not continuations:
                    return returns, True
                env.clear()
                for name in set().union(*(e.keys() for e in continuations)):
                    env[name] = merge(*(e.get(name, Value()) for e in continuations))
            elif isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                self.warn("Loops are approximated by zero or one iteration; no fixed-point analysis.")
                before, iteration = copy.deepcopy(env), copy.deepcopy(env)
                if isinstance(node, (ast.For, ast.AsyncFor)):
                    items = self.expr(node.iter, env)
                    self.assign(node.target, Value(items.all_traces()), iteration, node.lineno)
                else:
                    self.expr(node.test, env)
                rv, _ = self.block(node.body, iteration)
                returns = merge(returns, rv)
                for name in before.keys() | iteration.keys():
                    env[name] = merge(before.get(name, Value()), iteration.get(name, Value()))
                rv, _ = self.block(node.orelse, env)
                returns = merge(returns, rv)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                self.warn("Context manager entry/exit effects are not modeled; body analyzed conditionally.")
                for item in node.items:
                    value = self.expr(item.context_expr, env)
                    if item.optional_vars:
                        self.assign(item.optional_vars, value, env, node.lineno)
                rv, stopped = self.block(node.body, env)
                returns = merge(returns, rv)
                if stopped:
                    return returns, True
            elif isinstance(node, ast.Assert):
                self.expr(node.test, env)
            elif isinstance(node, ast.ClassDef):
                # Declarations are indexed for explicit test entry points only.
                if self.entry_points == "module":
                    self.warn("Class bodies are not entry points in module mode.")
                continue
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Import, ast.ImportFrom, ast.Pass)):
                continue
            else:
                self.warn(f"Unsupported statement: {type(node).__name__}; its body is not analyzed.")
        return returns, False

    def call(self, node, env):
        name = get_name(node.func) or "<dynamic>"
        head, *tail = name.split(".")
        resolved = ".".join([self.aliases.get(head, head), *tail])
        positional_hints = {"requests.auth.HTTPBasicAuth": {1: "password"},
                            "requests.auth.HTTPDigestAuth": {1: "password"},
                            "httpx.BasicAuth": {1: "password"}, "hmac.new": {0: "private_key"},
                            "requests_oauthlib.OAuth1Session": {1: "client_secret", 3: "resource_owner_secret"}}
        if isinstance(node.func, ast.Attribute):
            receiver_name = get_name(node.func.value)
            receiver = env.get(receiver_name, Value())
            if node.func.attr == "auth_password" and "paramiko.Transport" in receiver.types:
                positional_hints[resolved] = {1: "password"}
            elif node.func.attr == "connect":
                if "paramiko.SSHClient" in receiver.types:
                    positional_hints[resolved] = {3: "password"}
                elif "paramiko.Transport" in receiver.types:
                    positional_hints[resolved] = {2: "password"}
        args = [self.expr(arg, env, positional_hints.get(resolved, {}).get(i, "")) for i, arg in enumerate(node.args)]
        kwargs = {}
        for kw in node.keywords:
            value = self.expr(kw.value, env, kw.arg or "")
            if kw.arg is None and value.fields and all(isinstance(k, str) for k in value.fields):
                kwargs.update(value.fields)
            else:
                kwargs[kw.arg] = value
        if any(isinstance(arg, ast.Starred) for arg in node.args) or None in kwargs:
            self.warn("Starred call arguments are not resolved.")
        if name.startswith("self.") and self.current_class and name.count(".") == 1:
            method = self.methods(self.current_class).get(name.split(".")[1])
            if method:
                return self.invoke(method, [Value(), *args], kwargs, env, node.lineno, method=True)
        modeled = self.library_call(node, resolved, args, kwargs, env)
        if modeled is not None:
            return modeled
        if name in self.functions and name not in env and isinstance(node.func, ast.Name):
            return self.invoke(self.functions[name], args, kwargs, env, node.lineno)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "join", "encode", "decode", "strip"}:
            return Value(merge(self.expr(node.func.value, env), *args, *kwargs.values()).all_traces())
        if head in env:
            self.warn(f"Shadowed or object call at line {node.lineno} is not resolved.")
            return Value()
        parts = resolved.split(".")
        if len(parts) == 2 and parts[0] in HTTP_MODULES and parts[1] in HTTP_METHODS:
            headers = kwargs.get("headers", Value())
            for key, value in headers.fields.items():
                if isinstance(key, str) and key.lower() in AUTH_HEADERS:
                    self.record(value, resolved, node.lineno, "api_token" if "key" in key.lower() else "authentication", f"headers[{key!r}]")
            auth = kwargs.get("auth", Value())
            self.record(auth.fields.get(1, auth), resolved, node.lineno, "authentication", "auth")
        elif resolved in {"psycopg2.connect", "psycopg.connect", "pymysql.connect", "mysql.connector.connect"}:
            for key in ("password", "passwd"):
                self.record(kwargs.get(key, Value()), resolved, node.lineno, "database", key)
        elif resolved == "hmac.new":
            self.record(args[0] if args else kwargs.get("key", Value()), resolved, node.lineno, "cryptographic_key", "key")
        else:
            self.warn(f"Unresolved call at line {node.lineno}; return value and side effects are not tracked.")
        return Value()

    def invoke(self, function, args, kwargs, caller, line, method=False):
        if function.name in self.active or len(self.active) >= self.max_depth:
            self.warn("Recursion/depth limit reached; this call was not analyzed.")
            return Value()
        # Module globals are visible; caller locals must not leak into another function.
        global_env = self.env if self.active else caller
        local = copy.deepcopy(global_env)
        for child in ast.walk(function):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                local[child.id] = Value()
        if method:
            local.update({k: copy.deepcopy(v) for k, v in caller.items() if k.startswith("self.")})
        positional = function.args.posonlyargs + function.args.args
        defaults = dict(zip([p.arg for p in positional[-len(function.args.defaults):]] if function.args.defaults else [], function.args.defaults))
        for i, parameter in enumerate(positional):
            value = args[i] if i < len(args) else kwargs.get(parameter.arg)
            if value is None:
                value = self.expr(defaults.get(parameter.arg), global_env, parameter.arg)
            local[parameter.arg] = self.step(value, f"{function.name}({parameter.arg})", line, "parameter")
        for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
            value = kwargs[parameter.arg] if parameter.arg in kwargs else self.expr(default, global_env, parameter.arg)
            local[parameter.arg] = self.step(value, f"{function.name}({parameter.arg})", line, "parameter")
        if function.args.vararg or function.args.kwarg:
            self.warn("Variadic function parameters are not bound.")
        self.active.append(function.name)
        result, _ = self.block(function.body, local)
        self.active.pop()
        if method:
            for key in list(caller):
                if key.startswith("self."):
                    del caller[key]
            caller.update({k: v for k, v in local.items() if k.startswith("self.")})
        return self.step(result, f"{function.name}()", line, "call_result")

    def record(self, value, sink, line, purpose, argument):
        value = self.step(Value(value.all_traces()), sink, line, "sink")
        for cid, trace in value.traces.items():
            if cid not in self.candidates:
                node, hint = self.literal_sources[cid]
                evidence = literal_evidence(node.value, 'password' if argument == 'auth' else argument)
                if evidence is None or evidence['is_secret'] is not True:
                    continue
                evidence = dict(evidence, reason='literal_reaches_sensitive_argument', purpose=purpose)
                self.candidates[cid] = {'id': cid, 'file': self.filename, 'line': node.lineno,
                                        'column': node.col_offset, 'source': hint or 'literal',
                                        'value': '[REDACTED]', 'assessment': evidence}
            if self.candidates[cid]['assessment']['reason'] == 'protocol_or_field_word':
                continue
            key = (cid, sink, line, argument, self.entry_point)
            if key in self._findings:
                continue
            self._findings.add(key)
            candidate = self.candidates[cid]
            self.findings.append({"candidate_id": cid, "candidate": "[REDACTED]", "source": candidate["source"],
                                  "file": self.filename, "source_line": candidate["line"], "sink": sink,
                                  "line": line, "argument": argument, "purpose": purpose, "trace": trace,
                                  "entry_point": self.entry_point})

    def resolve(self, name):
        head, *tail = (name or "").split(".")
        return ".".join([self.aliases.get(head, head), *tail])

    def methods(self, class_name, seen=None):
        seen = set() if seen is None else seen
        if class_name in seen or class_name not in self.classes:
            return {}
        seen.add(class_name)
        cls = self.classes[class_name]
        methods = {}
        for base in reversed(cls.bases):
            methods.update(self.methods(get_name(base), seen))
        methods.update({n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))})
        return methods

    def is_test_class(self, name, seen=None):
        seen = set() if seen is None else seen
        if name in seen or name not in self.classes:
            return False
        seen.add(name)
        return any(self.resolve(get_name(base)) in {"unittest.TestCase", "unittest.case.TestCase"}
                   or self.is_test_class(get_name(base), seen) for base in self.classes[name].bases)

    def analyze_tests(self):
        for name in self.classes:
            if not self.is_test_class(name):
                continue
            methods = self.methods(name)
            for test_name, method in methods.items():
                if not test_name.startswith("test"):
                    continue
                self.current_class = name
                self.entry_point = f"unittest:{name}.{test_name}"
                env = copy.deepcopy(self.env)
                # Class literal attributes are visible on each fresh test instance.
                declarations = [n for n in self.classes[name].body if isinstance(n, (ast.Assign, ast.AnnAssign))]
                attributes = {}
                self.block(declarations, attributes)
                env.update({f"self.{k}": v for k, v in attributes.items()})
                if "setUpClass" in methods:
                    self.warn("setUpClass fixtures are not modeled.")
                if "setUp" in methods:
                    self.invoke(methods["setUp"], [Value()], {}, env, methods["setUp"].lineno, method=True)
                self.invoke(method, [Value()], {}, env, method.lineno, method=True)
        self.current_class = None
        self.entry_point = "module"

    def library_call(self, node, resolved, args, kwargs, env):
        head = (get_name(node.func) or "").split(".")[0]
        unshadowed = head not in env
        if resolved == "dict" and unshadowed:
            return Value(fields={**(args[0].fields if args else {}), **{k:v for k,v in kwargs.items() if k is not None}})
        auth_types = {"requests.auth.HTTPBasicAuth", "requests.auth.HTTPDigestAuth", "httpx.BasicAuth"}
        if resolved in auth_types and unshadowed:
            return args[1] if len(args) > 1 else kwargs.get("password", Value())
        constructors = {"requests.Session", "requests.sessions.Session", "httpx.Client", "httpx.AsyncClient",
                        "requests_oauthlib.OAuth1Session", "requests_oauthlib.OAuth2Session",
                        "requests_oauthlib.oauth1_session.OAuth1Session", "requests_oauthlib.oauth2_session.OAuth2Session",
                        "paramiko.SSHClient", "paramiko.Transport"}
        if resolved in constructors and unshadowed:
            fields = dict(kwargs)
            if "OAuth1Session" in resolved:
                for i, key in ((1, "client_secret"), (3, "resource_owner_secret")):
                    if i < len(args):
                        fields[key] = args[i]
            return Value(fields=fields, types=frozenset({resolved}))
        if not isinstance(node.func, ast.Attribute):
            return None
        receiver = self.expr(node.func.value, env)
        method = node.func.attr
        if not receiver.types and receiver.fields:
            if method == "get" and node.args and isinstance(node.args[0], ast.Constant):
                return copy.deepcopy(receiver.fields.get(node.args[0].value, args[1] if len(args) > 1 else Value()))
            if method == "update":
                receiver.fields.update(args[0].fields if args else {})
                receiver.fields.update({k:v for k,v in kwargs.items() if k is not None})
                self.assign(node.func.value, receiver, env, node.lineno)
                return Value()
        for typ in sorted(receiver.types):
            sink = f"{typ}.{method}"
            if typ.startswith(("requests.", "requests_oauthlib.", "httpx.")):
                if method in HTTP_METHODS or ("OAuth" in typ and method in {"fetch_token", "refresh_token", "fetch_access_token", "fetch_request_token"}):
                    fields = {**receiver.fields, **kwargs}
                    auth = fields.get("auth", Value())
                    self.record(auth.fields.get(1, auth), sink, node.lineno, "authentication", "auth")
                    for key, value in fields.get("headers", Value()).fields.items():
                        if isinstance(key, str) and key.lower() in AUTH_HEADERS:
                            self.record(value, sink, node.lineno, "api_token" if "key" in key.lower() else "authentication", f"headers[{key!r}]")
                    if "OAuth" in typ:
                        for key in ("client_secret", "resource_owner_secret", "password", "token"):
                            self.record(fields.get(key, Value()), sink, node.lineno, "authentication", key)
                    return Value()
            if typ.startswith("paramiko.") and method in {"connect", "auth_password"}:
                password = kwargs.get("password", Value())
                index = 1 if method == "auth_password" else 3 if typ == "paramiko.SSHClient" else 2
                if len(args) > index:
                    password = args[index]
                self.record(password, sink, node.lineno, "authentication", "password")
                return Value()
        return None

    def target_hint(self, node):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            return node.slice.value
        return get_name(node) or ""

    def discover(self, node, hint=""):
        """Candidate extraction is independent of whether a function is called."""
        if isinstance(node, ast.Constant):
            self.literal(node, hint)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, (ast.Tuple, ast.List)) and isinstance(node.value, (ast.Tuple, ast.List)):
                    for item, value in zip(target.elts, node.value.elts):
                        self.discover(value, self.target_hint(item))
                else:
                    self.discover(node.value, self.target_hint(target))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = node.args.posonlyargs + node.args.args
            for parameter, default in zip(positional[-len(node.args.defaults):], node.args.defaults):
                self.discover(default, parameter.arg)
            for parameter, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                self.discover(default, parameter.arg)
            for statement in node.body:
                self.discover(statement)
        elif isinstance(node, ast.Compare):
            parts = [node.left, *node.comparators]
            comparison_hint = next((self.target_hint(p) for p in parts if self.is_suspicious_name(self.target_hint(p))), "")
            for part in parts:
                if not isinstance(part, ast.Subscript):
                    self.discover(part, comparison_hint)
                else:
                    self.discover(part.value)
        elif isinstance(node, ast.Subscript):
            # A lookup key such as config['password'] is not a secret literal.
            self.discover(node.value)
        elif isinstance(node, ast.Call):
            resolved = self.resolve(get_name(node.func))
            hints = {"requests.auth.HTTPBasicAuth": {1: "password"},
                     "requests.auth.HTTPDigestAuth": {1: "password"},
                     "httpx.BasicAuth": {1: "password"}, "hmac.new": {0: "private_key"},
                     "requests_oauthlib.OAuth1Session": {1: "client_secret", 3: "resource_owner_secret"}}
            function = self.functions.get(get_name(node.func))
            positional = hints.get(resolved, {})
            if function:
                positional = {i: p.arg for i, p in enumerate(function.args.posonlyargs + function.args.args)}
            for i, arg in enumerate(node.args):
                # Preserve hints only through known literal transformations.
                inherited = hint if resolved in {'base64.b64encode', 'base64.b64decode', 'str', 'bytes'} else ''
                self.discover(arg, positional.get(i, inherited))
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'encode', 'decode', 'strip', 'format'}:
                self.discover(node.func.value, hint)
            for keyword in node.keywords:
                self.discover(keyword)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                self.discover(value, str(key.value) if isinstance(key, ast.Constant) else hint)
        elif isinstance(node, ast.keyword):
            if node.arg == "auth" and isinstance(node.value, (ast.Tuple, ast.List)):
                for i, item in enumerate(node.value.elts):
                    self.discover(item, "password" if i == 1 else "")
            else:
                self.discover(node.value, node.arg or "")
        elif isinstance(node, ast.AST):
            for child in ast.iter_child_nodes(node):
                self.discover(child, hint)

    def context(self, line, radius=3):
        """Export nearby top-level statements with every string literal masked."""
        class Redact(ast.NodeTransformer):
            def visit_Constant(self, node):
                if isinstance(node.value, (str, bytes)):
                    return ast.copy_location(ast.Constant("[REDACTED]"), node)
                return node

        tree = ast.parse(self.source)
        snippets = []
        for statement in tree.body:
            if statement.lineno <= line + radius and statement.end_lineno >= line - radius:
                sanitized = Redact().visit(copy.deepcopy(statement))
                snippets.append(f"# Original lines {statement.lineno}-{statement.end_lineno}\n{ast.unparse(sanitized)}")
        return "\n\n".join(snippets)[:12000]

    def report(self):
        return {"file": self.filename, "entry_points": self.entry_points, "candidates": list(self.candidates.values()), "findings": self.findings,
                "assessments": self.assessments(),
                "warnings": self.warnings}

    def assessments(self):
        results = []
        for candidate in self.candidates.values():
            evidence = dict(candidate['assessment'])
            flows = [f for f in self.findings if f['candidate_id'] == candidate['id']]
            if flows and evidence['is_secret'] is True:
                evidence.update(purpose=flows[0]['purpose'])
            results.append({'candidate_id': candidate['id'], 'file': self.filename,
                            'line': candidate['line'], 'source': candidate['source'],
                            **evidence, 'sensitive_use_found': bool(flows)})
        return results


def scan_file(filename, display_path=None, entry_points="module"):
    with tokenize.open(filename) as handle:
        source = handle.read()
    scanner = KeytraceScanner(display_path or str(filename), source, entry_points=entry_points)
    return scanner.visit(ast.parse(source, filename=str(filename)))


def scan_path(path, entry_points="module"):
    path = Path(path)
    excluded = {".git", ".venv", "venv", "__pycache__", "node_modules"}
    if not path.exists():
        return [], [{"file": str(path), "error": "Path does not exist"}]
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*.py") if not p.is_symlink() and not excluded.intersection(p.relative_to(path).parts))
    scanners, errors = [], []
    for file in files:
        display = file.name if path.is_file() else file.relative_to(path).as_posix()
        try:
            scanners.append(scan_file(file, display, entry_points=entry_points))
        except (SyntaxError, UnicodeError, OSError) as exc:
            errors.append({"file": display, "error": type(exc).__name__, "line": getattr(exc, "lineno", None)})
    return scanners, errors
