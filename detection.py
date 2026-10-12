"""Explainable literal evidence. A positive is a potential secret, never validation."""
import re
from urllib.parse import urlsplit, unquote


def credential_name(name):
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()
    return bool(re.search(r"password|passwd|passphrase|(?:^|[_.-])pwd(?:$|[_.-])|token|api_?key|secret|access_?key|private_?key|authorization|(?:^|[_.-])auth(?:$|[_.-])", name))


def content_kind(text):
    if re.search(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", text):
        return "private_key"
    if re.fullmatch(r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,255})", text):
        return "token_format"
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        try:
            parsed = urlsplit(text)
            if parsed.username and parsed.password:
                return "credential_url"
        except ValueError:
            pass
    return None


def placeholder(text):
    value = text.strip().lower()
    return (value in {"", "placeholder", "changeme", "change-me", "replace_me", "your_password", "your_token", "your_api_key", "redacted", "[redacted]", "<redacted>", "none", "null"}
            or bool(re.fullmatch(r"(?:<[^<>]+>|\$\{[^}]+\}|\{\{.*\}\}|%\([^)]+\)s|%s|\{\})", value))
            or bool(re.fullmatch(r"[x*]{4,}", value)))


def literal_evidence(value, hint):
    """Return only safe, categorical evidence; never retain the literal value."""
    if not isinstance(value, (str, bytes)) or not value:
        return None
    text = value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value
    kind = content_kind(text)
    if not kind and not credential_name(hint):
        return None
    name = hint.lower()
    purpose = ('cryptographic_key' if kind == 'private_key' or 'private_key' in name else
               'api_token' if kind == 'token_format' or any(x in name for x in ('token', 'api_key', 'apikey', 'access_key')) else
               'authentication')
    result = {'is_secret': True, 'purpose': purpose, 'confidence': 'medium',
              'reason': 'credential_named_literal'}
    if kind:
        result.update(confidence='high', reason=kind)
        if kind == 'credential_url':
            if placeholder(unquote(urlsplit(text).password)):
                result.update(is_secret=False, purpose='non_secret', confidence='medium', reason='placeholder_url_password')
        return result
    # Names of credentials and paths are not the credentials themselves.
    if re.search(r'(?:^|[_.-])(?:name|id|path|file|filename|type|method|url|uri|endpoint|algorithm|format|magic|placement|header|env|length|prompt)(?:$|[_.-])', name):
        return dict(result, is_secret=None, purpose='unknown', confidence='low', reason='credential_metadata_name')
    if placeholder(text):
        return dict(result, is_secret=False, purpose='non_secret', reason='explicit_placeholder')
    if text.strip().lower() in {'bearer', 'basic', 'digest', 'authorization', 'password', 'access_token', 'utf-8', 'utf8', 'ascii'}:
        return dict(result, is_secret=None, purpose='unknown', confidence='low', reason='protocol_or_field_word')
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', text) or re.search(r'\.(?:pem|pub|key|crt|json)$', text) or text.startswith(('/', './', '../', '~/')):
        return dict(result, is_secret=None, purpose='unknown', confidence='low', reason='possible_resource_reference')
    if re.search(r'(?:^|[_.-])example(?:$|[_.-])', name) and re.match(r'^(?:dummy|test|example|sample)(?:$|[-_ ])', text, re.I):
        return dict(result, is_secret=False, purpose='test_example', reason='explicit_example_value')
    return result
