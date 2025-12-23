import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from ast_security import run_ast_security_checks


RULE_SNIPPETS = [
    ("password = 'supersecret'", "HARDCODED_SECRETS"),
    ("eval('1 + 1')", "DANGEROUS_EVAL"),
    ("exec('print(1)')", "DANGEROUS_EXEC"),
    ("import subprocess\nsubprocess.run('ls', shell=True)", "DANGEROUS_SUBPROCESS"),
    ("import os\nos.system('ls -la')", "DANGEROUS_OS_SYSTEM"),
    ("import pickle\npickle.loads(blob)", "DANGEROUS_PICKLE"),
    ("import yaml\nyaml.load(blob)", "UNSAFE_YAML_LOAD"),
    ("import hashlib\nhashlib.md5(b'data')", "WEAK_HASH"),
    ("import requests\nrequests.get('https://example.com', verify=False)", "REQUESTS_VERIFY_FALSE"),
    ("cursor.execute('SELECT ' + user_input)", "SQLI_STRING_CONCAT"),
    ("cursor.execute(f'SELECT {user_input}')", "SQLI_FSTRING"),
    ("app.run(debug=True)", "DEBUG_MODE_ENABLED"),
    ("open(base + filename)", "PATH_TRAVERSAL_OPEN"),
    ("import xml.etree.ElementTree as ET\nET.parse('file.xml')", "XML_UNSAFE_PARSER"),
    ("import random\nrandom.randint(1, 10)", "WEAK_RNG_USAGE"),
]


def test_rulepack_snippets_fire() -> None:
    for code, expected in RULE_SNIPPETS:
        findings = run_ast_security_checks(code, active_rules=["ALL"])
        assert expected in findings, f"Expected {expected} in findings for: {code}"


def test_rulepack_allows_benign_snippets() -> None:
    benign_snippets = [
        "import hashlib\nhashlib.sha256(b'data')",
        "import yaml\nyaml.safe_load(blob)",
        "import requests\nrequests.get('https://example.com', verify=True)",
        "import subprocess\nsubprocess.run('ls', shell=False)",
        "app.run(debug=False)",
        "open('static/path.txt')",
        "cursor.execute('SELECT * FROM users WHERE id = ?', [user_id])",
    ]
    for code in benign_snippets:
        findings = run_ast_security_checks(code, active_rules=["ALL"])
        assert findings == [], f"Unexpected findings for snippet: {code}: {findings}"
