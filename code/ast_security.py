import ast
from typing import Iterable, List, Optional, Set


RULEPACK_VERSION = "v1.5"


class RulepackVisitor(ast.NodeVisitor):
    """AST-based security checker (Rulepack v1.5).

    The visitor is intentionally conservative and structural. It avoids taint
    tracking and only emits rule tags when specific syntactic patterns are seen.
    """

    def __init__(self) -> None:
        self.violations: Set[str] = set()
        self.sensitive_names = {"password", "secret", "token", "api_key", "apikey"}
        self.hashlib_aliases: Set[str] = {"hashlib"}
        self.hashlib_direct: Set[str] = set()
        self.yaml_aliases: Set[str] = {"yaml"}
        self.yaml_load_direct: Set[str] = set()
        self.yaml_unsafe_load_direct: Set[str] = set()
        self.requests_aliases: Set[str] = {"requests"}
        self.requests_direct: Set[str] = set()
        self.subprocess_aliases: Set[str] = {"subprocess"}
        self.pickle_aliases: Set[str] = {"pickle"}
        self.pickle_direct: Set[str] = set()
        self.os_aliases: Set[str] = {"os"}
        self.xml_aliases: Set[str] = set()
        self.xml_direct: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:  # type: ignore[override]
        for alias in node.names:
            if alias.name == "hashlib":
                self.hashlib_aliases.add(alias.asname or alias.name)
            elif alias.name == "yaml":
                self.yaml_aliases.add(alias.asname or alias.name)
            elif alias.name == "requests":
                self.requests_aliases.add(alias.asname or alias.name)
            elif alias.name == "subprocess":
                self.subprocess_aliases.add(alias.asname or alias.name)
            elif alias.name == "pickle":
                self.pickle_aliases.add(alias.asname or alias.name)
            elif alias.name == "os":
                self.os_aliases.add(alias.asname or alias.name)
            elif alias.name.startswith("xml"):
                self.xml_aliases.add(alias.asname or alias.name)
            elif alias.name.startswith("lxml"):
                self.xml_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # type: ignore[override]
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            if module == "hashlib" and alias.name in {"md5", "sha1"}:
                self.hashlib_direct.add(name)
            elif module == "yaml":
                if alias.name == "load":
                    self.yaml_load_direct.add(name)
                elif alias.name == "unsafe_load":
                    self.yaml_unsafe_load_direct.add(name)
            elif module == "requests":
                self.requests_direct.add(name)
            elif module == "subprocess":
                self.subprocess_aliases.add(name)
            elif module == "pickle" and alias.name in {"load", "loads"}:
                self.pickle_direct.add(name)
            elif module.startswith("xml") or module.startswith("lxml"):
                self.xml_aliases.add(name)
                if alias.name in {"parse", "fromstring", "parseString"}:
                    self.xml_direct.add(name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # type: ignore[override]
        self._check_secret_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # type: ignore[override]
        targets = [node.target]
        self._check_secret_assignment(targets, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
        func_name = _get_dotted_name(node.func)

        if func_name in {"eval", "builtins.eval"}:
            self.violations.add("DANGEROUS_EVAL")
        if func_name in {"exec", "builtins.exec"}:
            self.violations.add("DANGEROUS_EXEC")

        if self._is_os_system_call(node.func):
            self.violations.add("DANGEROUS_OS_SYSTEM")

        if self._is_subprocess_shell_true(node):
            self.violations.add("DANGEROUS_SUBPROCESS")

        if self._is_pickle_load(node.func):
            self.violations.add("DANGEROUS_PICKLE")

        if self._is_yaml_unsafe_load(node):
            self.violations.add("UNSAFE_YAML_LOAD")

        if self._is_weak_hash_call(node.func):
            self.violations.add("WEAK_HASH")

        if self._is_requests_verify_false(node):
            self.violations.add("REQUESTS_VERIFY_FALSE")

        if self._is_sql_injection_pattern(node):
            self.violations.update(_sql_violation_tags(node))

        if self._is_debug_mode(node):
            self.violations.add("DEBUG_MODE_ENABLED")

        if self._is_path_traversal_open(node):
            self.violations.add("PATH_TRAVERSAL_OPEN")

        if self._is_xml_unsafe_parser(node):
            self.violations.add("XML_UNSAFE_PARSER")

        if self._is_weak_rng_import(node):
            self.violations.add("WEAK_RNG_USAGE")

        self.generic_visit(node)

    def _check_secret_assignment(
        self, targets: Iterable[ast.expr], value: Optional[ast.expr]
    ) -> None:
        if not isinstance(value, (ast.Constant, ast.Str)):
            return
        raw_value = value.s if isinstance(value, ast.Str) else value.value
        if not isinstance(raw_value, str):
            return
        lowered_value = raw_value.strip().lower()
        if not lowered_value or len(lowered_value) < 4:
            return
        if "env" in lowered_value:
            return
        for target in targets:
            name = _get_name_for_target(target)
            if name and _is_sensitive_name(name):
                self.violations.add("HARDCODED_SECRETS")

    def _is_os_system_call(self, func: ast.expr) -> bool:
        dotted = _get_dotted_name(func)
        if dotted == "os.system":
            return True
        parts = dotted.split(".")
        return len(parts) == 2 and parts[0] in self.os_aliases and parts[1] == "system"

    def _is_subprocess_shell_true(self, node: ast.Call) -> bool:
        func_name = _get_dotted_name(node.func)
        parts = func_name.split(".")
        if len(parts) != 2 or parts[0] not in self.subprocess_aliases:
            return False
        if parts[1] not in {"call", "run", "Popen", "check_call", "check_output"}:
            return False
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                return kw.value.value is True
        return False

    def _is_pickle_load(self, func: ast.expr) -> bool:
        dotted = _get_dotted_name(func)
        if dotted in {"pickle.load", "pickle.loads"}:
            return True
        parts = dotted.split(".")
        if len(parts) == 2 and parts[0] in self.pickle_aliases and parts[1] in {"load", "loads"}:
            return True
        if dotted in self.pickle_direct:
            return True
        return False

    def _is_yaml_unsafe_load(self, node: ast.Call) -> bool:
        dotted = _get_dotted_name(node.func)
        if dotted in {"yaml.unsafe_load"}:
            return True
        if dotted in self.yaml_unsafe_load_direct:
            return True
        is_yaml_load = False
        if dotted in {"yaml.load"}:
            is_yaml_load = True
        else:
            parts = dotted.split(".")
            if len(parts) == 2 and parts[0] in self.yaml_aliases and parts[1] == "load":
                is_yaml_load = True
            if dotted in self.yaml_load_direct:
                is_yaml_load = True
        if not is_yaml_load:
            return False
        loader_kw = None
        for kw in node.keywords:
            if kw.arg in {"Loader", "loader"}:
                loader_kw = kw.value
                break
        if loader_kw is None:
            return True
        loader_name = _get_dotted_name(loader_kw)
        return "safeloader" not in loader_name.lower() and "csafeloader" not in loader_name.lower()

    def _is_weak_hash_call(self, func: ast.expr) -> bool:
        dotted = _get_dotted_name(func)
        if dotted in {"hashlib.md5", "hashlib.sha1"}:
            return True
        parts = dotted.split(".")
        if len(parts) == 2 and parts[0] in self.hashlib_aliases and parts[1] in {"md5", "sha1"}:
            return True
        if dotted in self.hashlib_direct:
            return True
        return False

    def _is_requests_verify_false(self, node: ast.Call) -> bool:
        func_name = _get_dotted_name(node.func)
        parts = func_name.split(".")
        is_requests = False
        if len(parts) == 2 and parts[0] in self.requests_aliases:
            is_requests = True
        elif func_name in self.requests_direct:
            is_requests = True
        if not is_requests:
            return False
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant):
                return kw.value.value is False
        return False

    def _is_sql_injection_pattern(self, node: ast.Call) -> bool:
        func_name = _get_dotted_name(node.func)
        if func_name in {"execute", "exec", "query"}:
            return True
        if func_name.endswith(".execute") or func_name.endswith(".exec") or func_name.endswith(".query"):
            return True
        return False

    def _is_debug_mode(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "run":
            return False
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant):
                return kw.value.value is True
        return False

    def _is_path_traversal_open(self, node: ast.Call) -> bool:
        func_name = _get_dotted_name(node.func)
        if func_name not in {"open", "io.open"} and not func_name.endswith(".open"):
            return False
        if not node.args:
            return False
        return _is_dynamic_path_expr(node.args[0])

    def _is_xml_unsafe_parser(self, node: ast.Call) -> bool:
        func_name = _get_dotted_name(node.func)
        if func_name in self.xml_direct:
            return True
        for prefix in (
            "xml.etree.ElementTree.",
            "xml.dom.minidom.",
            "xml.sax.",
            "lxml.etree.",
        ):
            if func_name.startswith(prefix):
                if func_name.endswith("parse") or func_name.endswith("fromstring") or func_name.endswith("parseString"):
                    return True
        parts = func_name.split(".")
        if len(parts) == 2 and parts[0] in self.xml_aliases:
            return parts[1] in {"parse", "fromstring", "parseString"}
        return False

    def _is_weak_rng_import(self, node: ast.Call) -> bool:
        func_name = _get_dotted_name(node.func)
        parts = func_name.split(".")
        if len(parts) != 2:
            return False
        if parts[0] != "random":
            return False
        return parts[1] in {"random", "randint", "randrange", "choice", "choices"}


def _sql_violation_tags(node: ast.Call) -> Set[str]:
    tags: Set[str] = set()
    if not node.args:
        return tags
    first_arg = node.args[0]
    if isinstance(first_arg, ast.BinOp):
        tags.add("SQLI_STRING_CONCAT")
    elif isinstance(first_arg, ast.JoinedStr):
        tags.add("SQLI_FSTRING")
    elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute):
        if first_arg.func.attr == "format":
            tags.add("SQLI_STRING_CONCAT")
    return tags


def _is_dynamic_path_expr(expr: ast.expr) -> bool:
    if isinstance(expr, ast.BinOp):
        return True
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        return expr.func.attr == "format"
    return False


def _get_name_for_target(target: ast.expr) -> Optional[str]:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(key in lowered for key in {"password", "secret", "token", "api_key", "apikey"})


def _get_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: List[str] = []
        current: Optional[ast.AST] = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(node, ast.Constant):
        return str(node.value)
    return ""


def run_ast_security_checks(code_str: str, active_rules: Optional[List[str]] = None) -> List[str]:
    """Parse code and return violation tags filtered by active task rules."""
    if active_rules is None:
        active_rules = []

    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        return ["SYNTAX_ERROR_PREVENTS_SECURITY_SCAN"]

    visitor = RulepackVisitor()
    visitor.visit(tree)

    violations = sorted(visitor.violations)
    if not violations:
        return []

    active_set = set(active_rules)
    if "ALL" in active_set:
        return violations

    category_map = {
        "SQLI": {"SQLI_STRING_CONCAT", "SQLI_FSTRING"},
        "SECRETS": {"HARDCODED_SECRETS"},
        "WEAK_RNG": {"WEAK_RNG_USAGE"},
        "CODE_EXECUTION": {"DANGEROUS_EVAL", "DANGEROUS_EXEC"},
        "SUBPROCESS": {"DANGEROUS_SUBPROCESS"},
        "OS_COMMAND": {"DANGEROUS_OS_SYSTEM"},
        "DESERIALIZATION": {"DANGEROUS_PICKLE"},
        "YAML": {"UNSAFE_YAML_LOAD"},
        "HASH": {"WEAK_HASH"},
        "TLS": {"REQUESTS_VERIFY_FALSE"},
        "DEBUG": {"DEBUG_MODE_ENABLED"},
        "PATH_TRAVERSAL": {"PATH_TRAVERSAL_OPEN"},
        "XML": {"XML_UNSAFE_PARSER"},
    }

    enabled: Set[str] = set()
    for rule in active_set:
        if rule in category_map:
            enabled.update(category_map[rule])
        else:
            enabled.add(rule)

    if not enabled:
        return []

    return [v for v in violations if v in enabled]
