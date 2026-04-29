from __future__ import annotations

import ast
from collections.abc import Mapping
from functools import lru_cache
import json
from typing import Any


ALLOWED_HELPERS = {
    "pick",
    "pick_first",
    "exists",
    "success",
    "text",
    "len",
    "bool",
    "int",
    "float",
    "str",
}
BASE_CONTEXT_NAMES = {
    "payload",
    "status_code",
    "detail",
    "validation",
    "empty_value",
    "content_type",
    "headers",
    "query",
}
ALLOWED_BINARY_OPERATORS = (
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
)
ALLOWED_UNARY_OPERATORS = (
    ast.Not,
    ast.UAdd,
    ast.USub,
)
ALLOWED_BOOLEAN_OPERATORS = (
    ast.And,
    ast.Or,
)
ALLOWED_COMPARISON_OPERATORS = (
    ast.Eq,
    ast.NotEq,
    ast.Gt,
    ast.GtE,
    ast.Lt,
    ast.LtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
)
MISSING = object()


class _CustomOutputValidator:
    def __init__(self) -> None:
        self.assigned_names: set[str] = set()

    def validate(self, tree: ast.Module) -> None:
        if not tree.body:
            raise ValueError("Custom transform code cannot be empty.")
        for statement in tree.body:
            self._validate_statement(statement)
        if "result" not in self.assigned_names:
            raise ValueError("Custom transform code must assign the final shaped body to 'result'.")

    def _validate_statement(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._validate_target(target)
            self._validate_expression(node.value)
            return
        if isinstance(node, ast.If):
            self._validate_expression(node.test)
            if not node.body:
                raise ValueError(self._error(node, "Custom transform if-block cannot be empty."))
            for statement in node.body:
                self._validate_statement(statement)
            for statement in node.orelse:
                self._validate_statement(statement)
            return
        if isinstance(node, ast.Pass):
            return
        raise ValueError(
            self._error(
                node,
                "Only assignments and if/else blocks are allowed in custom transform code.",
            )
        )

    def _validate_target(self, node: ast.expr) -> None:
        if not isinstance(node, ast.Name):
            raise ValueError(self._error(node, "Only plain variable assignments are allowed."))
        name = node.id.strip()
        if not name or name.startswith("_"):
            raise ValueError(self._error(node, "Variable names starting with '_' are not allowed."))
        if name in BASE_CONTEXT_NAMES or name in ALLOWED_HELPERS:
            raise ValueError(self._error(node, f"Variable name '{name}' is reserved."))
        self.assigned_names.add(name)

    def _validate_expression(self, node: ast.expr) -> None:
        if isinstance(node, ast.Constant):
            return
        if isinstance(node, ast.Name):
            if node.id not in BASE_CONTEXT_NAMES and node.id not in ALLOWED_HELPERS and node.id not in self.assigned_names:
                raise ValueError(self._error(node, f"Unknown name '{node.id}' in custom transform code."))
            return
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is not None:
                    self._validate_expression(key)
            for value in node.values:
                self._validate_expression(value)
            return
        if isinstance(node, (ast.List, ast.Tuple)):
            for item in node.elts:
                self._validate_expression(item)
            return
        if isinstance(node, ast.BinOp):
            if not isinstance(node.op, ALLOWED_BINARY_OPERATORS):
                raise ValueError(self._error(node, "This operator is not allowed in custom transform code."))
            self._validate_expression(node.left)
            self._validate_expression(node.right)
            return
        if isinstance(node, ast.UnaryOp):
            if not isinstance(node.op, ALLOWED_UNARY_OPERATORS):
                raise ValueError(self._error(node, "This unary operator is not allowed in custom transform code."))
            self._validate_expression(node.operand)
            return
        if isinstance(node, ast.BoolOp):
            if not isinstance(node.op, ALLOWED_BOOLEAN_OPERATORS):
                raise ValueError(self._error(node, "This boolean operator is not allowed in custom transform code."))
            for value in node.values:
                self._validate_expression(value)
            return
        if isinstance(node, ast.Compare):
            self._validate_expression(node.left)
            for operator in node.ops:
                if not isinstance(operator, ALLOWED_COMPARISON_OPERATORS):
                    raise ValueError(self._error(node, "This comparison operator is not allowed in custom transform code."))
            for comparator in node.comparators:
                self._validate_expression(comparator)
            return
        if isinstance(node, ast.IfExp):
            self._validate_expression(node.test)
            self._validate_expression(node.body)
            self._validate_expression(node.orelse)
            return
        if isinstance(node, ast.Subscript):
            self._validate_expression(node.value)
            self._validate_expression(node.slice)
            return
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in ALLOWED_HELPERS:
                raise ValueError(self._error(node, "Only built-in safe helper calls are allowed in custom transform code."))
            for argument in node.args:
                self._validate_expression(argument)
            for keyword in node.keywords:
                if keyword.arg is None:
                    raise ValueError(self._error(node, "Star-arguments are not allowed in custom transform code."))
                self._validate_expression(keyword.value)
            return
        raise ValueError(
            self._error(
                node,
                f"Unsupported syntax '{type(node).__name__}' in custom transform code.",
            )
        )

    def _error(self, node: ast.AST, message: str) -> str:
        line = getattr(node, "lineno", 0) or 0
        column = getattr(node, "col_offset", 0) or 0
        return f"{message} (line {line}, column {column + 1})"


@lru_cache(maxsize=128)
def _compile_custom_code(code: str) -> Any:
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        line = exc.lineno or 0
        column = (exc.offset or 1)
        message = exc.msg or "invalid syntax"
        raise ValueError(f"Custom transform syntax error at line {line}, column {column}: {message}.") from exc
    _CustomOutputValidator().validate(tree)
    return compile(tree, "<napigate-custom-output>", "exec")


def validate_custom_output_code(code: str) -> None:
    _compile_custom_code(code)


def execute_custom_output_code(
    code: str,
    *,
    payload: Any,
    status_code: int,
    detail: str = "",
    validation: Mapping[str, Any] | None = None,
    empty_value: Any = "",
    content_type: str = "",
    headers: Mapping[str, Any] | None = None,
    query: Mapping[str, Any] | None = None,
) -> Any:
    compiled = _compile_custom_code(code)
    request_headers = dict(headers or {})
    request_query = dict(query or {})

    def path_value(source: Any, path: str, default: Any = MISSING) -> Any:
        current = source
        for raw_part in str(path or "").split("."):
            part = raw_part.strip()
            if not part:
                return default
            if isinstance(current, Mapping):
                if part not in current:
                    return default
                current = current[part]
                continue
            if isinstance(current, list) and part.isdigit():
                index = int(part)
                if index >= len(current):
                    return default
                current = current[index]
                continue
            return default
        if current in (None, "") and default is not MISSING:
            return default
        return current

    def helper_pick(path: str, default: Any = MISSING) -> Any:
        fallback = empty_value if default is MISSING else default
        return path_value(payload, path, fallback)

    def helper_pick_first(*paths: str, default: Any = MISSING) -> Any:
        fallback = empty_value if default is MISSING else default
        for path in paths:
            value = path_value(payload, path, MISSING)
            if value is not MISSING and value not in (None, ""):
                return value
        return fallback

    def helper_exists(path: str) -> bool:
        return path_value(payload, path, MISSING) is not MISSING

    def helper_success(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"false", "0", "no", "failed", "error"}:
                return False
            if normalized in {"true", "1", "yes", "ok", "success"}:
                return True
        return bool(value)

    def helper_text(value: Any) -> str:
        if value in (None, ""):
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        return json.dumps(value, ensure_ascii=False)

    namespace: dict[str, Any] = {
        "__builtins__": {},
        "payload": payload,
        "status_code": status_code,
        "detail": detail,
        "validation": dict(validation or {}),
        "empty_value": empty_value,
        "content_type": content_type,
        "headers": request_headers,
        "query": request_query,
        "pick": helper_pick,
        "pick_first": helper_pick_first,
        "exists": helper_exists,
        "success": helper_success,
        "text": helper_text,
        "len": len,
        "bool": bool,
        "int": int,
        "float": float,
        "str": str,
    }
    exec(compiled, namespace, namespace)
    if "result" not in namespace:
        raise ValueError("Custom transform code must assign the final shaped body to 'result'.")
    return namespace["result"]
