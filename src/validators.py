"""contracts/request.schema.json 的最小校验（仅覆盖本契约用到的子集）。

不引入第三方校验库；规则严格按 schema 的 required / type / minimum / minLength
/ format=date-time 执行。
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "contracts" / "request.schema.json"


class ValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _parse_datetime(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must carry a timezone offset (e.g. Z)")
    return dt


def validate(payload: Any, schema: dict[str, Any] | None = None) -> dict[str, str | int]:
    schema = schema or load_schema()
    errors: list[str] = []

    if not isinstance(payload, dict):
        raise ValidationError(["request body must be a JSON object"])

    for field in schema.get("required", []):
        if field not in payload:
            errors.append(f"missing required field: {field}")

    properties = schema.get("properties", {})
    for name, rule in properties.items():
        if name not in payload:
            continue
        value = payload[name]
        expected = rule.get("type")
        if expected == "string":
            if not isinstance(value, str):
                errors.append(f"{name} must be a string")
            elif rule.get("minLength", 1) > 0 and not value:
                errors.append(f"{name} must not be empty")
            elif rule.get("format") == "date-time":
                try:
                    _parse_datetime(value)
                except ValueError:
                    errors.append(f"{name} must be an RFC3339 timestamp with timezone")
        elif expected == "integer":
            # bool 是 int 的子类，显式排除
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"{name} must be an integer")
            elif "minimum" in rule and value < rule["minimum"]:
                errors.append(f"{name} must be >= {rule['minimum']}")

    if errors:
        raise ValidationError(errors)
    return payload


def parse_timestamp(value: str) -> datetime:
    return _parse_datetime(value)
