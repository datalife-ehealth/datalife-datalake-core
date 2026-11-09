from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

CONTRACT_VERSION = "1.0"
SUPPORTED_VERSION: tuple[int, int] = (1, 0)
MAX_MANIFEST_BYTES = 65536
MAX_TABLES = 64
MAX_COLUMNS = 256
MAX_ROW_COUNT = 1000000000

ERROR_CODES = frozenset(
    {
        "invalid_json",
        "too_large",
        "not_object",
        "missing_field",
        "unexpected_field",
        "invalid_type",
        "invalid_format",
        "policy_violation",
        "forbidden_identity_field",
        "forbidden_reference",
        "unapproved_location",
        "duplicate_table",
        "duplicate_column",
        "invalid_row_count",
        "too_many_tables",
        "too_many_columns",
        "hash_mismatch",
        "incompatible_version",
    }
)

FORBIDDEN_REFERENCE_COLUMNS = frozenset(
    {
        "object_key",
        "payload_sha256",
        "token",
        "grant_token",
        "otp",
    }
)

_VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})")
_RELEASE_ID_PATTERN = re.compile(r"rel-[0-9]{4}-[0-9]{4}")
_POLICY_VERSION_PATTERN = re.compile(r"[1-9][0-9]{0,3}")
_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")

_TOP_LEVEL_FIELDS = ("contract_version", "release_id", "deidentification", "tables")
_DEIDENTIFICATION_FIELDS = (
    "policy_version",
    "direct_identifiers_removed",
    "subject_key_pseudonymous",
)
_POLICY_FLAGS = ("direct_identifiers_removed", "subject_key_pseudonymous")
_TABLE_FIELDS = ("name", "location", "row_count", "columns", "sha256")


@dataclass(frozen=True)
class ManifestError:
    code: str
    path: str


def format_error(error: ManifestError) -> str:
    return f"{error.code} {error.path}"


def parse_version(value: str) -> tuple[int, int] | None:
    if not isinstance(value, str):
        return None
    match = _VERSION_PATTERN.fullmatch(value)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def is_compatible(
    value: str, supported: tuple[int, int] = SUPPORTED_VERSION
) -> bool:
    parsed = parse_version(value)
    if parsed is None:
        return False
    return parsed[0] == supported[0] and parsed[1] <= supported[1]


def _record(found: dict[str, ManifestError], code: str, path: str) -> None:
    if path not in found:
        found[path] = ManifestError(code, path)


def _join(prefix: str, key: str) -> str:
    if prefix == "":
        return key
    return f"{prefix}.{key}"


def _check_keys(
    data: Mapping[str, Any],
    prefix: str,
    required: tuple[str, ...],
    found: dict[str, ManifestError],
) -> None:
    for key in required:
        if key not in data:
            _record(found, "missing_field", _join(prefix, key))
    for key in data:
        if key not in required:
            _record(found, "unexpected_field", _join(prefix, "<key>"))


def _check_contract_version(
    data: Mapping[str, Any], found: dict[str, ManifestError]
) -> None:
    if "contract_version" not in data:
        return
    value = data["contract_version"]
    if not isinstance(value, str):
        _record(found, "invalid_type", "contract_version")
        return
    if parse_version(value) is None:
        _record(found, "invalid_format", "contract_version")
        return
    if not is_compatible(value):
        _record(found, "incompatible_version", "contract_version")


def _check_release_id(
    data: Mapping[str, Any], found: dict[str, ManifestError]
) -> None:
    if "release_id" not in data:
        return
    value = data["release_id"]
    if not isinstance(value, str):
        _record(found, "invalid_type", "release_id")
        return
    if _RELEASE_ID_PATTERN.fullmatch(value) is None:
        _record(found, "invalid_format", "release_id")


def _check_deidentification(
    data: Mapping[str, Any], found: dict[str, ManifestError]
) -> None:
    if "deidentification" not in data:
        return
    value = data["deidentification"]
    if not isinstance(value, dict):
        _record(found, "invalid_type", "deidentification")
        return
    _check_keys(value, "deidentification", _DEIDENTIFICATION_FIELDS, found)
    if "policy_version" in value:
        policy_version = value["policy_version"]
        path = "deidentification.policy_version"
        if not isinstance(policy_version, str):
            _record(found, "invalid_type", path)
        elif _POLICY_VERSION_PATTERN.fullmatch(policy_version) is None:
            _record(found, "invalid_format", path)
    for flag in _POLICY_FLAGS:
        if flag not in value:
            continue
        path = _join("deidentification", flag)
        state = value[flag]
        if not isinstance(state, bool):
            _record(found, "invalid_type", path)
        elif state is not True:
            _record(found, "policy_violation", path)


def _check_columns(
    table: Mapping[str, Any], base: str, found: dict[str, ManifestError]
) -> None:
    if "columns" not in table:
        return
    path = _join(base, "columns")
    value = table["columns"]
    if not isinstance(value, list):
        _record(found, "invalid_type", path)
        return
    if not value:
        _record(found, "invalid_format", path)
        return
    if len(value) > MAX_COLUMNS:
        _record(found, "too_many_columns", path)
        return
    seen: set[str] = set()
    for index, column in enumerate(value):
        column_path = f"{path}[{index}]"
        if not isinstance(column, str):
            _record(found, "invalid_type", column_path)
            continue
        if _NAME_PATTERN.fullmatch(column) is None:
            _record(found, "invalid_format", column_path)
            continue
        if column in seen:
            _record(found, "duplicate_column", column_path)
            continue
        seen.add(column)


def _check_table(
    table: Any,
    index: int,
    seen_names: set[str],
    found: dict[str, ManifestError],
) -> None:
    base = f"tables[{index}]"
    if not isinstance(table, dict):
        _record(found, "invalid_type", base)
        return
    _check_keys(table, base, _TABLE_FIELDS, found)
    if "name" in table:
        name = table["name"]
        path = _join(base, "name")
        if not isinstance(name, str):
            _record(found, "invalid_type", path)
        elif _NAME_PATTERN.fullmatch(name) is None:
            _record(found, "invalid_format", path)
        elif name in seen_names:
            _record(found, "duplicate_table", path)
        else:
            seen_names.add(name)
    if "location" in table and not isinstance(table["location"], str):
        _record(found, "invalid_type", _join(base, "location"))
    if "row_count" in table:
        row_count = table["row_count"]
        path = _join(base, "row_count")
        if isinstance(row_count, bool) or not isinstance(row_count, int):
            _record(found, "invalid_type", path)
        elif row_count < 0 or row_count > MAX_ROW_COUNT:
            _record(found, "invalid_row_count", path)
    _check_columns(table, base, found)
    if "sha256" in table:
        digest = table["sha256"]
        path = _join(base, "sha256")
        if not isinstance(digest, str):
            _record(found, "invalid_type", path)
        elif _DIGEST_PATTERN.fullmatch(digest) is None:
            _record(found, "invalid_format", path)


def _check_tables(
    data: Mapping[str, Any], found: dict[str, ManifestError]
) -> None:
    if "tables" not in data:
        return
    value = data["tables"]
    if not isinstance(value, list):
        _record(found, "invalid_type", "tables")
        return
    if not value:
        _record(found, "invalid_format", "tables")
        return
    if len(value) > MAX_TABLES:
        _record(found, "too_many_tables", "tables")
        return
    seen_names: set[str] = set()
    for index, table in enumerate(value):
        _check_table(table, index, seen_names, found)


def validate_manifest(
    data: Mapping[str, Any], *, table_digests: Mapping[str, str] | None = None
) -> list[ManifestError]:
    found: dict[str, ManifestError] = {}
    if not isinstance(data, Mapping):
        _record(found, "not_object", "manifest")
        return sorted(found.values(), key=lambda error: (error.path, error.code))
    _check_keys(data, "", _TOP_LEVEL_FIELDS, found)
    _check_contract_version(data, found)
    _check_release_id(data, found)
    _check_deidentification(data, found)
    _check_tables(data, found)
    return sorted(found.values(), key=lambda error: (error.path, error.code))
