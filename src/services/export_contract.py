from __future__ import annotations

import argparse
import hmac
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.crypto import canonical_json, sha256_hex

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
_NON_ALNUM_PATTERN = re.compile(r"[^a-z0-9]+")

_IDENTITY_COLUMNS = frozenset(
    {
        "fullname",
        "firstname",
        "lastname",
        "middlename",
        "name",
        "patientname",
        "patientid",
        "patientidentifier",
        "mrn",
        "medicalrecordnumber",
        "email",
        "emailaddress",
        "cpf",
        "ssn",
        "nationalid",
        "dateofbirth",
        "dob",
        "birthdate",
        "phone",
        "phonenumber",
        "telephone",
        "address",
        "homeaddress",
        "emergencycontact",
    }
)

_REFERENCE_COLUMNS = frozenset(
    {
        "objectkey",
        "payloadsha256",
        "token",
        "granttoken",
        "otp",
    }
)

_TOP_LEVEL_FIELDS = ("contract_version", "release_id", "deidentification", "tables")
_DEIDENTIFICATION_FIELDS = (
    "policy_version",
    "direct_identifiers_removed",
    "subject_key_pseudonymous",
)
_POLICY_FLAGS = ("direct_identifiers_removed", "subject_key_pseudonymous")
_TABLE_FIELDS = ("name", "location", "row_count", "columns", "sha256")
_ROOT_PATH = "$"
_UNREADABLE = "error: unreadable input"


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


def compute_table_digest(rows: list[Any]) -> str:
    return sha256_hex(canonical_json(rows))


def validate_manifest(
    data: Mapping[str, Any], *, table_digests: Mapping[str, str] | None = None
) -> list[ManifestError]:
    found: dict[str, ManifestError] = {}
    if not isinstance(data, Mapping):
        _record(found, "not_object", "manifest")
        return sorted(found.values(), key=lambda error: (error.path, error.code))
    digests = table_digests if isinstance(table_digests, Mapping) else None
    release_id = _valid_release_id(data)
    _check_keys(data, "", _TOP_LEVEL_FIELDS, found)
    _check_contract_version(data, found)
    _check_release_id(data, found)
    _check_deidentification(data, found)
    _check_tables(data, digests, release_id, found)
    return sorted(found.values(), key=lambda error: (error.path, error.code))


def validate_manifest_bytes(
    raw: bytes, *, table_digests: Mapping[str, str] | None = None
) -> list[ManifestError]:
    data, errors = load_manifest(raw)
    if data is None:
        return errors
    return validate_manifest(data, table_digests=table_digests)


def load_manifest(
    raw: bytes,
) -> tuple[dict[str, Any] | None, list[ManifestError]]:
    if not isinstance(raw, (bytes, bytearray)):
        return None, [ManifestError("invalid_json", _ROOT_PATH)]
    if len(raw) > MAX_MANIFEST_BYTES:
        return None, [ManifestError("too_large", _ROOT_PATH)]
    try:
        document = json.loads(
            bytes(raw).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None, [ManifestError("invalid_json", _ROOT_PATH)]
    if not isinstance(document, dict):
        return None, [ManifestError("not_object", _ROOT_PATH)]
    return document, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m services.export_contract")
    parser.add_argument("manifest")
    parser.add_argument("--digests")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.manifest).read_bytes()
    except (OSError, ValueError):
        print(_UNREADABLE, file=sys.stderr)
        return 2
    digests: dict[str, str] | None = None
    if args.digests is not None:
        try:
            digests = _read_digests(Path(args.digests).read_bytes())
        except (OSError, ValueError):
            print(_UNREADABLE, file=sys.stderr)
            return 2
        if digests is None:
            print(_UNREADABLE, file=sys.stderr)
            return 2
    errors = validate_manifest_bytes(raw, table_digests=digests)
    if not errors:
        print("ok")
        return 0
    for error in errors:
        print(format_error(error))
    return 1


def _read_digests(raw: bytes) -> dict[str, str] | None:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    digests: dict[str, str] = {}
    for key, value in document.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None
        digests[key] = value
    return digests


def _record(found: dict[str, ManifestError], code: str, path: str) -> None:
    if path not in found:
        found[path] = ManifestError(code, path)


def _join(prefix: str, key: str) -> str:
    if prefix == "":
        return key
    return f"{prefix}.{key}"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ValueError


def _normalize_key(value: str) -> str:
    return _NON_ALNUM_PATTERN.sub("", value.lower())


def _is_forbidden_identity(value: str) -> bool:
    return _normalize_key(value) in _IDENTITY_COLUMNS


def _is_reference_value(value: str) -> bool:
    return value.startswith("/") or "://" in value


def _is_forbidden_reference(value: str) -> bool:
    if _normalize_key(value) in _REFERENCE_COLUMNS:
        return True
    return _is_reference_value(value)


def _valid_release_id(data: Mapping[str, Any]) -> str | None:
    value = data.get("release_id")
    if not isinstance(value, str):
        return None
    if _RELEASE_ID_PATTERN.fullmatch(value) is None:
        return None
    return value


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
        if _is_forbidden_identity(column):
            _record(found, "forbidden_identity_field", column_path)
            continue
        if _is_forbidden_reference(column):
            _record(found, "forbidden_reference", column_path)
            continue
        if _NAME_PATTERN.fullmatch(column) is None:
            _record(found, "invalid_format", column_path)
            continue
        if column in seen:
            _record(found, "duplicate_column", column_path)
            continue
        seen.add(column)


def _check_location(
    value: str,
    base: str,
    name: str | None,
    release_id: str | None,
    found: dict[str, ManifestError],
) -> None:
    path = _join(base, "location")
    if _is_reference_value(value):
        _record(found, "forbidden_reference", path)
        return
    if name is None or release_id is None:
        return
    if value != f"releases/{release_id}/{name}.jsonl":
        _record(found, "unapproved_location", path)


def _check_table_digest(
    name: str,
    digest: str,
    digests: Mapping[str, str],
    path: str,
    found: dict[str, ManifestError],
) -> None:
    expected = digests.get(name)
    if not isinstance(expected, str) or not expected.isascii():
        _record(found, "hash_mismatch", path)
        return
    if not hmac.compare_digest(expected, digest):
        _record(found, "hash_mismatch", path)


def _check_table(
    table: Any,
    index: int,
    seen_names: set[str],
    digests: Mapping[str, str] | None,
    release_id: str | None,
    found: dict[str, ManifestError],
) -> None:
    base = f"tables[{index}]"
    if not isinstance(table, dict):
        _record(found, "invalid_type", base)
        return
    _check_keys(table, base, _TABLE_FIELDS, found)
    name: str | None = None
    if "name" in table:
        value = table["name"]
        path = _join(base, "name")
        if not isinstance(value, str):
            _record(found, "invalid_type", path)
        elif _NAME_PATTERN.fullmatch(value) is None:
            _record(found, "invalid_format", path)
        elif value in seen_names:
            _record(found, "duplicate_table", path)
        else:
            seen_names.add(value)
            name = value
    if "location" in table:
        location = table["location"]
        if not isinstance(location, str):
            _record(found, "invalid_type", _join(base, "location"))
        else:
            _check_location(location, base, name, release_id, found)
    if "row_count" in table:
        row_count = table["row_count"]
        path = _join(base, "row_count")
        if isinstance(row_count, bool) or not isinstance(row_count, int):
            _record(found, "invalid_type", path)
        elif row_count < 0 or row_count > MAX_ROW_COUNT:
            _record(found, "invalid_row_count", path)
    _check_columns(table, base, found)
    digest: str | None = None
    if "sha256" in table:
        value = table["sha256"]
        path = _join(base, "sha256")
        if not isinstance(value, str):
            _record(found, "invalid_type", path)
        elif _DIGEST_PATTERN.fullmatch(value) is None:
            _record(found, "invalid_format", path)
        else:
            digest = value
    if digests is not None and name is not None and digest is not None:
        _check_table_digest(name, digest, digests, _join(base, "sha256"), found)


def _check_tables(
    data: Mapping[str, Any],
    digests: Mapping[str, str] | None,
    release_id: str | None,
    found: dict[str, ManifestError],
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
        _check_table(table, index, seen_names, digests, release_id, found)


if __name__ == "__main__":
    raise SystemExit(main())
