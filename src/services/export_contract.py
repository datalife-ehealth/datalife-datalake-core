from __future__ import annotations

import re
from dataclasses import dataclass

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
