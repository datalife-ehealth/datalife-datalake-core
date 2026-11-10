from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from services.export_contract import (
    ERROR_CODES,
    MAX_COLUMNS,
    MAX_MANIFEST_BYTES,
    MAX_ROW_COUNT,
    MAX_TABLES,
    ManifestError,
    compute_table_digest,
    format_error,
    is_compatible,
    load_manifest,
    main,
    parse_version,
    validate_manifest,
    validate_manifest_bytes,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFEST_PATH = FIXTURES / "export_manifest_v1.json"
ROWS_PATH = FIXTURES / "export_rows_v1.json"
SENTINEL = "zz-sentinel-9f3"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest() -> dict[str, Any]:
    return _load(MANIFEST_PATH)


def _rows() -> dict[str, Any]:
    return _load(ROWS_PATH)


def _digests(
    manifest: dict[str, Any], rows: dict[str, Any]
) -> dict[str, str]:
    return {
        table["name"]: compute_table_digest(rows[table["name"]])
        for table in manifest["tables"]
    }


def _check(
    errors: list[ManifestError], expected: list[tuple[str, str]]
) -> None:
    assert [(error.code, error.path) for error in errors] == expected
    for error in errors:
        assert error.code in ERROR_CODES
        assert format_error(error) == f"{error.code} {error.path}"


def test_valid_fixture_passes() -> None:
    manifest = _manifest()
    rows = _rows()
    _check(validate_manifest(manifest), [])
    _check(validate_manifest(manifest, table_digests=_digests(manifest, rows)), [])


def test_fixture_digests_match_rows() -> None:
    manifest = _manifest()
    rows = _rows()
    for table in manifest["tables"]:
        data = rows[table["name"]]
        assert table["sha256"] == compute_table_digest(data)
        assert table["row_count"] == len(data)


def test_digest_is_deterministic() -> None:
    rows = _rows()["observations"]
    assert compute_table_digest(rows) == compute_table_digest(rows)
    assert compute_table_digest(rows) == compute_table_digest(deepcopy(rows))


@pytest.mark.parametrize(
    "field", ["contract_version", "release_id", "deidentification", "tables"]
)
def test_missing_top_level_field(field: str) -> None:
    manifest = _manifest()
    del manifest[field]
    _check(validate_manifest(manifest), [("missing_field", field)])


@pytest.mark.parametrize(
    "field", ["name", "location", "row_count", "columns", "sha256"]
)
def test_missing_table_field(field: str) -> None:
    manifest = _manifest()
    del manifest["tables"][0][field]
    _check(validate_manifest(manifest), [("missing_field", f"tables[0].{field}")])


def test_unexpected_field_uses_placeholder() -> None:
    manifest = _manifest()
    manifest["sentinel_extra_key"] = 1
    manifest["tables"][0]["sentinel_extra_key"] = 2
    errors = validate_manifest(manifest)
    _check(
        errors,
        [
            ("unexpected_field", "<key>"),
            ("unexpected_field", "tables[0].<key>"),
        ],
    )
    for error in errors:
        assert "sentinel_extra_key" not in error.code
        assert "sentinel_extra_key" not in error.path
        assert "sentinel_extra_key" not in format_error(error)


@pytest.mark.parametrize("release_id", ["rel-26-1", "REL-2026-0001", "rel-2026-00012"])
def test_invalid_release_id(release_id: str) -> None:
    manifest = _manifest()
    manifest["release_id"] = release_id
    _check(validate_manifest(manifest), [("invalid_format", "release_id")])


@pytest.mark.parametrize(
    ("row_count", "code"),
    [
        (-1, "invalid_row_count"),
        (MAX_ROW_COUNT + 1, "invalid_row_count"),
        (True, "invalid_type"),
        (1.5, "invalid_type"),
        ("4", "invalid_type"),
    ],
)
def test_row_count_rules(row_count: Any, code: str) -> None:
    manifest = _manifest()
    manifest["tables"][0]["row_count"] = row_count
    _check(validate_manifest(manifest), [(code, "tables[0].row_count")])


@pytest.mark.parametrize("sha256", ["A" * 64, "a" * 63, "g" * 64])
def test_invalid_sha256_format(sha256: str) -> None:
    manifest = _manifest()
    manifest["tables"][0]["sha256"] = sha256
    _check(validate_manifest(manifest), [("invalid_format", "tables[0].sha256")])


def test_duplicate_table_and_column() -> None:
    manifest = _manifest()
    manifest["tables"][1]["name"] = manifest["tables"][0]["name"]
    _check(validate_manifest(manifest), [("duplicate_table", "tables[1].name")])

    manifest = _manifest()
    manifest["tables"][0]["columns"][2] = manifest["tables"][0]["columns"][1]
    _check(validate_manifest(manifest), [("duplicate_column", "tables[0].columns[2]")])


def test_hash_mismatch() -> None:
    manifest = _manifest()
    rows = _rows()
    digests = _digests(manifest, rows)
    digests["observations"] = "0" * 64
    _check(
        validate_manifest(manifest, table_digests=digests),
        [("hash_mismatch", "tables[0].sha256")],
    )
    partial = _digests(manifest, rows)
    del partial["lab_panels"]
    _check(
        validate_manifest(manifest, table_digests=partial),
        [("hash_mismatch", "tables[1].sha256")],
    )


@pytest.mark.parametrize(
    "column", ["full_name", "patientId", "email", "cpf", "date_of_birth", "phone_number"]
)
def test_identity_columns_rejected(column: str) -> None:
    manifest = _manifest()
    manifest["tables"][0]["columns"].append(column)
    _check(
        validate_manifest(manifest),
        [("forbidden_identity_field", "tables[0].columns[4]")],
    )


def test_subject_key_column_allowed() -> None:
    manifest = _manifest()
    assert "subject_key" in manifest["tables"][0]["columns"]
    _check(validate_manifest(manifest), [])


@pytest.mark.parametrize(
    "column", ["object_key", "token", "https://host/x", "/api/v1/x"]
)
def test_reference_columns_rejected(column: str) -> None:
    manifest = _manifest()
    manifest["tables"][0]["columns"].append(column)
    _check(
        validate_manifest(manifest),
        [("forbidden_reference", "tables[0].columns[4]")],
    )


@pytest.mark.parametrize(
    ("location", "code"),
    [
        ("https://host/x", "forbidden_reference"),
        ("/abs/x.jsonl", "forbidden_reference"),
        ("releases/rel-2026-0001/../x.jsonl", "unapproved_location"),
        ("releases/rel-2026-0002/observations.jsonl", "unapproved_location"),
        ("releases/rel-2026-0001/lab_panels.jsonl", "unapproved_location"),
        ("releases/rel-2026-0001/observations.parquet", "unapproved_location"),
        ("releases\\rel-2026-0001\\observations.jsonl", "unapproved_location"),
    ],
)
def test_location_rules(location: str, code: str) -> None:
    manifest = _manifest()
    manifest["tables"][0]["location"] = location
    _check(validate_manifest(manifest), [(code, "tables[0].location")])


@pytest.mark.parametrize(
    "flag", ["direct_identifiers_removed", "subject_key_pseudonymous"]
)
def test_deidentification_flags(flag: str) -> None:
    manifest = _manifest()
    manifest["deidentification"][flag] = False
    _check(
        validate_manifest(manifest),
        [("policy_violation", f"deidentification.{flag}")],
    )
    manifest = _manifest()
    manifest["deidentification"][flag] = "true"
    _check(
        validate_manifest(manifest),
        [("invalid_type", f"deidentification.{flag}")],
    )


@pytest.mark.parametrize(
    ("version", "code"),
    [
        ("1.0", None),
        ("1.1", "incompatible_version"),
        ("2.0", "incompatible_version"),
        ("0.9", "incompatible_version"),
        ("1", "invalid_format"),
        ("v1.0", "invalid_format"),
        ("01.0", "invalid_format"),
        ("1.0.0", "invalid_format"),
    ],
)
def test_version_compatibility(version: str, code: str | None) -> None:
    manifest = _manifest()
    manifest["contract_version"] = version
    expected = [] if code is None else [(code, "contract_version")]
    _check(validate_manifest(manifest), expected)
    assert (parse_version(version) is not None) is (code != "invalid_format")
    assert is_compatible(version) is (code is None)


def test_version_helpers() -> None:
    assert parse_version("1.0") == (1, 0)
    assert parse_version("1.7") == (1, 7)
    assert parse_version("01.0") is None
    assert parse_version("1") is None
    assert parse_version("1.0.0") is None
    assert is_compatible("1.0") is True
    assert is_compatible("1.0", (1, 2)) is True
    assert is_compatible("1.1") is False
    assert is_compatible("1.3", (1, 2)) is False
    assert is_compatible("2.0") is False
    assert is_compatible("bogus") is False


def test_limits() -> None:
    manifest = _manifest()
    manifest["tables"] = [
        deepcopy(manifest["tables"][0]) for _ in range(MAX_TABLES + 1)
    ]
    _check(validate_manifest(manifest), [("too_many_tables", "tables")])

    manifest = _manifest()
    manifest["tables"][0]["columns"] = [
        f"col_{index}" for index in range(MAX_COLUMNS + 1)
    ]
    _check(validate_manifest(manifest), [("too_many_columns", "tables[0].columns")])

    _check(
        validate_manifest_bytes(b" " * (MAX_MANIFEST_BYTES + 1)),
        [("too_large", "$")],
    )


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'{"a": "\xff"}', "invalid_json"),
        (b'{"a": 1', "invalid_json"),
        (b'{"a": 1, "a": 2}', "invalid_json"),
        (b'{"a": NaN}', "invalid_json"),
        (b"[]", "not_object"),
        (b"7", "not_object"),
    ],
)
def test_load_manifest_rejects_bad_bytes(raw: bytes, code: str) -> None:
    data, errors = load_manifest(raw)
    assert data is None
    _check(errors, [(code, "$")])
    _check(validate_manifest_bytes(raw), [(code, "$")])


def test_errors_never_echo_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest()
    manifest["release_id"] = SENTINEL
    manifest[SENTINEL] = 1
    manifest["tables"][0]["name"] = SENTINEL
    manifest["tables"][0]["columns"][0] = SENTINEL
    manifest["tables"][0]["location"] = SENTINEL
    errors = validate_manifest(manifest)
    assert errors
    for error in errors:
        assert SENTINEL not in error.code
        assert SENTINEL not in error.path
        assert SENTINEL not in format_error(error)

    path = tmp_path / "sentinel.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert main([str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.out
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err


def test_errors_are_sorted_and_stable() -> None:
    manifest = _manifest()
    manifest["release_id"] = "bad"
    manifest["contract_version"] = "9.9"
    del manifest["tables"][0]["row_count"]
    manifest["tables"][1]["columns"].append("Bad")
    errors = validate_manifest(manifest)
    pairs = [(error.path, error.code) for error in errors]
    assert pairs == sorted(pairs)
    assert len(errors) == len({error.path for error in errors})
    assert [error.path for error in errors] == [
        "contract_version",
        "release_id",
        "tables[0].row_count",
        "tables[1].columns[3]",
    ]
    assert errors == validate_manifest(deepcopy(manifest))


def test_all_codes_are_known() -> None:
    manifests: list[dict[str, Any]] = []
    for field in ("contract_version", "release_id", "deidentification", "tables"):
        broken = _manifest()
        del broken[field]
        manifests.append(broken)
    for mutate in (
        lambda item: item.__setitem__("contract_version", "9.9"),
        lambda item: item.__setitem__("release_id", "bad"),
        lambda item: item["deidentification"].__setitem__(
            "direct_identifiers_removed", False
        ),
        lambda item: item["tables"][0].__setitem__("row_count", -1),
        lambda item: item["tables"][0].__setitem__("sha256", "zz"),
        lambda item: item["tables"][0].__setitem__("columns", ["email"]),
        lambda item: item["tables"][0].__setitem__("columns", ["token"]),
        lambda item: item["tables"][0].__setitem__("location", "https://host/x"),
        lambda item: item["tables"][0].__setitem__("location", "elsewhere"),
        lambda item: item["tables"][0].__setitem__("sentinel_extra_key", 1),
        lambda item: item["tables"][1].__setitem__("name", "observations"),
        lambda item: item["tables"][0].__setitem__("columns", []),
        lambda item: item.__setitem__("tables", []),
        lambda item: item.__setitem__("tables", ["nope"]),
        lambda item: item.__setitem__("deidentification", []),
    ):
        broken = _manifest()
        mutate(broken)
        manifests.append(broken)
    seen: set[str] = set()
    for manifest in manifests:
        errors = validate_manifest(manifest)
        assert errors
        for error in errors:
            assert error.code in ERROR_CODES
            seen.add(error.code)
    assert seen
    assert seen <= ERROR_CODES


def test_cli_ok(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(MANIFEST_PATH)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "ok\n"
    assert captured.err == ""


def test_cli_reports_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest()
    manifest["release_id"] = "bad"
    del manifest["tables"][0]["sha256"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    expected = validate_manifest(manifest)
    assert main([str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "".join(
        f"{format_error(error)}\n" for error in expected
    )
    assert captured.out.splitlines() == [
        "invalid_format release_id",
        "missing_field tables[0].sha256",
    ]


def test_cli_digests_option(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest()
    rows = _rows()
    digests = _digests(manifest, rows)
    good = tmp_path / "good.json"
    good.write_text(json.dumps(digests), encoding="utf-8")
    assert main([str(MANIFEST_PATH), "--digests", str(good)]) == 0
    assert capsys.readouterr().out == "ok\n"

    wrong = tmp_path / "wrong.json"
    digests["observations"] = "0" * 64
    wrong.write_text(json.dumps(digests), encoding="utf-8")
    assert main([str(MANIFEST_PATH), "--digests", str(wrong)]) == 1
    assert capsys.readouterr().out == "hash_mismatch tables[0].sha256\n"


def test_cli_unreadable_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(tmp_path / "missing.json")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: unreadable input\n"
