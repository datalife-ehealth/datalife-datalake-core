"""Validation tests for hardened JSON, XML, and DICOM JSON ingestion.

The suite exercises the ingestion endpoint end to end plus focused unit tests for
the bounded parser in ``services.parsing``. All fixtures are synthetic; no network,
external entities, or proprietary data are used.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from api.routes.ingestion import reset_store
from main import app
from services.parsing import (
    ParseError,
    PayloadKind,
    parse_payload,
)


@pytest.fixture(autouse=True)
def clean_store():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _ingest(client: TestClient, kind: str, media_type: str, body: str):
    return client.post(
        "/api/v1/ingest",
        json={"subject_key": "subj-0001", "kind": kind, "media_type": media_type, "body": body},
    )


# --------------------------------------------------------------------- JSON path


def test_valid_json_object_is_accepted_with_stable_digest(client):
    body = '{"panel": "metabolic", "values": [1, 2, 3]}'
    response = _ingest(client, "json", "application/json", body)
    assert response.status_code == 200
    record = response.json()
    expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert record["payload_sha256"] == expected
    assert record["object_key"] == expected[:32]
    assert record["kind"] == "json"
    assert record["media_type"] == "application/json"


def test_valid_json_array_root_is_accepted(client):
    response = _ingest(client, "json", "application/json", '[{"a": 1}, {"b": 2}]')
    assert response.status_code == 200


def test_malformed_json_is_rejected(client):
    response = _ingest(client, "json", "application/json", '{"a": }')
    assert response.status_code == 422


def test_duplicate_json_keys_are_rejected(client):
    response = _ingest(client, "json", "application/json", '{"a": 1, "a": 2}')
    assert response.status_code == 422


def test_scalar_json_root_is_rejected(client):
    response = _ingest(client, "json", "application/json", "42")
    assert response.status_code == 422


def test_json_with_mismatched_media_type_is_rejected(client):
    response = _ingest(client, "json", "application/xml", '{"a": 1}')
    assert response.status_code == 422


# ---------------------------------------------------------------------- XML path


def test_valid_xml_is_accepted(client):
    body = '<Panel><Hemoglobin value="13.2"/></Panel>'
    response = _ingest(client, "xml", "application/xml", body)
    assert response.status_code == 200
    assert response.json()["payload_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_namespace_qualified_xml_is_accepted(client):
    body = '<ns:Panel xmlns:ns="urn:datalife:lab"><ns:Hemoglobin value="13.2"/></ns:Panel>'
    assert _ingest(client, "xml", "application/xml", body).status_code == 200


def test_text_xml_alias_is_accepted(client):
    assert _ingest(client, "xml", "text/xml", "<Panel/>").status_code == 200


def test_malformed_xml_is_rejected(client):
    assert _ingest(client, "xml", "application/xml", "<Panel><unclosed>").status_code == 422


def test_xml_doctype_is_rejected(client):
    body = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x "y">]><foo>&x;</foo>'
    assert _ingest(client, "xml", "application/xml", body).status_code == 422


def test_xml_billion_laughs_is_rejected(client):
    body = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE lolz [<!ENTITY lol \"lol\">"
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>'
        "<lolz>&lol2;</lolz>"
    )
    assert _ingest(client, "xml", "application/xml", body).status_code == 422


def test_xml_external_entity_is_rejected(client):
    body = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    assert _ingest(client, "xml", "application/xml", body).status_code == 422


# -------------------------------------------------------------------- DICOM path


def test_valid_dicom_json_subset_is_accepted(client):
    body = '{"00080060": {"vr": "CS", "Value": ["MR"]}, "00100020": {"vr": "LO", "Value": ["anon-1"]}}'
    response = _ingest(client, "dicom", "application/dicom+json", body)
    assert response.status_code == 200
    assert response.json()["payload_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_mixed_case_dicom_tag_is_accepted(client):
    body = '{"0008beef": {"vr": "cs", "Value": ["X"]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 200


def test_dicom_entry_without_value_is_accepted(client):
    assert _ingest(client, "dicom", "application/dicom+json", '{"00080060": {"vr": "CS"}}').status_code == 200


def test_dicom_inline_binary_is_rejected(client):
    body = '{"00080060": {"vr": "OB", "InlineBinary": "AAAA"}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_bulk_data_uri_is_rejected(client):
    body = '{"00080060": {"vr": "CS", "BulkDataURI": "http://x/y"}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_pixel_data_tag_is_rejected(client):
    body = '{"7FE00010": {"vr": "OW"}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_malformed_tag_is_rejected(client):
    assert _ingest(client, "dicom", "application/dicom+json", '{"00GG0060": {"vr": "CS"}}').status_code == 422


def test_dicom_unsupported_vr_is_rejected(client):
    assert _ingest(client, "dicom", "application/dicom+json", '{"00080060": {"vr": "OB"}}').status_code == 422


def test_dicom_wrong_media_type_is_rejected(client):
    assert _ingest(client, "dicom", "application/json", '{"00080060": {"vr": "CS"}}').status_code == 422


def test_dicom_array_root_is_rejected(client):
    assert _ingest(client, "dicom", "application/dicom+json", "[]").status_code == 422


# ----------------------------------------- review follow-ups: hardened edge cases


def test_dicom_nested_object_in_value_is_rejected(client):
    # A binary reference smuggled as a nested object inside Value must not slip through.
    body = '{"00080060": {"vr": "CS", "Value": [{"BulkDataURI": "http://x/y"}]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_nested_array_in_value_is_rejected(client):
    body = '{"00080060": {"vr": "CS", "Value": [[1, 2]]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_boolean_in_value_is_rejected(client):
    body = '{"00080060": {"vr": "CS", "Value": [true]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_scalar_values_are_accepted(client):
    body = '{"00200013": {"vr": "IS", "Value": [1, 2.5, "3"]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 200


def test_dicom_unknown_entry_field_is_rejected(client):
    body = '{"00080060": {"vr": "CS", "Value": ["MR"], "unexpected": 1}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_dicom_case_collision_is_rejected(client):
    # Distinct raw keys that normalize to the same tag must fail rather than overwrite.
    body = '{"0008beef": {"vr": "CS", "Value": ["A"]}, "0008BEEF": {"vr": "LO", "Value": ["B"]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_json_rejects_nan_and_infinity(client, literal):
    body = '{"x": ' + literal + "}"
    assert _ingest(client, "json", "application/json", body).status_code == 422


def test_lone_surrogate_body_is_rejected_cleanly(client):
    # An escaped lone surrogate cannot be encoded as UTF-8; it must map to 422, not 500.
    # Send the request as raw ASCII bytes (json.dumps escapes the surrogate to \ud800)
    # so the server decodes the lone surrogate exactly as a hostile client would send it.
    raw = json.dumps(
        {
            "subject_key": "subj-0001",
            "kind": "json",
            "media_type": "application/json",
            "body": '{"x": "\ud800"}',
        }
    )
    response = client.post("/api/v1/ingest", content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 422


def test_parse_payload_rejects_lone_surrogate():
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", '{"x": "\ud800"}', **_LIMITS)


def test_parse_payload_rejects_nan_constant():
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", '{"x": NaN}', **_LIMITS)


# ----------------------------------------- second review pass: runtime edge cases


@pytest.mark.parametrize("tag", ["+0000060", "0008_060", " 0008060", "0008006"])
def test_dicom_lenient_tag_forms_are_rejected(client, tag):
    # int(tag, 16) tolerates signs/underscores/whitespace; the strict regex must not.
    body = '{"' + tag + '": {"vr": "CS"}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_json_float_overflow_is_rejected(client):
    assert _ingest(client, "json", "application/json", '{"x": 1e999}').status_code == 422


def test_dicom_float_overflow_in_value_is_rejected(client):
    body = '{"00200013": {"vr": "DS", "Value": [1e999]}}'
    assert _ingest(client, "dicom", "application/dicom+json", body).status_code == 422


def test_escaped_surrogate_inside_json_string_is_rejected(client):
    # The body field is valid ASCII; the inner JSON decodes "\ud800" to a lone
    # surrogate, which must be rejected rather than carried forward.
    assert _ingest(client, "json", "application/json", '{"x": "\\ud800"}').status_code == 422


def test_escaped_surrogate_in_object_key_is_rejected(client):
    assert _ingest(client, "json", "application/json", '{"\\ud800": 1}').status_code == 422


def test_parse_payload_rejects_float_overflow():
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", '{"x": 1e999}', **_LIMITS)


def test_parse_payload_rejects_escaped_surrogate():
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", '{"x": "\\ud800"}', **_LIMITS)


def test_validation_error_keeps_structured_shape_without_input(client):
    secret = "CANARY-VALIDATE-7d2e"
    # Invalid kind (fails the model pattern) carrying a secret in the rejected field.
    response = _ingest(client, secret, "application/json", '{"a": 1}')
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, list) and detail
    for item in detail:
        assert set(item.keys()) == {"type", "loc", "msg"}
        assert "input" not in item
    assert secret not in response.text


def test_other_routes_keep_structured_validation_errors(client):
    # The custom handler must not break the HTTPValidationError contract elsewhere.
    response = client.post("/api/v1/access/otp", json={"physician_id": "PHY-0001"})
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)


# -------------------------------------------------- non-reflective error contract


def test_error_response_does_not_echo_payload_or_secret(client):
    secret = "CANARY-9b1c3d-DO-NOT-ECHO"
    body = '{"leak": ' + secret + "}"  # intentionally invalid JSON embedding a secret
    response = _ingest(client, "json", "application/json", body)
    assert response.status_code == 422
    assert secret not in response.text
    assert body not in response.text


def test_error_logs_do_not_contain_secret(client, caplog):
    secret = "CANARY-LOG-5a7f9e"
    body = "<Panel>" + secret + "<!DOCTYPE"  # malformed XML carrying a secret
    with caplog.at_level("DEBUG"):
        response = _ingest(client, "xml", "application/xml", body)
    assert response.status_code == 422
    assert secret not in caplog.text


# ---------------------------------------------------------- parser unit: limits

_LIMITS = {"max_body_bytes": 10_000, "max_depth": 16, "max_nodes": 100, "max_dicom_values": 8}


def test_parse_payload_rejects_oversized_body():
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", '{"a": 1}', **{**_LIMITS, "max_body_bytes": 4})


def test_parse_payload_rejects_excessive_json_depth():
    body = "[" * 50 + "]" * 50
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", body, **_LIMITS)


def test_parse_payload_rejects_excessive_json_nodes():
    body = "[" + ",".join("1" for _ in range(200)) + "]"
    with pytest.raises(ParseError):
        parse_payload("json", "application/json", body, **{**_LIMITS, "max_nodes": 10})


def test_parse_payload_rejects_excessive_xml_depth():
    body = "<a>" * 50 + "</a>" * 50
    with pytest.raises(ParseError):
        parse_payload("xml", "application/xml", body, **_LIMITS)


def test_parse_payload_rejects_long_dicom_value_array():
    values = ", ".join('"x"' for _ in range(50))
    body = '{"00080060": {"vr": "CS", "Value": [' + values + "]}}"
    with pytest.raises(ParseError):
        parse_payload("dicom", "application/dicom+json", body, **_LIMITS)


def test_parse_payload_returns_typed_result_for_each_kind():
    json_result = parse_payload("json", "application/json", '{"a": 1}', **_LIMITS)
    assert json_result.kind is PayloadKind.JSON
    assert json_result.normalized == {"a": 1}
    assert "a" in json_result.keys

    xml_result = parse_payload("xml", "application/xml", '<Panel code="x"/>', **_LIMITS)
    assert xml_result.kind is PayloadKind.XML
    assert xml_result.normalized.tag == "Panel"
    assert xml_result.normalized.attributes == {"code": "x"}

    dicom_result = parse_payload(
        "dicom", "application/dicom+json", '{"0008beef": {"vr": "cs", "Value": ["MR"]}}', **_LIMITS
    )
    assert dicom_result.kind is PayloadKind.DICOM
    assert dicom_result.normalized == {"0008BEEF": {"vr": "CS", "Value": ["MR"]}}
    assert "0008BEEF" in dicom_result.keys
