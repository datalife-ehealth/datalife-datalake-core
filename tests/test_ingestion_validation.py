"""Validation tests for hardened JSON, XML, and DICOM JSON ingestion.

The suite exercises the ingestion endpoint end to end plus focused unit tests for
the bounded parser in ``services.parsing``. All fixtures are synthetic; no network,
external entities, or proprietary data are used.
"""

from __future__ import annotations

import hashlib

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
