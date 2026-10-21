"""Tests for the contextual PII rejection policy (services.pii) and its wiring.

Unit tests exercise the framework-independent policy directly; API tests confirm the
ingestion and glass-break boundaries reject identifiers without reflecting the value
into the response, logs, or the audit chain. Positives use unmistakably synthetic
values; negatives use realistic clinical content to guard against false positives.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from api.routes.access import audit_log, reset_access_store
from api.routes.ingestion import reset_store
from main import app
from services.parsing import ParseError, parse_payload
from services.pii import PiiFinding, scan_payload, scan_text

_LIMITS = {"max_body_bytes": 100_000, "max_depth": 32, "max_nodes": 2_000, "max_dicom_values": 64}


@pytest.fixture(autouse=True)
def clean_state():
    reset_store()
    reset_access_store()
    yield
    reset_store()
    reset_access_store()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _scan(kind: str, media_type: str, body: str) -> list[PiiFinding]:
    return scan_payload(parse_payload(kind, media_type, body, **_LIMITS))


def _ingest(client: TestClient, kind: str, media_type: str, body: str):
    return client.post(
        "/api/v1/ingest",
        json={"subject_key": "subj-0001", "kind": kind, "media_type": media_type, "body": body},
    )


# ------------------------------------------------------- unit: JSON field + values


def test_json_identity_key_is_flagged_by_category():
    findings = _scan("json", "application/json", '{"patient": {"full_name": "x"}}')
    assert any(f.category == "patient_name" for f in findings)


@pytest.mark.parametrize(
    "key,category",
    [
        ("email", "email"),
        ("phone_number", "phone"),
        ("cpf", "government_id"),
        ("date_of_birth", "date_of_birth"),
        ("emergency_contact", "emergency_contact"),
        ("address", "address"),
    ],
)
def test_json_identity_key_variants(key, category):
    findings = _scan("json", "application/json", '{"' + key + '": "value"}')
    assert any(f.category == category for f in findings)


def test_json_email_value_is_flagged_without_reflecting_it():
    email = "jane.doe@example.com"
    findings = _scan("json", "application/json", '{"note": "contact ' + email + '"}')
    assert findings and findings[0].category == "email"
    # The matched value must never appear in a finding.
    assert all(email not in f.path for f in findings)
    assert email not in repr(findings)


def test_json_cpf_value_is_flagged():
    findings = _scan("json", "application/json", '{"ref": "012.345.678-90"}')
    assert any(f.category == "government_id" for f in findings)


def test_json_email_as_key_uses_placeholder_path():
    findings = _scan("json", "application/json", '{"john@example.com": 1}')
    assert findings and findings[0].category == "email"
    assert "john@example.com" not in repr(findings)
    assert findings[0].path.endswith("<key>")


# ----------------------------------------------------------- unit: false positives


@pytest.mark.parametrize(
    "body",
    [
        '{"observation": {"code": "789-8", "value": 13.2, "unit": "g/dL"}}',
        '{"panel": {"loinc": "2160-0", "collected": "2024-03-15"}}',
        '{"vitals": [{"hr": 72}, {"spo2": 98}]}',
        '{"namespace": "clinical", "filename": "report.txt"}',
    ],
)
def test_clinical_json_negatives_are_not_flagged(body):
    assert _scan("json", "application/json", body) == []


# --------------------------------------------------------------------- unit: XML


def test_xml_cpf_element_is_flagged():
    findings = _scan("xml", "application/xml", "<Record><cpf>000</cpf></Record>")
    assert any(f.category == "government_id" for f in findings)


def test_xml_patient_name_element_is_flagged():
    findings = _scan("xml", "application/xml", "<Record><PatientName>x</PatientName></Record>")
    assert any(f.category == "patient_name" for f in findings)


def test_xml_email_attribute_value_is_flagged():
    findings = _scan("xml", "application/xml", '<Record contact="a.b@example.org"/>')
    assert any(f.category == "email" for f in findings)


def test_xml_clinical_negative_is_not_flagged():
    assert _scan("xml", "application/xml", '<Panel><Hemoglobin value="13.2"/></Panel>') == []


# ------------------------------------------------------------------- unit: DICOM


@pytest.mark.parametrize(
    "tag,vr,category",
    [
        ("00100010", "PN", "patient_name"),
        ("00100020", "LO", "government_id"),
        ("00100030", "DA", "date_of_birth"),
        ("00101040", "LO", "address"),
    ],
)
def test_dicom_identity_tags_are_flagged(tag, vr, category):
    body = '{"' + tag + '": {"vr": "' + vr + '", "Value": ["x"]}}'
    findings = _scan("dicom", "application/dicom+json", body)
    assert any(f.category == category for f in findings)


def test_dicom_clinical_tag_is_not_flagged():
    assert _scan("dicom", "application/dicom+json", '{"00080060": {"vr": "CS", "Value": ["MR"]}}') == []


# --------------------------------------------------------------- unit: free text


def test_scan_text_flags_email_in_reason():
    findings = scan_text("reach the family at kin@example.com")
    assert findings and findings[0].category == "email"


def test_scan_text_allows_clinical_reason():
    assert scan_text("patient unconscious on arrival, GCS 3") == []


# ------------------------------------------------------------- API: ingestion wiring


def test_ingest_rejects_identity_key_with_stable_message(client):
    response = _ingest(client, "json", "application/json", '{"full_name": "Jane Doe"}')
    assert response.status_code == 422
    assert response.json()["detail"] == "personal identifiers are not accepted by the lake tier"


def test_ingest_does_not_reflect_identifier_value(client):
    email = "canary.patient@example.com"
    response = _ingest(client, "json", "application/json", '{"note": "' + email + '"}')
    assert response.status_code == 422
    assert email not in response.text


def test_ingest_accepts_safe_clinical_payload(client):
    response = _ingest(client, "json", "application/json", '{"observation": {"loinc": "2160-0", "value": 13.2}}')
    assert response.status_code == 200


def test_ingest_pii_not_written_to_logs(client, caplog):
    secret = "pii.canary@example.com"
    with caplog.at_level("DEBUG"):
        response = _ingest(client, "json", "application/json", '{"email": "' + secret + '"}')
    assert response.status_code == 422
    assert secret not in caplog.text


# ----------------------------------------------------- API: glass-break reason wiring


def test_glass_break_rejects_pii_reason_and_leaves_ledger_untouched(client):
    before = len(audit_log())
    email = "nextofkin@example.com"
    response = client.post(
        "/api/v1/access/glass-break",
        json={"physician_id": "PHY-0001", "subject_key": "subj-1", "reason": "call " + email},
    )
    assert response.status_code == 422
    assert email not in response.text
    # No grant issued and nothing appended to the audit chain.
    assert len(audit_log()) == before


def test_glass_break_accepts_clean_reason(client):
    response = client.post(
        "/api/v1/access/glass-break",
        json={"physician_id": "PHY-0001", "subject_key": "subj-1", "reason": "unconscious on arrival"},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "UNCONFIRMED"


# -------------------------------------------- review follow-ups: bypass + DoS gaps


@pytest.mark.parametrize(
    "number",
    [
        "202-555-0198",
        "+1 (202) 555-0198",
        "202 555 0198",
        "+55 11 91234-5678",
        "(11) 91234-5678",
        "+44 7911 123456",
        "+33 6 12 34 56 78",
    ],
)
def test_formatted_phone_numbers_are_detected(number):
    findings = scan_text("call the family at " + number)
    assert findings and findings[0].category == "phone"


@pytest.mark.parametrize(
    "text",
    [
        "code 789-8",
        "loinc 2160-0",
        "dose 500 mg",
        "collected 2024-03-15",
        "hemoglobin 13.2",
        "room 4 bed 2",
        # dosage ranges and timestamp-adjacent IDs must not be read as phone numbers
        "recorded 2024-03-15 123-4567",
        "titration 500 250-1000 mg",
        "insulin 10 250-1000 units",
        "fluids 250-1000 ml",
        # spelled-out units and a backtrack-dodge attempt must also be rejected
        "titration 500 250-1000 milligrams",
        "give 20 milligrams",
        "dose +1 20 30 mg",
        # too few digits to be a real phone number (E.164 needs ~7+)
        "dose +1 20 30",
    ],
)
def test_clinical_numbers_are_not_detected_as_phone(text):
    assert scan_text(text) == []


def test_glass_break_international_phone_is_rejected_and_not_in_ledger(client):
    before = len(audit_log())
    number = "+44 7911 123456"
    response = client.post(
        "/api/v1/access/glass-break",
        json={"physician_id": "PHY-0001", "subject_key": "subj-1", "reason": "ring " + number},
    )
    assert response.status_code == 422
    assert number not in response.text
    assert len(audit_log()) == before
    assert number not in repr(audit_log())


def test_glass_break_formatted_phone_is_rejected_and_not_logged_to_ledger(client):
    before = len(audit_log())
    number = "202-555-0198"
    response = client.post(
        "/api/v1/access/glass-break",
        json={"physician_id": "PHY-0001", "subject_key": "subj-1", "reason": "call back " + number},
    )
    assert response.status_code == 422
    assert number not in response.text
    # Nothing appended, and the number is nowhere in the serialized audit chain.
    assert len(audit_log()) == before
    assert number not in repr(audit_log())


def test_namespaced_attribute_collision_is_rejected_at_parse():
    body = '<r xmlns:a="urn:a" xmlns:b="urn:b" a:contact="victim@example.com" b:contact="safe"/>'
    with pytest.raises(ParseError):
        parse_payload("xml", "application/xml", body, **_LIMITS)


def test_namespaced_attribute_collision_payload_is_rejected_without_leak(client):
    email = "victim@example.com"
    body = '<r xmlns:a="urn:a" xmlns:b="urn:b" a:contact="' + email + '" b:contact="safe"/>'
    response = _ingest(client, "xml", "application/xml", body)
    assert response.status_code == 422
    assert email not in response.text


def test_single_namespaced_attribute_value_is_still_scanned():
    body = '<r xmlns:a="urn:a" a:contact="person@example.com"/>'
    findings = scan_payload(parse_payload("xml", "application/xml", body, **_LIMITS))
    assert any(f.category == "email" for f in findings)


def test_email_detection_is_linear_on_large_input():
    # A long local-part-like run with no "@" previously backtracked quadratically.
    # With bounded/possessive quantifiers it must stay fast and not match.
    blob = "a" * 200_000
    start = time.perf_counter()
    result = scan_text(blob)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0


def test_glass_break_reason_length_is_bounded(client):
    response = client.post(
        "/api/v1/access/glass-break",
        json={"physician_id": "PHY-0001", "subject_key": "subj-1", "reason": "x" * 5000},
    )
    assert response.status_code == 422
