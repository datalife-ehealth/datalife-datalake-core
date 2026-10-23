"""Contextual PII rejection policy for the zero-cloud-PII boundary.

This module centralizes the rule that direct patient identity data must never be
accepted into the lake tier or recorded in the audit chain. It operates on the
already-normalized output of :mod:`services.parsing` (JSON values, the XML node
tree, and the DICOM JSON metadata subset) so it never reparses raw input, and it
can also scan a single free-text field such as a glass-break reason.

Design constraints:

* **Framework independent.** Nothing here imports FastAPI. The policy returns a
  list of :class:`PiiFinding` describing *what* category was matched and a *safe
  field path*; the caller decides the HTTP behavior.
* **Zero value reflection.** A finding never contains the matched value. Paths are
  built from structural field names/tags only, and a field name that is itself a
  detected value (for example an email used as an object key) is replaced with a
  ``<key>`` placeholder so nothing sensitive leaks into a response, log, or audit
  event.
* **Fail closed, conservative detectors.** Field-name matching uses an explicit set
  of normalized identity concepts rather than substring guessing, which avoids
  false positives like ``namespace`` or ``filename`` matching ``name``. Value
  detectors cover only unambiguous email, government-ID (CPF/SSN), and formatted
  phone forms. They deliberately require separators/structure so clinical codes and
  measurements (``789-8``, ``13.2``, LOINC codes, ISO dates) are not misread as
  identifiers. This is rejection at the boundary, not de-identification; it makes no
  anonymization or regulatory-conformance claim.

Scope boundaries: opaque ``subject_key`` values, server-issued tokens, and
configured ``physician_id`` values are not identity payloads and are never scanned
by callers of this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from services.parsing import ParseResult, PayloadKind, XmlNode


@dataclass(frozen=True)
class PiiFinding:
    """A single policy hit. Carries the category and a safe field path only."""

    category: str
    path: str


# --------------------------------------------------------------- field-name policy

# Separators and casing are stripped before comparison so "full_name", "Full Name",
# "full-name", and "fullName" all normalize to the same token.
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalize_key(name: str) -> str:
    return _NON_ALNUM.sub("", name.lower())


# Normalized identity concept keys grouped by category. Matching is exact against the
# normalized form, not a substring, to keep false positives down.
_KEY_CATEGORY_GROUPS: dict[str, frozenset[str]] = {
    "patient_name": frozenset(
        {
            "name", "fullname", "firstname", "lastname", "surname", "givenname",
            "familyname", "middlename", "patientname", "personname", "othernames",
            "otherpatientnames",
        }
    ),
    "government_id": frozenset(
        {
            "cpf", "ssn", "rg", "governmentid", "nationalid", "taxid", "patientid",
            "otherpatientids", "issuerofpatientid", "mrn", "medicalrecordnumber",
        }
    ),
    "phone": frozenset(
        {
            "phone", "phonenumber", "telephone", "telephonenumber", "mobile",
            "mobilenumber", "cell", "cellphone", "contactnumber",
            "patienttelephonenumbers",
        }
    ),
    "email": frozenset({"email", "emailaddress"}),
    "address": frozenset(
        {"address", "streetaddress", "homeaddress", "postaladdress", "patientaddress", "residence"}
    ),
    "date_of_birth": frozenset({"dob", "dateofbirth", "birthdate", "birthday", "patientbirthdate"}),
    "emergency_contact": frozenset(
        {"emergencycontact", "emergencycontacts", "emergencyphone", "emergencycontactname", "nextofkin"}
    ),
}

# Flattened normalized-key -> category lookup.
_KEY_CATEGORIES: dict[str, str] = {
    key: category for category, keys in _KEY_CATEGORY_GROUPS.items() for key in keys
}

# DICOM patient-identity tags from the v0.1 metadata contract, mapped to a category.
_DICOM_PII_TAGS: dict[str, str] = {
    "00100010": "patient_name",       # PatientName
    "00101001": "patient_name",       # OtherPatientNames
    "00100020": "government_id",      # PatientID
    "00101000": "government_id",      # OtherPatientIDs
    "00100021": "government_id",      # IssuerOfPatientID
    "00100030": "date_of_birth",      # PatientBirthDate
    "00101040": "address",            # PatientAddress
    "00102154": "phone",              # PatientTelephoneNumbers
}


def _key_category(name: str) -> str | None:
    return _KEY_CATEGORIES.get(_normalize_key(name))


# -------------------------------------------------------------------- value policy

# Unambiguous forms only. Each requires enough structure that ordinary clinical
# numbers/codes do not match (see module docstring for the false-positive stance).
#
# Email: bounded, possessive quantifiers (``{m,n}+``) so there is no backtracking.
# RFC-ish length caps (local <= 64, domain <= 255) keep matching strictly linear in
# the input length, closing the quadratic/ReDoS risk on large inputs.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}+@(?:[A-Za-z0-9\-]{1,63}\.){1,8}+[A-Za-z]{2,24}+")
_CPF_RE = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
# Phone: three accepted shapes, each bounded (so matching stays linear):
#   * +country intl grouping -> +1 (202) 555-0198, +55 11 91234-5678, +44 7911 123456,
#                               +33 6 12 34 56 78 (the first group after the country
#                               code may be a single digit)
#   * parenthesized area code -> (11) 91234-5678
#   * North American 3-3-4    -> 202-555-0198, 202 555 0198
# To keep clinical text from matching, the start must not sit inside a larger
# word/number/date (leading look-behind), the match must not run into more digits,
# and it must not be immediately followed by a clinical unit -- abbreviated or
# spelled out (mg, ml, units, milligrams, ...). The trailing digit groups are matched
# possessively (``{0,4}+``) so the engine cannot backtrack to a shorter match that
# dodges the unit guard (e.g. ``dose +1 20 30 mg``).
_PHONE_RE = re.compile(
    r"(?<![\w\-/.])"
    r"(?:"
    r"\+\d{1,3}[\s.\-]?(?:\(\d{1,4}\)|\d{1,4})(?:[\s.\-]?(?:\(\d{1,4}\)|\d{2,6})){0,4}+"
    r"|\(\d{1,4}\)[\s.\-]?\d{2,6}(?:[\s.\-]\d{2,6}){0,3}+"
    r"|\d{3}[\s.\-]\d{3}[\s.\-]\d{4}"
    r")"
    r"(?!\d)"
    r"(?![\s.\-]?(?:mg|mcg|ug|ml|dl|kg|g|units?|iu|mmol|mol|meq|bpm|mm|cm|hr|hrs|min|sec|kcal|cal"
    r"|milligrams?|micrograms?|millilit(?:er|re)s?|grams?|liters?|litres?)\b)",
    re.IGNORECASE,
)


# A phone-shaped token must carry at least this many digits to count. E.164 numbers
# run ~7-15 digits, so this rejects short separated runs such as "+1 20 30" (which
# otherwise matched the international branch) while still accepting real numbers like
# "+44 7911 123456" or "+33 6 12 34 56 78".
_MIN_PHONE_DIGITS = 7


def _detect_value(text: str) -> str | None:
    """Return a category if ``text`` contains an obvious identifier value.

    All patterns are linear in ``len(text)`` (bounded/possessive quantifiers), so
    this is safe to run on large values; callers additionally bound their inputs
    (ingestion caps the body size and the glass-break reason is length-limited).
    """
    if _EMAIL_RE.search(text):
        return "email"
    if _CPF_RE.search(text) or _SSN_RE.search(text):
        return "government_id"
    # A phone-shaped match only counts once it clears the minimum digit length, so a
    # short clinical sequence does not register while a real number elsewhere still can.
    for match in _PHONE_RE.finditer(text):
        if sum(char.isdigit() for char in match.group()) >= _MIN_PHONE_DIGITS:
            return "phone"
    return None


# ------------------------------------------------------------------- traversal API


def scan_payload(result: ParseResult) -> list[PiiFinding]:
    """Scan a parsed payload for direct identity data.

    Dispatches on the payload kind and traverses the normalized structure, checking
    field/tag names against the identity-concept policy and string values against the
    conservative value detectors.
    """
    if result.kind is PayloadKind.JSON:
        return _scan_json(result.normalized, "json")
    if result.kind is PayloadKind.XML:
        return _scan_xml(result.normalized, "xml")
    return _scan_dicom(result.normalized, "dicom")


def scan_text(text: str, path: str = "reason") -> list[PiiFinding]:
    """Scan a single free-text field (e.g. a glass-break reason) for identifiers."""
    category = _detect_value(text)
    return [PiiFinding(category, path)] if category else []


def _scan_json(root: Any, base: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    stack: list[tuple[Any, str]] = [(root, base)]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                # A key that is itself an identifier value (e.g. an email used as a
                # key) is reported without echoing the key text.
                key_value_category = _detect_value(key)
                if key_value_category:
                    child_path = f"{path}.<key>"
                    findings.append(PiiFinding(key_value_category, child_path))
                else:
                    child_path = f"{path}.{key}"
                    name_category = _key_category(key)
                    if name_category:
                        findings.append(PiiFinding(name_category, child_path))
                stack.append((value, child_path))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                stack.append((value, f"{path}[{index}]"))
        elif isinstance(node, str):
            value_category = _detect_value(node)
            if value_category:
                findings.append(PiiFinding(value_category, path))
    return findings


def _scan_xml(node: XmlNode, base: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    stack: list[tuple[XmlNode, str]] = [(node, f"{base}.{node.tag}")]
    while stack:
        element, path = stack.pop()
        name_category = _key_category(element.tag)
        if name_category:
            findings.append(PiiFinding(name_category, path))
        for attr_name, attr_value in element.attributes.items():
            attr_path = f"{path}@{attr_name}"
            attr_name_category = _key_category(attr_name)
            if attr_name_category:
                findings.append(PiiFinding(attr_name_category, attr_path))
            attr_value_category = _detect_value(attr_value)
            if attr_value_category:
                findings.append(PiiFinding(attr_value_category, attr_path))
        if element.text:
            text_category = _detect_value(element.text)
            if text_category:
                findings.append(PiiFinding(text_category, f"{path}#text"))
        for child in element.children:
            stack.append((child, f"{path}.{child.tag}"))
    return findings


def _scan_dicom(document: dict[str, dict[str, Any]], base: str) -> list[PiiFinding]:
    findings: list[PiiFinding] = []
    for tag, entry in document.items():
        path = f"{base}.{tag}"
        tag_category = _DICOM_PII_TAGS.get(tag)
        if tag_category:
            findings.append(PiiFinding(tag_category, path))
        value = entry.get("Value")
        if isinstance(value, list):
            for index, element in enumerate(value):
                if isinstance(element, str):
                    value_category = _detect_value(element)
                    if value_category:
                        findings.append(PiiFinding(value_category, f"{path}.Value[{index}]"))
    return findings
