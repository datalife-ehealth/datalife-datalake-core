"""Bounded, fail-closed parsing for ingested clinical payloads.

The ingestion endpoint receives an opaque ``body`` string whose structure depends
on the declared ``kind`` (``json``, ``xml``, or ``dicom``). This module is the single
entry point that turns that opaque string into a typed, already-validated structure
that later privacy/validation passes can traverse without reparsing raw input.

Design rules for the v0.1 boundary:

* Enforce a maximum UTF-8 body size and conservative depth/node limits before and
  during parsing. Anything over the limit, malformed, or ambiguous fails closed.
* JSON must be syntactically valid, rooted at an object or array, and free of
  duplicate object keys.
* XML is parsed with DTDs, entity declarations, and external resource resolution
  fully disabled, so document type definitions and entity-expansion payloads are
  rejected rather than processed.
* DICOM is accepted only as the small DICOM JSON metadata subset documented below;
  Part 10 binary, pixel data, inline binary, and bulk-data references are rejected.

Failures are raised as :class:`ParseError` carrying a stable, non-reflective reason.
The reason text is a fixed category string; it never contains the submitted body or
fragments of it, so callers can surface it in responses and logs safely.

This module performs no network access, resolves no external entities or schemas,
and reads no files. It is pure, deterministic, and side-effect free.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from xml.parsers import expat


class PayloadKind(str, Enum):
    """Declared structural family of an ingested payload."""

    JSON = "json"
    XML = "xml"
    DICOM = "dicom"


# Media types accepted for each kind. The ingestion request carries a declared
# media type that must be compatible with the declared kind; anything else is a
# mismatch and fails closed. ``text/xml`` is retained as a backwards-compatible
# alias for ``application/xml`` because device exports still emit it.
_ALLOWED_MEDIA_TYPES: dict[PayloadKind, frozenset[str]] = {
    PayloadKind.JSON: frozenset({"application/json"}),
    PayloadKind.XML: frozenset({"application/xml", "text/xml"}),
    PayloadKind.DICOM: frozenset({"application/dicom+json"}),
}


class ParseError(Exception):
    """A payload was rejected. ``reason`` is a stable, non-reflective category.

    ``reason`` is deliberately a fixed string drawn from a small vocabulary. It must
    never embed the submitted payload or parser fragments, so it is safe to return
    to clients and to write to logs.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ParseResult:
    """Typed outcome of a successful parse.

    ``normalized`` is a structure that downstream validation can traverse without
    touching the raw body again:

    * JSON  -> the decoded object/array (duplicate keys already rejected).
    * XML   -> a nested :class:`XmlNode` tree with namespace-resolved local names.
    * DICOM -> a mapping of upper-case tag -> ``{"vr": str, "Value": list | None}``.

    ``keys`` collects the normalized field/attribute/tag names observed in the
    payload. It exists so the dedicated PII policy work can inspect structure without
    reimplementing parsing; it is intentionally not consumed here.
    """

    kind: PayloadKind
    media_type: str
    normalized: Any
    keys: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class XmlNode:
    """A single XML element with namespace-resolved local names.

    ``text`` accumulates the element's own character data (expat may deliver it in
    several chunks). Child elements are kept in document order.
    """

    tag: str
    attributes: dict[str, str]
    text: str = ""
    children: list["XmlNode"] = field(default_factory=list)


# Reason codes. Kept coarse and input-free on purpose.
_REASON_SIZE = "payload exceeds the maximum allowed size"
_REASON_MEDIA_MISMATCH = "media_type is not compatible with the declared kind"
_REASON_DEPTH = "payload nesting exceeds the maximum allowed depth"
_REASON_NODES = "payload exceeds the maximum allowed number of nodes"
_REASON_ENCODING = "payload is not valid UTF-8 text"
_REASON_JSON_SYNTAX = "payload is not valid JSON"
_REASON_JSON_ROOT = "JSON root must be an object or an array"
_REASON_JSON_DUPLICATE = "JSON object contains duplicate keys"
_REASON_JSON_CONSTANT = "JSON must not contain NaN or Infinity values"
_REASON_XML_SYNTAX = "payload is not well-formed XML"
_REASON_XML_DTD = "XML document type definitions and entities are not accepted"
_REASON_DICOM_ROOT = "DICOM JSON metadata must be a single object of tags"
_REASON_DICOM_TAG = "DICOM tag keys must be eight hexadecimal digits"
_REASON_DICOM_ENTRY = "DICOM tag entry is malformed"
_REASON_DICOM_UNKNOWN_KEY = "DICOM tag entry contains unsupported fields"
_REASON_DICOM_VR = "DICOM value representation is unsupported in this subset"
_REASON_DICOM_BINARY = "DICOM binary, inline-binary, and bulk-data references are not accepted"
_REASON_DICOM_VALUE = "DICOM Value array exceeds the maximum allowed length"
_REASON_DICOM_VALUE_TYPE = "DICOM Value entries must be scalar strings or numbers"
_REASON_DICOM_COLLISION = "DICOM tag is duplicated after case normalization"


def parse_payload(
    kind: str,
    media_type: str,
    body: str,
    *,
    max_body_bytes: int,
    max_depth: int,
    max_nodes: int,
    max_dicom_values: int,
) -> ParseResult:
    """Validate and parse an ingested payload, failing closed on any problem.

    Args:
        kind: Declared payload kind (``json``, ``xml``, or ``dicom``).
        media_type: Declared media type, validated against ``kind``.
        body: The payload as a UTF-8 string (the request body field).
        max_body_bytes: Maximum size of ``body`` in UTF-8 bytes.
        max_depth: Maximum structural nesting depth.
        max_nodes: Maximum number of structural nodes/elements.
        max_dicom_values: Maximum length of a DICOM ``Value`` array.

    Returns:
        A :class:`ParseResult` describing the normalized payload.

    Raises:
        ParseError: If the payload is too large, has an incompatible media type, is
            malformed, or violates any configured limit.
    """
    try:
        payload_kind = PayloadKind(kind)
    except ValueError as exc:  # pragma: no cover - the route constrains kind already
        raise ParseError(_REASON_MEDIA_MISMATCH) from exc

    # Size is checked against the raw UTF-8 encoding, matching the digest contract,
    # and before any parsing so hostile inputs cannot force expensive work. The encode
    # also rejects strings carrying lone surrogates (e.g. an escaped "\ud800") that
    # cannot be represented as UTF-8, mapping them to a clean 422 instead of letting a
    # later UnicodeEncodeError surface as a 500.
    try:
        body_bytes = body.encode("utf-8")
    except UnicodeError as exc:
        raise ParseError(_REASON_ENCODING) from exc
    if len(body_bytes) > max_body_bytes:
        raise ParseError(_REASON_SIZE)

    if media_type not in _ALLOWED_MEDIA_TYPES[payload_kind]:
        raise ParseError(_REASON_MEDIA_MISMATCH)

    if payload_kind is PayloadKind.JSON:
        normalized, keys = _parse_json(body, max_depth=max_depth, max_nodes=max_nodes)
    elif payload_kind is PayloadKind.XML:
        normalized, keys = _parse_xml(body, max_depth=max_depth, max_nodes=max_nodes)
    else:
        normalized, keys = _parse_dicom_json(
            body, max_depth=max_depth, max_nodes=max_nodes, max_dicom_values=max_dicom_values
        )

    return ParseResult(kind=payload_kind, media_type=media_type, normalized=normalized, keys=tuple(keys))


# --------------------------------------------------------------------------- JSON


def _scan_json_depth(body: str, max_depth: int) -> None:
    """Reject JSON whose bracket nesting exceeds ``max_depth``.

    This is a cheap, iterative, string-level pre-scan. Bounding depth before calling
    :func:`json.loads` keeps the standard decoder's recursive descent well away from
    the interpreter recursion limit, so deeply nested adversarial inputs fail closed
    with HTTP 422 instead of raising a ``RecursionError``.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in body:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > max_depth:
                raise ParseError(_REASON_DEPTH)
        elif char in "}]":
            depth -= 1


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects duplicate keys in a JSON object."""
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ParseError(_REASON_JSON_DUPLICATE)
        seen.add(key)
    return dict(pairs)


def _reject_constant(_token: str) -> Any:
    """``parse_constant`` hook rejecting the non-standard NaN/Infinity literals.

    ``json.loads`` accepts ``NaN``, ``Infinity``, and ``-Infinity`` by default; strict
    ingestion must not, so any of them fails closed here.
    """
    raise ParseError(_REASON_JSON_CONSTANT)


def _measure_json(value: Any, max_depth: int, max_nodes: int) -> list[str]:
    """Enforce depth/node limits iteratively and collect observed object keys."""
    keys: list[str] = []
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ParseError(_REASON_NODES)
        if depth > max_depth:
            raise ParseError(_REASON_DEPTH)
        if isinstance(current, dict):
            for key, child in current.items():
                keys.append(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
    return keys


def _parse_json(body: str, max_depth: int, max_nodes: int) -> tuple[Any, list[str]]:
    _scan_json_depth(body, max_depth)
    try:
        value = json.loads(
            body,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ParseError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ParseError(_REASON_JSON_SYNTAX) from exc
    if not isinstance(value, (dict, list)):
        raise ParseError(_REASON_JSON_ROOT)
    keys = _measure_json(value, max_depth=max_depth, max_nodes=max_nodes)
    return value, keys


# ---------------------------------------------------------------------------- XML

# Expat reports namespaced names as "uri<sep>local"; this separator cannot appear in
# a URI or local name, so it unambiguously splits the two.
_XML_NS_SEP = "\x01"


def _local_name(name: str) -> str:
    """Return the local part of a possibly namespace-qualified expat name."""
    return name.rsplit(_XML_NS_SEP, 1)[-1]


def _parse_xml(body: str, max_depth: int, max_nodes: int) -> tuple[XmlNode, list[str]]:
    parser = expat.ParserCreate(namespace_separator=_XML_NS_SEP)

    # Fail closed on anything that could trigger entity expansion or external
    # resolution. Rejecting the DOCTYPE outright also blocks internal-subset
    # "billion laughs" style entity-expansion payloads before they are defined.
    def _reject_dtd(*_args: Any) -> None:
        raise ParseError(_REASON_XML_DTD)

    def _reject_external(*_args: Any) -> int:
        raise ParseError(_REASON_XML_DTD)

    parser.StartDoctypeDeclHandler = _reject_dtd
    parser.EntityDeclHandler = _reject_dtd
    parser.UnparsedEntityDeclHandler = _reject_dtd
    parser.ExternalEntityRefHandler = _reject_external
    # Belt-and-suspenders: expat defaults to not loading an external DTD, but make the
    # intent explicit so a future default change cannot silently open a fetch path.
    try:
        parser.UseForeignDTD(False)
    except expat.error:  # pragma: no cover - only fails after parsing has started
        pass

    keys: list[str] = []
    node_count = 0
    root: XmlNode | None = None
    stack: list[XmlNode] = []

    def start_element(name: str, attributes: dict[str, str]) -> None:
        nonlocal node_count, root
        node_count += 1
        if node_count > max_nodes:
            raise ParseError(_REASON_NODES)
        if len(stack) + 1 > max_depth:
            raise ParseError(_REASON_DEPTH)
        local = _local_name(name)
        normalized_attrs = {_local_name(attr): val for attr, val in attributes.items()}
        keys.append(local)
        keys.extend(normalized_attrs.keys())
        node = XmlNode(tag=local, attributes=normalized_attrs)
        if stack:
            stack[-1].children.append(node)
        else:
            root = node
        stack.append(node)

    def end_element(_name: str) -> None:
        stack.pop()

    def char_data(data: str) -> None:
        if stack:
            stack[-1].text += data

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = char_data

    try:
        parser.Parse(body, True)
    except ParseError:
        raise
    except expat.ExpatError as exc:
        raise ParseError(_REASON_XML_SYNTAX) from exc

    if root is None:
        raise ParseError(_REASON_XML_SYNTAX)
    return root, keys


# -------------------------------------------------------------------------- DICOM

# Supported value representations for the v0.1 DICOM JSON metadata subset. These are
# the string/number/date/time VRs that carry inline JSON values. Binary-bearing VRs
# (OB, OW, OF, OD, OL, OV, UN) and sequences (SQ) are intentionally excluded so this
# subset never implies pixel data, encapsulated binary, or nested item parsing.
_SUPPORTED_DICOM_VRS: frozenset[str] = frozenset(
    {
        "AE", "AS", "AT", "CS", "DA", "DS", "DT", "FL", "FD",
        "IS", "LO", "LT", "PN", "SH", "SL", "SS", "ST", "TM",
        "UC", "UI", "UL", "UR", "US", "UT",
    }
)

# Pixel-data tag; always rejected regardless of the declared VR.
_DICOM_PIXEL_DATA_TAG = "7FE00010"

# Keys inside a tag entry that indicate out-of-band binary and are never accepted.
_DICOM_BINARY_KEYS: frozenset[str] = frozenset({"InlineBinary", "BulkDataURI"})

# The only fields a tag entry may carry in this subset. Anything else (including the
# binary keys above and any other out-of-band reference) is rejected.
_DICOM_ALLOWED_ENTRY_KEYS: frozenset[str] = frozenset({"vr", "Value"})

# Scalar JSON types permitted inside a ``Value`` array. Nested objects and arrays are
# rejected so binary references cannot be smuggled in as nested entries, and so the
# subset stays flat and predictable for downstream validation. ``bool`` is excluded
# explicitly because it is a subclass of ``int``.
_DICOM_SCALAR_TYPES: tuple[type, ...] = (str, int, float)


def _is_dicom_tag(tag: str) -> bool:
    """A tag is exactly eight hexadecimal digits (group + element)."""
    if len(tag) != 8:
        return False
    try:
        int(tag, 16)
    except ValueError:
        return False
    return True


def _parse_dicom_json(
    body: str, max_depth: int, max_nodes: int, max_dicom_values: int
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    # The subset is JSON, so it must first be valid, bounded JSON.
    document, _ = _parse_json(body, max_depth=max_depth, max_nodes=max_nodes)
    if not isinstance(document, dict):
        raise ParseError(_REASON_DICOM_ROOT)

    normalized: dict[str, dict[str, Any]] = {}
    tags: list[str] = []
    for raw_tag, entry in document.items():
        tag = raw_tag.upper()
        if not _is_dicom_tag(tag):
            raise ParseError(_REASON_DICOM_TAG)
        # Tags that are distinct in the raw document but collide after case
        # normalization (e.g. "0008beef" and "0008BEEF") would otherwise silently
        # overwrite one another, so reject the collision outright.
        if tag in normalized:
            raise ParseError(_REASON_DICOM_COLLISION)
        if tag == _DICOM_PIXEL_DATA_TAG:
            raise ParseError(_REASON_DICOM_BINARY)
        if not isinstance(entry, dict):
            raise ParseError(_REASON_DICOM_ENTRY)
        if _DICOM_BINARY_KEYS & entry.keys():
            raise ParseError(_REASON_DICOM_BINARY)
        # Reject any field outside the documented subset rather than silently dropping
        # it, so out-of-band references cannot ride along unnoticed.
        if entry.keys() - _DICOM_ALLOWED_ENTRY_KEYS:
            raise ParseError(_REASON_DICOM_UNKNOWN_KEY)

        vr = entry.get("vr")
        if not isinstance(vr, str):
            raise ParseError(_REASON_DICOM_ENTRY)
        vr = vr.upper()
        if vr not in _SUPPORTED_DICOM_VRS:
            raise ParseError(_REASON_DICOM_VR)

        value = entry.get("Value")
        if value is not None:
            if not isinstance(value, list):
                raise ParseError(_REASON_DICOM_ENTRY)
            if len(value) > max_dicom_values:
                raise ParseError(_REASON_DICOM_VALUE)
            # Every element must be a plain scalar; nested objects/arrays (the vector
            # for smuggling BulkDataURI/InlineBinary inside Value) are rejected.
            for element in value:
                if isinstance(element, bool) or not isinstance(element, _DICOM_SCALAR_TYPES):
                    raise ParseError(_REASON_DICOM_VALUE_TYPE)

        normalized[tag] = {"vr": vr, "Value": value}
        tags.append(tag)

    return normalized, tags
