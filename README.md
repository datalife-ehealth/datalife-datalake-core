# datalife-datalake-core

Core data lake for [DataLife e-Health](https://github.com/datalife-ehealth). Author: Luchang Jiang (@FinalSunFlower).

The service accepts clinical payloads (JSON, device XML, DICOM metadata) and records access in a cryptographic tamper-evident ledger. Personal identifiers stay on the patient client. This repository does not store name, CPF, phone, or emergency contacts.

The ledger chains SHA-256 Merkle roots. It is not a distributed blockchain: there is no peer network, consensus protocol, or miner.

## Layout

```text
src/core/config.py              Settings
src/models/schema.py            User, Project, Document, CrisisRecord, MerkleBlock
src/services/crypto.py          Merkle root, block hash, chain verification
src/services/access_control.py  OTP grants and glass-break
src/services/parsing.py         Bounded JSON, XML, and DICOM JSON payload parsing
src/api/routes/                 ingestion, access, audit
src/main.py                     FastAPI application
```

`User.subject_key` is an opaque key minted by the patient client. It is not a government identifier.

## Local setup

Python 3.11 or newer.

```bash
pip install -e ".[test,postgres]"
pytest -q
uvicorn main:app --app-dir src --reload
```

OpenAPI is served at `http://127.0.0.1:8000/docs`.

PostgreSQL and the API together:

```bash
docker compose up --build
```

Set `DATALIFE_AUDIT_SECRET` before any shared deployment. The compose file uses a local default only so a developer machine can boot.

## API

### Health

```bash
curl http://127.0.0.1:8000/health
```

### Ingest a lab XML document

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d "{\"subject_key\":\"subj-1\",\"kind\":\"xml\",\"media_type\":\"application/xml\",\"body\":\"<Panel><Hemoglobin value=\\\"13.2\\\"/></Panel>\"}"
```

Payloads carrying direct patient identifiers are rejected (see PII policy below).

#### Payload validation

The endpoint parses `body` under conservative, fail-closed limits before storing it.
Invalid, oversized, over-nested, or kind/media-type-mismatched input is rejected with
HTTP 422 and a stable, non-reflective error that never echoes the submitted payload.

`media_type` must be compatible with `kind`:

| `kind`  | accepted `media_type`                       |
| ------- | ------------------------------------------- |
| `json`  | `application/json`                          |
| `xml`   | `application/xml`, `text/xml` (alias)       |
| `dicom` | `application/dicom+json`                    |

* **JSON** must be syntactically valid, rooted at an object or array, and free of
  duplicate object keys.
* **XML** is parsed with DTDs, entity declarations, and external resource resolution
  disabled; document type definitions and entity-expansion payloads are rejected.
* **DICOM** is accepted only as a small DICOM JSON metadata subset: a single JSON
  object whose keys are eight-hex-digit tags, each mapping to an object with a `vr`
  string and an optional bounded `Value` array. `InlineBinary`, `BulkDataURI`, pixel
  data (`7FE00010`), binary value representations, and DICOM Part 10 bytes are
  rejected. This is deliberately not a DICOM conformance claim.

#### PII policy

A centralized policy (`src/services/pii.py`) rejects direct patient identity data at
the boundary. It traverses the normalized parser output rather than the raw body:
nested JSON keys and string values, XML element/attribute names and text, and the
DICOM patient-identity tags (for example `PatientName`, `PatientID`,
`PatientBirthDate`, `PatientAddress`). Field names are matched against an explicit set
of identity concepts (name, government ID/CPF, phone, email, address, date of birth,
emergency contact) after normalizing case and separators. Values are matched only by
conservative detectors for unambiguous email, government-ID (CPF/SSN), and formatted
phone forms. The glass-break `reason` free-text field is scanned the same way before
anything is written to the audit ledger.

Rejections return a single stable HTTP 422 and never echo the matched value or
payload into the response, logs, or audit events. The detectors are intentionally
narrow to avoid flagging clinical codes, measurements, and dates; this is boundary
rejection, not de-identification, and makes no anonymization claim. `subject_key`,
server-issued tokens, and configured `physician_id` values are not scanned.

`payload_sha256` is always computed over the original UTF-8 request body, so parser
normalization never changes the digest. Limits are configurable via the
`DATALIFE_INGEST_MAX_BODY_BYTES`, `DATALIFE_INGEST_MAX_DEPTH`,
`DATALIFE_INGEST_MAX_NODES`, and `DATALIFE_INGEST_MAX_DICOM_VALUES` settings.

### Patient OTP

```bash
curl -X POST http://127.0.0.1:8000/api/v1/access/otp \
  -H "Content-Type: application/json" \
  -d "{\"subject_key\":\"subj-1\",\"physician_id\":\"PHY-0001\",\"ttl_seconds\":900}"
```

```bash
curl -X POST http://127.0.0.1:8000/api/v1/access/otp/validate \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"TOKEN\",\"subject_key\":\"subj-1\"}"
```

### Glass-break

A physician id must be listed in `DATALIFE_MASTER_PHYSICIAN_IDS`.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/access/glass-break \
  -H "Content-Type: application/json" \
  -d "{\"physician_id\":\"PHY-0001\",\"subject_key\":\"subj-1\",\"reason\":\"unconscious on arrival\"}"
```

The call appends an `UNCONFIRMED` audit event before any clinical read.

### Verify the ledger

```bash
curl http://127.0.0.1:8000/api/v1/audit/verify
```

`ok` is true when every block height, previous hash, Merkle root, and block hash still match the stored records.

## Tests and Benchmarks

Run routine unit and concurrency tests (`tests/test_merkle.py`, `tests/test_access.py`, `tests/test_concurrency.py`, `tests/test_ingestion_validation.py`):

```bash
pytest -q
```

Benchmarks are marked with `performance` and skipped by default during normal test runs via `addopts = "-m 'not performance'"` in `pyproject.toml`. To measure synthetic Merkle root calculations, chain verification depth, and tamper detection:

```bash
pip install -e ".[test,performance]"
pytest -m performance --benchmark-only
```

Optionally export machine-readable benchmark JSON results for CI tracking:

```bash
pytest -m performance --benchmark-only --benchmark-json=benchmark_results.json
```

### Cryptographic golden vectors

Deterministic golden test vectors for canonical JSON encoding, leaf hashes, Merkle roots, and sealed ledger chains are committed in `tests/fixtures/crypto_vectors_v1.json`.

Run the cryptographic vector test suite:

```bash
pytest -vv tests/test_crypto_vectors.py
```

An independent standard-library generator is provided for maintenance:

```bash
python scripts/generate_crypto_vectors.py --output tests/fixtures/crypto_vectors_v1.json
```

Every vector modification requires manual cryptographic review. Tests assert literal equality against committed fixture values and never regenerate expected values at runtime.
