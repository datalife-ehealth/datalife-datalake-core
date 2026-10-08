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

Payloads that contain `PatientName` or a `<cpf>` element are rejected.

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

Run routine unit and concurrency tests (`tests/test_merkle.py`, `tests/test_access.py`, `tests/test_concurrency.py`):

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
