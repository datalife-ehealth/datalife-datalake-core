"""FastAPI entrypoint for the DataLife data lake core."""

from fastapi import FastAPI

from api.routes import access, audit, ingestion

app = FastAPI(
    title="DataLife Data Lake Core",
    version="0.1.0",
    description=(
        "Dual-tier health data lake reference service by Luchang Jiang. "
        "Personal identifiers stay on the client. This process stores clinical payloads "
        "and a cryptographic tamper-evident Merkle ledger. It is not a distributed blockchain."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(ingestion.router)
app.include_router(access.router)
app.include_router(audit.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "datalife-datalake-core"}
