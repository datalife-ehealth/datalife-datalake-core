"""FastAPI entrypoint for the DataLife data lake core."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

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

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    """Return a stable 422 for request-validation failures without reflecting input.

    FastAPI's default handler echoes the offending ``input`` back in the response.
    That both leaks the submitted payload (which may embed secrets) and crashes when
    the input cannot be re-encoded as UTF-8 (for example an escaped lone surrogate
    such as ``\\ud800``, which pydantic rejects before the route runs). Replacing it
    with a fixed, non-reflective message keeps those cases a clean, logged-safe 422.
    """
    return JSONResponse(status_code=422, content={"detail": "request payload failed validation"})


app.include_router(ingestion.router)
app.include_router(access.router)
app.include_router(audit.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "datalife-datalake-core"}
