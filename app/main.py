"""PhishGuard FastAPI service.

Run:  uvicorn app.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from app.analyzer import get_analyzer
from app.config import APP_VERSION
from app.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
from feature_engineering.extractor import InvalidURLError


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_analyzer()  # load (or rebuild) the model once at start-up
    yield


app = FastAPI(
    title="PhishGuard API",
    version=APP_VERSION,
    description="Hybrid (ML + rules) phishing URL analysis. The submitted URL is analysed as a "
                "string only and is never visited.",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    a = get_analyzer()
    return HealthResponse(status="ok", model_loaded=True, version=APP_VERSION,
                          model_trained_at=a.meta.get("trained_at"))


@app.post("/analyze", response_model=AnalyzeResponse, tags=["analysis"])
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return AnalyzeResponse(**get_analyzer().analyze(req.url))
    except InvalidURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
