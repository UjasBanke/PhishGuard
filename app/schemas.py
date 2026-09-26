"""Pydantic request/response models for the PhishGuard API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, examples=["https://example.com/login"],
                     description="URL string to analyse. It is never fetched or opened.")


class IndicatorOut(BaseModel):
    id: str
    title: str
    detail: str
    reason: str
    severity: Literal["low", "medium", "high"]
    points: int


class ScoreBreakdown(BaseModel):
    ml_score: float
    rule_score: int
    ml_weight: float
    rule_weight: float
    suspicious_min: int
    high_min: int


class MLDriver(BaseModel):
    feature: str
    value: float
    baseline: float
    impact: float = Field(..., description="Change in phishing probability (percentage points) attributable to this feature")


class AnalyzeResponse(BaseModel):
    url: str
    normalized_url: str
    risk_score: int = Field(..., ge=0, le=100)
    verdict: Literal["LOW RISK", "SUSPICIOUS", "HIGH RISK"]
    ml_prediction: Literal["PHISHING", "LEGITIMATE"]
    ml_confidence: float = Field(..., ge=0, le=1, description="Confidence in the ML prediction (0-1)")
    ml_phishing_probability: float = Field(..., ge=0, le=1)
    rule_score: int = Field(..., ge=0, le=100)
    score_breakdown: ScoreBreakdown
    indicators: list[IndicatorOut]
    reasons: list[str]
    explanation: str
    features: dict[str, float]
    ml_drivers: list[MLDriver]
    analyzed_at: str
    note: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    version: str
    model_trained_at: str | None = None
