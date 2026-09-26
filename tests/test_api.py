import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["model_loaded"]


def test_analyze_ok(client):
    r = client.post("/analyze", json={"url": "http://paypal.secure-verify.tk/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "HIGH RISK" and body["indicators"] and "features" in body


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "x" * 2100}, {"url": 5}])
def test_analyze_validation_errors(client, payload):
    assert client.post("/analyze", json=payload).status_code == 422


def test_analyze_unsupported_scheme(client):
    r = client.post("/analyze", json={"url": "javascript:alert(1)"})
    assert r.status_code == 422 and "supported" in r.json()["detail"]
