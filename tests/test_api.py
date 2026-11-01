from fastapi.testclient import TestClient
from wtk.api import app

def test_status():
    r=TestClient(app).get("/api/status")
    assert r.status_code==200 and r.json()["offline"] is True
