from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "Firewall is active"}

def test_layer1_sql_injection_block():
    # Tests if Layer 1 properly blocks obvious SQL injection without needing the LLM
    payload = {
        "user_input": "SELECT * FROM users WHERE id = 1; DROP TABLE accounts;",
        "action_type": "login"
    }
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    assert response.json()["threat_category"] == "CODE_INJECTION"
