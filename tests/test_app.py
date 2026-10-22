"""Tests use a fake LLM so they run offline and fast."""

import json

import pytest

from app.llm import LLMUnavailable, extract_json
from app.main import create_app
from app.reviewer import Reviewer

VULN = '''import sqlite3
from flask import request

def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("a.db")
    return conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()

DEBUG_PASSWORD = "hunter2hunter2"  # only used in tests
'''


class FakeLLM:
    model = "fake-model"

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = 0

    def available(self):
        return not self.fail

    def chat(self, system, user, temperature=0.1):
        self.calls += 1
        if self.fail:
            raise LLMUnavailable("offline")
        if "pattern\nmatching would miss" in user or "pattern matching would miss" in user:
            return '```json\n[{"title": "Missing authentication on get_user", "severity": "HIGH", "line": 4, ' \
                   '"explanation": "Anyone can read any user.", "recommendation": "Require login and check ownership."}]\n```'
        if "Hardcoded password" in user:
            return json.dumps({"verdict": "false_positive", "confidence": "medium",
                               "explanation": "Comment says test-only.", "fixed_code": "", "references": []})
        return json.dumps({"verdict": "true_positive", "confidence": "high",
                           "explanation": "User input reaches the SQL query.",
                           "fixed_code": 'conn.execute("SELECT * FROM users WHERE id = ?", (uid,))',
                           "references": ["https://cwe.mitre.org/data/definitions/89.html"]})


def test_extract_json_handles_fences_and_chatter():
    assert extract_json('Sure!\n```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Here: [{"x": 2}] done') == [{"x": 2}]


def test_review_with_ai():
    result = Reviewer(llm=FakeLLM()).review(VULN, "app.py")
    assert result.ai_used
    titles = {f.title: f for f in result.findings}
    sql = titles["SQL query built with string formatting"]
    assert sql.verdict == "true_positive" and "?" in sql.fixed_code
    assert titles["Hardcoded password"].verdict == "false_positive"
    assert any(f.source == "ai" for f in result.findings)
    # false positive is not counted
    assert result.counts()["HIGH"] == 2   # SQLi + AI logic finding


def test_review_falls_back_without_llm():
    result = Reviewer(llm=FakeLLM(fail=True)).review(VULN, "app.py")
    assert not result.ai_used
    assert result.findings
    assert any("unavailable" in n for n in result.notes)


@pytest.fixture
def client(tmp_path):
    app = create_app(reviewer=Reviewer(llm=FakeLLM()), db_path=str(tmp_path / "t.db"))
    app.config["TESTING"] = True
    return app.test_client()


def test_web_flow(client):
    assert client.get("/").status_code == 200
    r = client.post("/review", data={"code": VULN, "language": ".py"})
    assert r.status_code == 302
    page = client.get(r.headers["Location"])
    assert b"SQL query built with string formatting" in page.data
    assert b"likely false positive" in page.data
    assert b"snippet.py" in client.get("/history").data


def test_empty_input_rejected(client):
    assert client.post("/review", data={"code": "   "}).status_code == 400


def test_bad_extension_rejected(client):
    from io import BytesIO
    r = client.post("/review", data={"file": (BytesIO(b"x"), "evil.exe")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_api(client):
    r = client.post("/api/review", json={"code": VULN, "filename": "../../etc/app.py"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["filename"] == "app.py"        # path stripped
    assert data["ai_used"] is True
    assert client.post("/api/review", json={}).status_code == 400


def test_output_is_escaped(client):
    r = client.post("/review", data={"code": 'password = "<script>alert(1)</script>"', "language": ".py"})
    page = client.get(r.headers["Location"]).data
    assert b"<script>alert(1)</script>" not in page
