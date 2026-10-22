"""
Flask web app.

Routes
    GET  /                 paste code or upload a file
    POST /review           run a review, store it, show the result
    GET  /review/<id>      view a past review
    GET  /history          list past reviews
    POST /api/review       JSON API: {"code": "...", "filename": "app.py"}
    GET  /api/health       status, including whether the LLM is reachable
"""

import json
import os
import sqlite3
from datetime import datetime

from flask import Flask, abort, g, jsonify, redirect, render_template, request, url_for

from .reviewer import Reviewer, LANGUAGES

ALLOWED_EXTENSIONS = set(LANGUAGES)
MAX_CODE_BYTES = 200_000


def create_app(reviewer: Reviewer = None, db_path: str = None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CODE_BYTES + 10_000
    app.config["DB_PATH"] = db_path or os.getenv("REVIEW_DB", "reviews.db")
    app.reviewer = reviewer or Reviewer(use_ai=os.getenv("USE_AI", "1") != "0")

    # ---------------- database ----------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("""CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created TEXT, filename TEXT, score INTEGER, grade TEXT,
                ai_used INTEGER, result TEXT)""")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db:
            db.close()

    def save(result):
        db = get_db()
        cur = db.execute(
            "INSERT INTO reviews (created, filename, score, grade, ai_used, result) VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), result.filename, result.score,
             result.grade, int(result.ai_used), json.dumps(result.to_dict())))
        db.commit()
        return cur.lastrowid

    # ---------------- input handling ----------------
    def read_input():
        """Returns (code, filename) from a pasted textarea or an uploaded file."""
        upload = request.files.get("file")
        if upload and upload.filename:
            filename = os.path.basename(upload.filename)
            if os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
                raise ValueError(f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
            code = upload.read(MAX_CODE_BYTES + 1).decode("utf-8", errors="replace")
        else:
            code = request.form.get("code", "")
            lang_ext = request.form.get("language", ".py")
            if lang_ext not in ALLOWED_EXTENSIONS:
                lang_ext = ".py"
            filename = f"snippet{lang_ext}"
        if not code.strip():
            raise ValueError("Paste some code or upload a file.")
        if len(code.encode()) > MAX_CODE_BYTES:
            raise ValueError("Code is too large (limit 200 KB).")
        return code, filename

    # ---------------- pages ----------------
    @app.get("/")
    def index():
        return render_template("index.html", languages=LANGUAGES, error=None)

    @app.post("/review")
    def review():
        try:
            code, filename = read_input()
        except ValueError as exc:
            return render_template("index.html", languages=LANGUAGES, error=str(exc)), 400
        result = app.reviewer.review(code, filename)
        review_id = save(result)
        return redirect(url_for("view_review", review_id=review_id))

    @app.get("/review/<int:review_id>")
    def view_review(review_id):
        row = get_db().execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
        if not row:
            abort(404)
        return render_template("result.html", r=json.loads(row["result"]),
                               created=row["created"], review_id=review_id)

    @app.get("/history")
    def history():
        rows = get_db().execute(
            "SELECT id, created, filename, score, grade, ai_used FROM reviews ORDER BY id DESC LIMIT 100"
        ).fetchall()
        return render_template("history.html", rows=rows)

    # ---------------- API ----------------
    @app.post("/api/review")
    def api_review():
        data = request.get_json(silent=True) or {}
        code = data.get("code", "")
        filename = os.path.basename(data.get("filename", "snippet.py"))
        if not code.strip():
            return jsonify(error="'code' is required"), 400
        if len(code.encode()) > MAX_CODE_BYTES:
            return jsonify(error="code too large"), 413
        result = app.reviewer.review(code, filename)
        out = result.to_dict()
        out["id"] = save(result)
        return jsonify(out)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", ai_enabled=app.reviewer.use_ai,
                       llm_reachable=app.reviewer.llm.available() if app.reviewer.use_ai else False,
                       model=app.reviewer.llm.model)

    @app.errorhandler(413)
    def too_large(_e):
        return render_template("index.html", languages=LANGUAGES, error="File too large (limit 200 KB)."), 413

    return app
