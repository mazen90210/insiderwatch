import os
import hmac

import psycopg
from flask import Flask, jsonify, request

app = Flask(__name__)


def get_conn():
    return psycopg.connect(os.environ["DATABASE_URL"])


def authorized():
    key = os.environ.get("INGEST_API_KEY", "")
    sent = request.headers.get("X-API-Key", "")
    return bool(key) and hmac.compare_digest(key, sent)


@app.route("/")
def home():
    return "InsiderWatch is running"


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/init", methods=["POST"])
def init_db():
    if not authorized():
        return jsonify(error="unauthorized"), 401
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                ts TIMESTAMPTZ DEFAULT now(),
                host TEXT,
                username TEXT,
                event_type TEXT,
                message TEXT
            )
            """
        )
    return jsonify(status="table ready")


@app.route("/api/ingest", methods=["POST"])
def ingest():
    if not authorized():
        return jsonify(error="unauthorized"), 401
    data = request.get_json(silent=True) or {}
    events = data.get("events", [])
    with get_conn() as conn:
        for e in events:
            conn.execute(
                "INSERT INTO events (host, username, event_type, message) "
                "VALUES (%s, %s, %s, %s)",
                (e.get("host"), e.get("user"), e.get("type"), e.get("message")),
            )
    return jsonify(inserted=len(events))


@app.route("/api/stats")
def stats():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
        ).fetchall()
    return jsonify({r[0]: r[1] for r in rows})
