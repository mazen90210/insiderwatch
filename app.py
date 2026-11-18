import os
import hmac

import psycopg
import numpy as np

from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest

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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                ts TIMESTAMPTZ DEFAULT now(),
                host TEXT,
                username TEXT,
                event_type TEXT,
                message TEXT
            )
        """)

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
                """
                INSERT INTO events (host, username, event_type, message)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    e.get("host"),
                    e.get("user"),
                    e.get("type"),
                    e.get("message")
                )
            )

    return jsonify(inserted=len(events))


@app.route("/api/stats")
def stats():
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT event_type, COUNT(*)
            FROM events
            GROUP BY event_type
            """
        ).fetchall()

    return jsonify({r[0]: r[1] for r in rows})


# =====================================
# AI THREAT DETECTION
# =====================================

@app.route("/api/ai/analyze")
def ai_analyze():

    with get_conn() as conn:
        rows = conn.execute("""
            SELECT
                host,
                username,

                COUNT(*) FILTER (
                    WHERE event_type = 'failed_login'
                ) AS failed_login,

                COUNT(*) FILTER (
                    WHERE event_type = 'successful_login'
                ) AS successful_login,

                COUNT(*) FILTER (
                    WHERE event_type = 'sudo_activity'
                ) AS sudo_activity,

                COUNT(*) FILTER (
                    WHERE event_type = 'privileged_activity'
                ) AS privileged_activity,

                COUNT(*) FILTER (
                    WHERE event_type = 'user_created'
                ) AS user_created,

                COUNT(*) FILTER (
                    WHERE event_type = 'user_deleted'
                ) AS user_deleted

            FROM events

            WHERE ts >= NOW() - INTERVAL '7 days'

            GROUP BY host, username

        """).fetchall()

    if not rows:
        return jsonify({
            "status": "no_data",
            "message": "No events available for AI analysis"
        })

    profiles = []

    for row in rows:

        profiles.append({
            "host": row[0],
            "user": row[1],
            "failed_login": row[2],
            "successful_login": row[3],
            "sudo_activity": row[4],
            "privileged_activity": row[5],
            "user_created": row[6],
            "user_deleted": row[7]
        })

    features = np.array([
        [
            p["failed_login"],
            p["successful_login"],
            p["sudo_activity"],
            p["privileged_activity"],
            p["user_created"],
            p["user_deleted"]
        ]
        for p in profiles
    ])

    # Train Isolation Forest when enough profiles exist

    model_available = len(profiles) >= 5

    if model_available:

        model = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42
        )

        model.fit(features)

        predictions = model.predict(features)
        anomaly_scores = model.decision_function(features)

    results = []

    for index, profile in enumerate(profiles):

        # Rule-based risk score

        risk = 0

        risk += min(profile["failed_login"] * 8, 40)
        risk += min(profile["sudo_activity"] * 5, 20)
        risk += min(profile["privileged_activity"] * 5, 20)
        risk += min(profile["user_created"] * 10, 10)
        risk += min(profile["user_deleted"] * 10, 10)

        is_anomaly = False
        anomaly_score = None

        # Isolation Forest result

        if model_available:

            is_anomaly = predictions[index] == -1
            anomaly_score = round(
                float(anomaly_scores[index]), 4
            )

            if is_anomaly:
                risk += 20

        risk = min(risk, 100)

        # Threat classification

        if risk >= 80:
            threat_level = "Critical"

        elif risk >= 60:
            threat_level = "High"

        elif risk >= 30:
            threat_level = "Medium"

        else:
            threat_level = "Low"

        results.append({
            "host": profile["host"],
            "username": profile["user"],
            "risk_score": risk,
            "threat_level": threat_level,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "activity": profile
        })

    results.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )

    return jsonify({
        "status": "success",
        "model": "Isolation Forest",
        "model_trained": model_available,
        "profiles_analyzed": len(profiles),
        "results": results
    })


if __name__ == "__main__":
    app.run(debug=True)