import os
import hmac

import psycopg
import numpy as np

from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template
from sklearn.ensemble import IsolationForest


load_dotenv(".env.local", override=True)

app = Flask(__name__)


# ==============================
# DATABASE CONNECTION
# ==============================

def get_conn():
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is missing")

    return psycopg.connect(database_url)


# ==============================
# API AUTHENTICATION
# ==============================

def authorized():
    key = os.environ.get("INGEST_API_KEY", "")
    sent = request.headers.get("X-API-Key", "")

    return bool(key) and hmac.compare_digest(key, sent)


# ==============================
# HOME DASHBOARD
# ==============================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify(status="ok")


# ==============================
# DATABASE INITIALIZATION
# ==============================

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


# ==============================
# RECEIVE SECURITY EVENTS
# ==============================

@app.route("/api/ingest", methods=["POST"])
def ingest():

    if not authorized():
        return jsonify(error="unauthorized"), 401

    data = request.get_json(silent=True) or {}

    events = data.get("events", [])

    if not isinstance(events, list):
        return jsonify(error="events must be a list"), 400

    with get_conn() as conn:

        for event in events:

            conn.execute("""
                INSERT INTO events
                (host, username, event_type, message)
                VALUES (%s, %s, %s, %s)
            """, (
                event.get("host"),
                event.get("user"),
                event.get("type"),
                event.get("message")
            ))

    return jsonify(inserted=len(events))


# ==============================
# STATISTICS API
# ==============================

@app.route("/api/stats")
def stats():

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT event_type, COUNT(*)
            FROM events
            GROUP BY event_type
        """).fetchall()

        total = conn.execute("""
            SELECT COUNT(*) FROM events
        """).fetchone()[0]

        failed = conn.execute("""
            SELECT COUNT(*)
            FROM events
            WHERE event_type = 'failed_login'
        """).fetchone()[0]

    result = {
        "total_events": total,
        "failed_login": failed
    }

    result.update({
        row[0]: row[1]
        for row in rows
    })

    return jsonify(result)


# ==============================
# RECENT EVENTS API
# ==============================

@app.route("/api/events")
def recent_events():

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT id, ts, host, username, event_type, message
            FROM events
            ORDER BY ts DESC
            LIMIT 20
        """).fetchall()

    events = []

    for row in rows:

        events.append({
            "id": row[0],
            "ts": row[1].isoformat() if row[1] else None,
            "host": row[2],
            "username": row[3],
            "event_type": row[4],
            "message": row[5]
        })

    return jsonify({"events": events})


# ==============================
# AI + RULE BASED ANALYSIS
# ==============================

@app.route("/api/ai/analyze")
def ai_analyze():

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT
                host,
                username,

                COUNT(*) FILTER (
                    WHERE event_type = 'failed_login'
                ),

                COUNT(*) FILTER (
                    WHERE event_type = 'successful_login'
                ),

                COUNT(*) FILTER (
                    WHERE event_type = 'sudo_activity'
                ),

                COUNT(*) FILTER (
                    WHERE event_type = 'privileged_activity'
                ),

                COUNT(*) FILTER (
                    WHERE event_type = 'user_created'
                ),

                COUNT(*) FILTER (
                    WHERE event_type = 'user_deleted'
                )

            FROM events

            WHERE ts >= NOW() - INTERVAL '7 days'

            GROUP BY host, username

        """).fetchall()

    if not rows:

        return jsonify({
            "status": "no_data",
            "model": "Isolation Forest",
            "model_trained": False,
            "profiles_analyzed": 0,
            "results": []
        })

    # BUILD USER PROFILES

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

    # AI FEATURES

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

    # TRAIN ISOLATION FOREST

    model_available = len(profiles) >= 5

    predictions = [1] * len(profiles)

    anomaly_scores = [None] * len(profiles)

    if model_available:

        model = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42
        )

        model.fit(features)

        predictions = model.predict(features)

        anomaly_scores = model.decision_function(features)

    # RISK ANALYSIS

    results = []

    for index, profile in enumerate(profiles):

        risk = 0

        failed = profile["failed_login"]

        # RULE-BASED FAILED LOGIN DETECTION

        if failed >= 8:

            risk += 85
            rule_triggered = True
            rule_reason = "Critical number of failed login attempts"

        elif failed >= 5:

            risk += 65
            rule_triggered = True
            rule_reason = "High number of failed login attempts"

        elif failed >= 3:

            risk += 40
            rule_triggered = True
            rule_reason = "Multiple failed login attempts"

        elif failed >= 1:

            risk += 16
            rule_triggered = False
            rule_reason = "Small number of failed login attempts"

        else:

            rule_triggered = False
            rule_reason = "No failed login attempts"

        # OTHER SECURITY ACTIVITIES

        risk += min(
            profile["sudo_activity"] * 5,
            20
        )

        risk += min(
            profile["privileged_activity"] * 5,
            20
        )

        risk += min(
            profile["user_created"] * 10,
            10
        )

        risk += min(
            profile["user_deleted"] * 10,
            10
        )

        # AI ANOMALY DETECTION

        is_anomaly = False

        anomaly_score = None

        if model_available:

            is_anomaly = predictions[index] == -1

            anomaly_score = round(
                float(anomaly_scores[index]),
                4
            )

            if is_anomaly:

                risk += 20

        # FINAL RISK SCORE

        risk = min(risk, 100)

        # THREAT CLASSIFICATION

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

            "is_anomaly": bool(is_anomaly),

            "anomaly_score": anomaly_score,

            "rule_triggered": rule_triggered,

            "rule_reason": rule_reason,

            "activity": profile

        })

    # SORT BY RISK SCORE

    results.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    return jsonify({

        "status": "success",

        "model": "Isolation Forest",

        "model_trained": model_available,

        "profiles_analyzed": len(profiles),

        "results": results

    })


# ==============================
# APPLICATION START
# ==============================

if __name__ == "__main__":

    app.run(debug=True)