import os
import hmac
import json

from functools import wraps
from datetime import timedelta

import psycopg
import numpy as np

from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    request,
    render_template,
    session
)

from sklearn.ensemble import IsolationForest


# ==========================================
# ENVIRONMENT
# ==========================================

load_dotenv(".env.local", override=False)


# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "SESSION_COOKIE_SECURE", "false"
    ).lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_conn():

    database_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is missing")

    return psycopg.connect(database_url)


# ==========================================
# GENERAL HELPERS
# ==========================================

def clean_username(username):

    if not username:
        return "unknown"

    username = str(username).strip()

    username = username.strip(
        "'\",;:()[]{} "
    )

    return username or "unknown"


def is_machine_account(username):

    if not username:
        return False

    return username.endswith("$")


def json_error(message, code):

    return jsonify(error=message), code


# ==========================================
# AUTHENTICATION
# ==========================================

def admin_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get("admin_authenticated"):

            return json_error("unauthorized", 401)

        return func(*args, **kwargs)

    return wrapper


def ingest_authorized():

    key = os.environ.get("INGEST_API_KEY", "")
    sent = request.headers.get("X-API-Key", "")

    return bool(key) and hmac.compare_digest(key, sent)


def response_agent_authorized():

    key = os.environ.get("RESPONSE_AGENT_KEY", "")
    sent = request.headers.get("X-Response-Agent-Key", "")

    return bool(key) and hmac.compare_digest(key, sent)


# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.route("/api/auth/login", methods=["POST"])
def admin_login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return json_error("JSON object is required", 400)

    sent_key = data.get("admin_key", "")
    admin_key = os.environ.get("INCIDENT_ADMIN_KEY", "")

    if not isinstance(sent_key, str):

        return json_error("invalid credentials", 401)

    if not admin_key or not hmac.compare_digest(
        admin_key,
        sent_key
    ):

        return json_error("invalid credentials", 401)

    session.clear()

    session["admin_authenticated"] = True
    session.permanent = True

    return jsonify(
        status="authenticated",
        authenticated=True
    )


@app.route("/api/auth/logout", methods=["POST"])
@admin_required
def admin_logout():

    session.clear()

    return jsonify(
        status="logged_out",
        authenticated=False
    )


@app.route("/api/auth/status", methods=["GET"])
def auth_status():

    return jsonify(
        authenticated=bool(
            session.get("admin_authenticated")
        )
    )


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")


@app.route("/health")
def health():

    return jsonify(status="ok")


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

@app.route("/api/init", methods=["POST"])
def init_db():

    if not ingest_authorized():

        return json_error("unauthorized", 401)

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


# ==========================================
# RECEIVE SECURITY EVENTS
# ==========================================

@app.route("/api/ingest", methods=["POST"])
def ingest():

    if not ingest_authorized():

        return json_error("unauthorized", 401)

    data = request.get_json(silent=True) or {}

    if not isinstance(data, dict):

        return json_error("JSON object is required", 400)

    events = data.get("events", [])

    if not isinstance(events, list):

        return json_error("events must be a list", 400)

    if len(events) > 500:

        return json_error("maximum 500 events per request", 400)

    inserted = 0

    with get_conn() as conn:

        for event in events:

            if not isinstance(event, dict):
                continue

            username = clean_username(
                event.get("user")
            )

            host = event.get("host")
            event_type = event.get("type")
            message = event.get("message")

            if not isinstance(host, str):
                continue

            if not isinstance(event_type, str):
                continue

            if message is not None and not isinstance(message, str):
                continue

            conn.execute("""
                INSERT INTO events
                (host, username, event_type, message)
                VALUES (%s, %s, %s, %s)
            """, (
                host[:255],
                username[:255],
                event_type[:100],
                message[:5000] if message else None
            ))

            inserted += 1

    return jsonify(inserted=inserted)


# ==========================================
# DASHBOARD STATISTICS
# ==========================================

@app.route("/api/stats")
@admin_required
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


# ==========================================
# RECENT EVENTS
# ==========================================

@app.route("/api/events")
@admin_required
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


# ==========================================
# AI + RULE BASED ANALYSIS
# ==========================================

@app.route("/api/ai/analyze")
@admin_required
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

    profiles = []

    for row in rows:

        profiles.append({

            "host": row[0],
            "user": clean_username(row[1]),
            "failed_login": row[2],
            "successful_login": row[3],
            "sudo_activity": row[4],
            "privileged_activity": row[5],
            "user_created": row[6],
            "user_deleted": row[7]

        })

    # Exclude machine accounts

    ai_indices = [

        index

        for index, profile in enumerate(profiles)

        if not is_machine_account(profile["user"])

    ]

    ai_profiles = [

        profiles[index]

        for index in ai_indices

    ]

    features = np.array([

        [

            p["failed_login"],
            p["successful_login"],
            p["sudo_activity"],
            p["privileged_activity"],
            p["user_created"],
            p["user_deleted"]

        ]

        for p in ai_profiles

    ])

    model_available = len(ai_profiles) >= 5

    predictions = [1] * len(profiles)

    anomaly_scores = [None] * len(profiles)

    if model_available:

        model = IsolationForest(

            n_estimators=150,
            contamination="auto",
            random_state=42

        )

        model.fit(features)

        ai_predictions = model.predict(features)

        ai_scores = model.decision_function(features)

        for position, original_index in enumerate(ai_indices):

            predictions[original_index] = ai_predictions[position]

            anomaly_scores[original_index] = ai_scores[position]

    results = []

    for index, profile in enumerate(profiles):

        risk = 0

        failed = profile["failed_login"]

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

        machine_account = is_machine_account(
            profile["user"]
        )

        is_anomaly = False

        anomaly_score = None

        if model_available and not machine_account:

            score = float(anomaly_scores[index])

            anomaly_score = round(score, 4)

            is_anomaly = (

                predictions[index] == -1

                and score < -0.08

            )

            if is_anomaly:

                risk += 20

        risk = min(risk, 100)

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

    results.sort(

        key=lambda item: item["risk_score"],

        reverse=True

    )

    return jsonify({

        "status": "success",
        "model": "Isolation Forest",
        "model_trained": model_available,
        "profiles_analyzed": len(profiles),
        "ai_profiles_analyzed": len(ai_profiles),
        "results": results

    })


# ==========================================
# INCIDENT MANAGEMENT
# ==========================================

INCIDENT_STATUSES = {
    "Open",
    "Acknowledged",
    "Investigating",
    "False Positive",
    "Resolved",
}

INCIDENT_SEVERITIES = {
    "Low",
    "Medium",
    "High",
    "Critical"
}


# ==========================================
# GET INCIDENTS
# ==========================================

@app.route("/api/incidents", methods=["GET"])
@admin_required
def get_incidents():

    with get_conn() as conn:

        rows = conn.execute("""
            SELECT id, event_id, title, description, host,
                   username, severity, risk_score, status,
                   investigation_notes, resolution,
                   created_at, updated_at
            FROM incidents
            ORDER BY created_at DESC
            LIMIT 200
        """).fetchall()

    incidents = []

    for row in rows:

        incidents.append({

            "id": row[0],
            "event_id": row[1],
            "title": row[2],
            "description": row[3],
            "host": row[4],
            "username": row[5],
            "severity": row[6],
            "risk_score": row[7],
            "status": row[8],
            "investigation_notes": row[9],
            "resolution": row[10],
            "created_at": row[11].isoformat() if row[11] else None,
            "updated_at": row[12].isoformat() if row[12] else None

        })

    return jsonify({"incidents": incidents})


# ==========================================
# CREATE INCIDENT
# ==========================================

@app.route("/api/incidents", methods=["POST"])
@admin_required
def create_incident():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return json_error("JSON object is required", 400)

    title = data.get("title", "")

    if not isinstance(title, str):

        return json_error("invalid title", 400)

    title = title.strip()

    if not title or len(title) > 250:

        return json_error(
            "title is required and must be 250 characters or fewer",
            400
        )

    severity = data.get("severity", "Medium")

    if severity not in INCIDENT_SEVERITIES:

        return json_error("invalid severity", 400)

    risk_score = data.get("risk_score", 0)

    if (
        isinstance(risk_score, bool)
        or not isinstance(risk_score, int)
        or not 0 <= risk_score <= 100
    ):

        return json_error(
            "risk_score must be an integer between 0 and 100",
            400
        )

    event_id = data.get("event_id")

    if event_id is not None:

        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or event_id <= 0
        ):

            return json_error(
                "event_id must be a positive integer or null",
                400
            )

    description = data.get("description")
    host = data.get("host")
    username = data.get("username")

    for field_name, value, max_length in (
        ("description", description, 2000),
        ("host", host, 255),
        ("username", username, 255),
    ):

        if value is not None and (
            not isinstance(value, str)
            or len(value) > max_length
        ):

            return json_error(
                f"{field_name} must be text of at most {max_length} characters",
                400
            )

    with get_conn() as conn:

        if event_id is not None:

            event_exists = conn.execute(
                "SELECT id FROM events WHERE id = %s",
                (event_id,),
            ).fetchone()

            if not event_exists:

                return json_error("event_id not found", 404)

        row = conn.execute("""
            INSERT INTO incidents
                (event_id, title, description, host, username,
                 severity, risk_score, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'Open')
            RETURNING id
        """, (
            event_id,
            title,
            description,
            host,
            username,
            severity,
            risk_score,
        )).fetchone()

        incident_id = row[0]

        conn.execute("""
            INSERT INTO incident_audit
                (incident_id, actor, action, details)
            VALUES (%s, %s, %s, %s)
        """, (
            incident_id,
            "admin",
            "Incident Created",
            "New incident created",
        ))

    return jsonify(
        status="created",
        incident_id=incident_id
    ), 201


# ==========================================
# UPDATE INCIDENT
# ==========================================

@app.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
@admin_required
def update_incident(incident_id):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return json_error("JSON object is required", 400)

    allowed_fields = {
        "status",
        "investigation_notes",
        "resolution"
    }

    if not data or not set(data.keys()).issubset(allowed_fields):

        return json_error(
            "provide only status, investigation_notes, and/or resolution",
            400
        )

    status = data.get("status")
    notes = data.get("investigation_notes")
    resolution = data.get("resolution")

    if status is not None and status not in INCIDENT_STATUSES:

        return json_error("invalid status", 400)

    for field_name, value in (
        ("investigation_notes", notes),
        ("resolution", resolution),
    ):

        if value is not None and (
            not isinstance(value, str)
            or len(value) > 5000
        ):

            return json_error(
                f"{field_name} must be text of at most 5000 characters",
                400
            )

    with get_conn() as conn:

        exists = conn.execute(
            "SELECT id FROM incidents WHERE id = %s",
            (incident_id,),
        ).fetchone()

        if not exists:

            return json_error("incident not found", 404)

        conn.execute("""
            UPDATE incidents
            SET status = COALESCE(%s, status),
                investigation_notes = COALESCE(%s, investigation_notes),
                resolution = COALESCE(%s, resolution),
                updated_at = NOW()
            WHERE id = %s
        """, (
            status,
            notes,
            resolution,
            incident_id
        ))

        audit_details = str(data)[:5000]

        if status is not None:

            action = "Status Changed: " + status

        elif notes is not None:

            action = "Investigation Notes Updated"

        else:

            action = "Resolution Updated"

        conn.execute("""
            INSERT INTO incident_audit
                (incident_id, actor, action, details)
            VALUES (%s, %s, %s, %s)
        """, (
            incident_id,
            "admin",
            action,
            audit_details,
        ))

    return jsonify(
        status="updated",
        incident_id=incident_id
    )


# ==========================================
# INCIDENT AUDIT
# ==========================================

@app.route("/api/incidents/<int:incident_id>/audit", methods=["GET"])
@admin_required
def get_incident_audit(incident_id):

    with get_conn() as conn:

        incident = conn.execute(
            "SELECT id FROM incidents WHERE id = %s",
            (incident_id,),
        ).fetchone()

        if not incident:

            return json_error("incident not found", 404)

        rows = conn.execute("""
            SELECT id, actor, action, details, created_at
            FROM incident_audit
            WHERE incident_id = %s
            ORDER BY created_at DESC
            LIMIT 200
        """, (incident_id,)).fetchall()

    return jsonify({

        "audit": [

            {
                "id": row[0],
                "actor": row[1],
                "action": row[2],
                "details": row[3],
                "created_at": row[4].isoformat() if row[4] else None
            }

            for row in rows

        ]

    })


# ==========================================
# RESPONSE CENTER
# ==========================================

RESPONSE_ACTION_TYPES = {
    "collect_security_logs"
}

RESPONSE_ACTION_STATUSES = {
    "Pending",
    "Running",
    "Completed",
    "Failed"
}


# ==========================================
# LIST RESPONSE ACTIONS
# ==========================================

@app.route("/api/response-actions", methods=["GET"])
@admin_required
def list_response_actions():

    incident_id = request.args.get(
        "incident_id",
        type=int
    )

    with get_conn() as conn:

        stats_row = conn.execute("""
            SELECT
                COUNT(*) AS total_actions,
                COUNT(*) FILTER (WHERE status = 'Completed'),
                COUNT(*) FILTER (WHERE status = 'Failed'),
                COUNT(*) FILTER (WHERE status IN ('Pending', 'Running')),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(result->>'events_uploaded', '') ~ '^[0-9]+$'
                        THEN (result->>'events_uploaded')::BIGINT
                        ELSE 0
                    END
                ), 0)
            FROM response_actions
        """).fetchone()

        stats = {
            "total": stats_row[0],
            "completed": stats_row[1],
            "failed": stats_row[2],
            "pending": stats_row[3],
            "events_collected": stats_row[4]
        }
        if incident_id is not None:

            rows = conn.execute("""
                SELECT id, incident_id, action_type, status,
                       requested_by, request_payload, result,
                       created_at, completed_at
                FROM response_actions
                WHERE incident_id = %s
                ORDER BY created_at DESC
                LIMIT 100
            """, (incident_id,)).fetchall()

        else:

            rows = conn.execute("""
                SELECT id, incident_id, action_type, status,
                       requested_by, request_payload, result,
                       created_at, completed_at
                FROM response_actions
                ORDER BY created_at DESC
                LIMIT 100
            """).fetchall()

    actions = []

    for row in rows:

        actions.append({

            "id": row[0],
            "incident_id": row[1],
            "action_type": row[2],
            "status": row[3],
            "requested_by": row[4],
            "request_payload": row[5],
            "result": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "completed_at": row[8].isoformat() if row[8] else None

        })

    return jsonify({"actions": actions, "stats": stats})


# ==========================================
# CREATE RESPONSE ACTION
# ==========================================

@app.route("/api/response-actions", methods=["POST"])
@admin_required
def create_response_action():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return json_error("JSON object is required", 400)

    incident_id = data.get("incident_id")

    action_type = data.get(
        "action_type",
        "collect_security_logs"
    )

    max_events = data.get("max_events", 50)

    if (
        isinstance(incident_id, bool)
        or not isinstance(incident_id, int)
        or incident_id <= 0
    ):

        return json_error(
            "incident_id must be a positive integer",
            400
        )

    if action_type not in RESPONSE_ACTION_TYPES:

        return json_error("unsupported action_type", 400)

    if (
        isinstance(max_events, bool)
        or not isinstance(max_events, int)
        or not 1 <= max_events <= 200
    ):

        return json_error(
            "max_events must be an integer from 1 to 200",
            400
        )

    payload = {
        "max_events": max_events
    }

    with get_conn() as conn:

        incident = conn.execute(
            "SELECT id FROM incidents WHERE id = %s",
            (incident_id,),
        ).fetchone()

        if not incident:

            return json_error("incident not found", 404)

        row = conn.execute("""
            INSERT INTO response_actions
                (incident_id, action_type, status,
                 requested_by, request_payload)
            VALUES (%s, %s, 'Pending', 'admin', %s::jsonb)
            RETURNING id
        """, (
            incident_id,
            action_type,
            json.dumps(payload),
        )).fetchone()

        action_id = row[0]

        conn.execute("""
            INSERT INTO incident_audit
                (incident_id, actor, action, details)
            VALUES (%s, %s, %s, %s)
        """, (
            incident_id,
            "admin",
            "Response Action Requested",
            f"Action #{action_id}: {action_type}; max_events={max_events}",
        ))

    return jsonify(
        status="created",
        action_id=action_id,
        incident_id=incident_id,
        action_type=action_type
    ), 201


# ==========================================
# AGENT - GET NEXT ACTION
# ==========================================

@app.route("/api/agent/response-actions/next", methods=["POST"])
def agent_get_next_response_action():

    if not response_agent_authorized():

        return json_error("unauthorized", 401)

    with get_conn() as conn:

        row = conn.execute("""
            WITH next_action AS (
                SELECT id
                FROM response_actions
                WHERE status = 'Pending'
                  AND action_type = 'collect_security_logs'
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE response_actions AS action
            SET status = 'Running'
            FROM next_action
            WHERE action.id = next_action.id
            RETURNING action.id,
                      action.incident_id,
                      action.action_type,
                      action.request_payload
        """).fetchone()

        if not row:

            return jsonify(command=None)

        conn.execute("""
            INSERT INTO incident_audit
                (incident_id, actor, action, details)
            VALUES (%s, %s, %s, %s)
        """, (
            row[1],
            "windows_agent",
            "Response Action Started",
            f"Action #{row[0]}: {row[2]}",
        ))

    return jsonify({

        "command": {

            "id": row[0],
            "incident_id": row[1],
            "action_type": row[2],
            "request_payload": row[3] or {}

        }

    })


# ==========================================
# AGENT - SUBMIT ACTION RESULT
# ==========================================

@app.route(
    "/api/agent/response-actions/<int:action_id>/result",
    methods=["POST"]
)
def agent_submit_response_result(action_id):

    if not response_agent_authorized():

        return json_error("unauthorized", 401)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return json_error("JSON object is required", 400)

    status = data.get("status")

    result = data.get("result", {})

    if status not in {"Completed", "Failed"}:

        return json_error(
            "status must be Completed or Failed",
            400
        )

    if not isinstance(result, dict):

        return json_error(
            "result must be a JSON object",
            400
        )

    try:

        serialized_result = json.dumps(
            result,
            ensure_ascii=False
        )

    except (TypeError, ValueError):

        return json_error(
            "result must contain valid JSON values",
            400
        )

    if len(serialized_result) > 20000:

        return json_error(
            "result is too large (20 KB maximum)",
            413
        )

    with get_conn() as conn:

        row = conn.execute("""
            UPDATE response_actions
            SET status = %s,
                result = %s::jsonb,
                completed_at = NOW()
            WHERE id = %s
              AND status = 'Running'
              AND action_type = 'collect_security_logs'
            RETURNING incident_id
        """, (
            status,
            serialized_result,
            action_id,
        )).fetchone()

        if not row:

            return json_error(
                "action not found or not running",
                404
            )

        summary = str(
            result.get("summary", "")
        )[:1000]

        conn.execute("""
            INSERT INTO incident_audit
                (incident_id, actor, action, details)
            VALUES (%s, %s, %s, %s)
        """, (
            row[0],
            "windows_agent",
            f"Response Action {status}",
            f"Action #{action_id}: {summary}",
        ))

    return jsonify(
        status="saved",
        action_id=action_id
    )


# ==========================================
# APPLICATION START
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

