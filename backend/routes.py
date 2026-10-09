from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from backend.schemas import PredictionRequest, PredictionResponse
from backend.predictor import predict_attack
from backend.logger import save_log
from backend.database import get_connection

# Authentication
from backend.auth import authenticate_user, create_access_token


router = APIRouter()


# ============================================================
# HOME
# ============================================================

@router.get("/")
def home():

    return {
        "message": "Network Intrusion Detection System Running",
        "mode": "Detection Only",
        "model": "Hybrid CNN-RFNN",
    }


# ============================================================
# LOGIN
# ============================================================

@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends()
):

    # --------------------------------------------------------
    # Authenticate user
    # --------------------------------------------------------

    user = authenticate_user(
        form_data.username,
        form_data.password
    )

    if not user:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    # --------------------------------------------------------
    # Create JWT token
    # --------------------------------------------------------

    access_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"],
        }
    )

    # --------------------------------------------------------
    # Return authentication data
    # --------------------------------------------------------

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "name": user.get(
            "name",
            user["username"]
        ),
    }


# ============================================================
# PREDICT ATTACK
# ============================================================

@router.post(
    "/predict",
    response_model=PredictionResponse
)
def predict(data: PredictionRequest):

    result = predict_attack(
        data.features
    )

    attack = result["attack"]

    confidence = float(
        result["confidence"]
    )

    severity = result.get(
        "severity",
        "Low"
    )

    # --------------------------------------------------------
    # Detection action
    # --------------------------------------------------------

    if str(attack).lower() == "benign":

        action = "Benign Traffic"

    elif confidence >= 95:

        action = "Threat Detected"

    elif confidence >= 80:

        action = "Alert Generated"

    else:

        action = "Monitor"

    # --------------------------------------------------------
    # Save prediction
    # --------------------------------------------------------

    save_log(
        attack_type=attack,
        confidence=confidence,
        action=action
    )

    return PredictionResponse(
        attack=attack,
        confidence=confidence,
        severity=severity,
        action=action
    )


# ============================================================
# ATTACK LOGS
# ============================================================

@router.get("/logs")
def get_logs(limit: int = 20):

    # Do not return the entire attack_logs table to the browser.
    limit = max(1, min(limit, 100))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM attack_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    logs = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return logs


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@router.get("/dashboard")
def dashboard():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM attack_logs
        """
    )
    total_logs = cursor.fetchone()[0] or 0

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        """
    )
    total_alerts = cursor.fetchone()[0] or 0

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM attack_logs
        WHERE LOWER(TRIM(attack_type)) != 'benign'
        """
    )
    active_threats = cursor.fetchone()[0] or 0

    cursor.execute(
        """
        SELECT COALESCE(SUM(bytes), 0)
        FROM attack_logs
        """
    )
    total_bytes = cursor.fetchone()[0] or 0

    conn.close()

    risk_score = min(active_threats * 10, 100)

    if total_bytes >= 1024 * 1024 * 1024:
        total_traffic = f"{total_bytes / (1024 * 1024 * 1024):.2f} GB"
    elif total_bytes >= 1024 * 1024:
        total_traffic = f"{total_bytes / (1024 * 1024):.2f} MB"
    elif total_bytes >= 1024:
        total_traffic = f"{total_bytes / 1024:.2f} KB"
    else:
        total_traffic = f"{total_bytes} B"

    # Names match Dashboard.jsx exactly.
    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "active_threats": active_threats,
        "total_traffic": total_traffic,
        "risk_score": risk_score,
    }


# ============================================================
# LATEST THREAT
# ============================================================

@router.get("/latest-threat")
def latest_threat():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            attack_type,
            confidence,
            source_ip,
            destination_ip,
            action,
            timestamp
        FROM attack_logs
        WHERE LOWER(attack_type) != 'benign'
        ORDER BY id DESC
        LIMIT 1
        """
    )

    row = cursor.fetchone()

    conn.close()

    if row is None:

        return {
            "attack": "None",
            "confidence": 0,
            "severity": "Low",
            "recommendation": "No active threats detected",
            "source_ip": None,
            "destination_ip": None,
            "action": "System Monitoring",
        }

    confidence = float(
        row["confidence"]
    )

    if confidence >= 95:

        severity = "Critical"

    elif confidence >= 80:

        severity = "High"

    elif confidence >= 60:

        severity = "Medium"

    else:

        severity = "Low"

    return {
        "attack": row["attack_type"],
        "confidence": confidence,
        "severity": severity,
        "recommendation": (
            f"Investigate {row['attack_type']}"
        ),
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "action": row["action"],
        "timestamp": row["timestamp"],
    }


# ============================================================
# ALERTS
# ============================================================

@router.get("/alerts")
def get_alerts(limit: int = 50):

    limit = max(1, min(limit, 200))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    alerts = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return alerts


# ============================================================
# THREAT IPS
# ============================================================

@router.get("/threat-ips")
def get_threat_ips():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            source_ip,
            COUNT(*) AS attack_count,
            MAX(confidence) AS max_confidence,
            MAX(timestamp) AS last_seen
        FROM attack_logs
        WHERE
            LOWER(attack_type) != 'benign'
            AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY attack_count DESC
        """
    )

    threats = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return threats

# ============================================================
# THREAT MAP (GeoIP disabled)
# ============================================================

@router.get("/threat-map")
def threat_map():
    """Return threat summaries without geographic lookup or coordinates."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            source_ip,
            COUNT(*) AS attack_count,
            MAX(confidence) AS max_confidence,
            MAX(timestamp) AS last_seen,
            (
                SELECT attack_type
                FROM attack_logs a2
                WHERE a2.source_ip = attack_logs.source_ip
                ORDER BY a2.id DESC
                LIMIT 1
            ) AS attack_type
        FROM attack_logs
        WHERE LOWER(attack_type) != 'benign'
          AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY attack_count DESC
        LIMIT 100
        """
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "ip": row["source_ip"],
            "attack_count": row["attack_count"] or 0,
            "max_confidence": float(row["max_confidence"] or 0),
            "last_seen": row["last_seen"],
            "attack_type": row["attack_type"] or "Unknown",
        }
        for row in rows
    ]

# ============================================================
# TRAFFIC HISTORY
# ============================================================

@router.get("/traffic-history")
def traffic_history():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            strftime('%H:%M', timestamp) AS time,
            SUM(bytes) AS traffic
        FROM attack_logs
        WHERE bytes IS NOT NULL
        GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
        ORDER BY timestamp DESC
        LIMIT 20
        """
    )

    rows = cursor.fetchall()

    conn.close()

    rows = list(reversed(rows))

    return [
        {
            "time": row["time"],
            "traffic": row["traffic"] or 0,
        }
        for row in rows
    ]


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

@router.get("/attack-distribution")
def attack_distribution():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            attack_type AS name,
            COUNT(*) AS value
        FROM attack_logs
        WHERE LOWER(attack_type) != 'benign'
        GROUP BY attack_type
        ORDER BY value DESC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return [
        {
            "name": row["name"],
            "value": row["value"],
        }
        for row in rows
    ]


# ============================================================
# DETECTION STATUS
# ============================================================

@router.get("/detection-status")
def detection_status():

    return {
        "system": "NIDS",
        "mode": "Detection Only",
        "packet_capture": "Active",
        "ai_model": "Loaded",
        "feature_engine": "78 Features",
        "database": "Connected",
        "prevention": "Disabled",
    }