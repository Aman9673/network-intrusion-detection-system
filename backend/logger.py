from backend.database import get_connection
from datetime import datetime


# =====================================================
# SEVERITY
# =====================================================

def calculate_severity(confidence):

    confidence = float(confidence)

    if confidence >= 95:
        return "Critical"

    if confidence >= 80:
        return "High"

    if confidence >= 60:
        return "Medium"

    return "Low"


# =====================================================
# SAVE PREDICTION LOG
# =====================================================

def save_log(
    attack_type,
    confidence,
    source_ip=None,
    destination_ip=None,
    action=None,
    traffic_bytes=0
):

    confidence = float(confidence)
    traffic_bytes = int(traffic_bytes or 0)
    attack_type = str(attack_type)

    severity = calculate_severity(confidence)

    conn = get_connection()
    cursor = conn.cursor()

    # =================================================
    # DUPLICATE PROTECTION
    # Ignore identical detection within 2 seconds
    # =================================================

    cursor.execute(
        """
        SELECT id
        FROM attack_logs
        WHERE attack_type = ?
          AND ABS(confidence - ?) < 0.01
          AND source_ip IS ?
          AND destination_ip IS ?
          AND bytes = ?
          AND timestamp >= datetime('now', '-2 seconds')
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            attack_type,
            confidence,
            source_ip,
            destination_ip,
            traffic_bytes
        )
    )

    duplicate = cursor.fetchone()

    if duplicate is not None:
        conn.close()
        return False

    # =================================================
    # SAVE ATTACK LOG
    # =================================================

    cursor.execute(
        """
        INSERT INTO attack_logs
        (
            attack_type,
            confidence,
            source_ip,
            destination_ip,
            action,
            bytes
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            attack_type,
            confidence,
            source_ip,
            destination_ip,
            action,
            traffic_bytes
        )
    )

    # =================================================
    # CREATE ALERT
    # =================================================

    if (
        attack_type.lower() != "benign"
        and severity in ["High", "Critical"]
    ):

        message = (
            f"{severity} Alert: "
            f"{attack_type} detected "
            f"with {confidence:.2f}% "
            f"confidence."
        )

        cursor.execute(
            """
            INSERT INTO alerts
            (
                attack_type,
                severity,
                message,
                source_ip,
                destination_ip,
                confidence,
                action
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attack_type,
                severity,
                message,
                source_ip,
                destination_ip,
                confidence,
                action
            )
        )

    conn.commit()
    conn.close()

    return True


# =====================================================
# GET SEVERITY
# =====================================================

def get_severity(confidence):

    return calculate_severity(confidence)