import time

from scapy.all import sniff
from scapy.layers.inet import IP

from backend.realtime.flow_manager import flow_manager
from backend.realtime.feature_extractor import FeatureExtractor
from backend.predictor import predict_attack
from backend.logger import save_log


# ============================================================
# DUPLICATE DETECTION PROTECTION
# ============================================================

_recent_detections = {}

DEDUP_WINDOW = 5.0


# ============================================================
# MEANINGFUL FLOW FILTER
# ============================================================

def is_meaningful_flow(flow):

    if flow is None:
        return False

    total_packets = (
        len(flow.forward_packets)
        + len(flow.backward_packets)
    )

    total_bytes = (
        flow.forward_bytes
        + flow.backward_bytes
    )

    if total_packets < 4:
        return False

    if total_bytes < 200:
        return False

    return True


# ============================================================
# DUPLICATE CHECK
# ============================================================

def is_duplicate_detection(
    src_ip,
    dst_ip,
    attack,
    confidence,
    traffic_bytes
):

    global _recent_detections

    now = time.time()

    # Remove old entries
    expired_keys = [
        key
        for key, timestamp in _recent_detections.items()
        if now - timestamp > DEDUP_WINDOW
    ]

    for key in expired_keys:
        del _recent_detections[key]

    fingerprint = (
        src_ip,
        dst_ip,
        str(attack),
        round(float(confidence), 1),
        int(traffic_bytes)
    )

    if fingerprint in _recent_detections:
        return True

    _recent_detections[fingerprint] = now

    return False


# ============================================================
# PREDICT COMPLETED FLOW
# ============================================================

def predict_flow(flow):

    if flow is None:
        return

    if not is_meaningful_flow(flow):
        return

    try:

        # ----------------------------------------------------
        # EXTRACT 78 FEATURES
        # ----------------------------------------------------

        extractor = FeatureExtractor(flow)

        features = extractor.basic_features()

        if len(features) != 78:

            print(
                f"[ERROR] Invalid feature vector: "
                f"{len(features)}"
            )

            return

        # ----------------------------------------------------
        # REALTIME FEATURES
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print("REALTIME FLOW FEATURES")
        print("=" * 70)

        for i, value in enumerate(features, 1):

            try:
                print(
                    f"{i:02d}. {float(value):.6f}"
                )

            except Exception:
                print(
                    f"{i:02d}. {value}"
                )

        print("=" * 70)

        # ----------------------------------------------------
        # AI PREDICTION
        # ----------------------------------------------------

        result = predict_attack(features)

        attack = result.get(
            "attack",
            "Unknown"
        )

        confidence = float(
            result.get(
                "confidence",
                0.0
            )
        )

        severity = result.get(
            "severity",
            "Low"
        )

        # ----------------------------------------------------
        # FLOW IP INFORMATION
        # ----------------------------------------------------

        src_ip = getattr(
            flow,
            "src_ip",
            "Unknown"
        )

        dst_ip = getattr(
            flow,
            "dst_ip",
            "Unknown"
        )

        # ----------------------------------------------------
        # TRAFFIC BYTES
        # ----------------------------------------------------

        traffic_bytes = (
            getattr(
                flow,
                "forward_bytes",
                0
            )
            +
            getattr(
                flow,
                "backward_bytes",
                0
            )
        )

        # ----------------------------------------------------
        # DETECTION ACTION
        # ----------------------------------------------------

        if str(attack).lower() == "benign":

            action = "Benign Traffic"

        elif confidence >= 95:

            action = "Threat Detected"

        elif confidence >= 80:

            action = "Alert Generated"

        else:

            action = "Monitor"

        # ----------------------------------------------------
        # TERMINAL OUTPUT
        # ----------------------------------------------------

        print()
        print("=" * 70)

        print(
            f"FLOW: {src_ip} -> {dst_ip}"
        )

        print(
            f"Prediction : {attack}"
        )

        print(
            f"Confidence : {confidence:.2f}%"
        )

        print(
            f"Severity   : {severity}"
        )

        print(
            f"Action     : {action}"
        )

        print(
            f"Bytes      : {traffic_bytes}"
        )

        print("=" * 70)

        # ----------------------------------------------------
        # DUPLICATE PROTECTION
        # ----------------------------------------------------

        if is_duplicate_detection(
            src_ip,
            dst_ip,
            attack,
            confidence,
            traffic_bytes
        ):

            print(
                "[Duplicate Detection Ignored]"
            )

            return

        # ----------------------------------------------------
        # DATABASE
        # ----------------------------------------------------

        try:

            saved = save_log(
                attack_type=attack,
                confidence=confidence,
                source_ip=src_ip,
                destination_ip=dst_ip,
                action=action,
                traffic_bytes=traffic_bytes
            )

            if saved is False:

                print(
                    "[Duplicate Database Entry Ignored]"
                )

        except Exception as e:

            print(
                "[Logger Error]:",
                e
            )

    except Exception as e:

        print(
            "[Flow Prediction Error]:",
            e
        )


# ============================================================
# PROCESS ONE PACKET
# ============================================================

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    try:

        # ----------------------------------------------------
        # UPDATE FLOW
        # ----------------------------------------------------

        completed_flow = (
            flow_manager.update_flow(packet)
        )

        # ----------------------------------------------------
        # PREDICT COMPLETED FLOW
        # ----------------------------------------------------

        if completed_flow is not None:

            predict_flow(
                completed_flow
            )

        # ----------------------------------------------------
        # CHECK EXPIRED FLOWS
        # ----------------------------------------------------

        expired_flows = (
            flow_manager.collect_expired_flows()
        )

        for flow in expired_flows:

            predict_flow(
                flow
            )

    except Exception as e:

        print(
            "[Packet Processing Error]:",
            e
        )


# ============================================================
# FLUSH ALL ACTIVE FLOWS
# ============================================================

def flush_flows():

    try:

        flows = flow_manager.flush()

        print()
        print(
            f"Finalizing {len(flows)} active flows..."
        )

        for flow in flows:

            predict_flow(
                flow
            )

    except Exception as e:

        print(
            "[Flow Flush Error]:",
            e
        )


# ============================================================
# START REAL-TIME MONITORING
# ============================================================

def start_monitoring():

    print("=" * 70)
    print("       NIDS REAL-TIME NETWORK MONITORING")
    print("=" * 70)

    print()

    print(
        "AI Model       : ACTIVE"
    )

    print(
        "Packet Capture : ACTIVE"
    )

    print(
        "Feature Engine : 78 FEATURES"
    )

    print(
        "Detection      : ACTIVE"
    )

    print(
        "Prevention     : DISABLED"
    )

    print(
        "Database       : ACTIVE"
    )

    print()

    print(
        "System Mode    : DETECTION ONLY"
    )

    print(
        "Flow Timeout   : 5 SECONDS"
    )

    print(
        "Minimum Flow   : 4 PACKETS / 200 BYTES"
    )

    print(
        "Duplicate Window : 5 SECONDS"
    )

    print(
        "Waiting for network packets..."
    )

    print("=" * 70)

    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print(
            "Stopping NIDS..."
        )

        flush_flows()

        print()
        print(
            "NIDS monitoring stopped."
        )

    except Exception as e:

        print(
            "[Packet Capture Error]:",
            e
        )

        flush_flows()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_monitoring()