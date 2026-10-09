from scapy.all import IP, TCP, Raw

from backend.realtime.flow_manager import Flow
from backend.realtime.feature_extractor import FeatureExtractor
from backend.predictor import predict_attack, FEATURE_NAMES


# ============================================================
# CREATE REALTIME TEST FLOW
# ============================================================

flow = Flow()

packet1 = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    )
    /
    TCP(
        sport=12345,
        dport=443,
        flags="S"
    )
)

flow.add_packet(
    packet1,
    "forward"
)


packet2 = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10"
    )
    /
    TCP(
        sport=443,
        dport=12345,
        flags="SA"
    )
    /
    Raw(b"HTTP/1.1 200 OK")
)

flow.add_packet(
    packet2,
    "backward"
)


# ============================================================
# EXTRACT EXACT REALTIME FEATURES
# ============================================================

extractor = FeatureExtractor(flow)

features = extractor.basic_features()


# ============================================================
# VALIDATE
# ============================================================

print()
print("=" * 70)
print("REALTIME MODEL SANITY TEST")
print("=" * 70)

print(
    "Feature count:",
    len(features)
)

if len(features) != 78:
    raise ValueError(
        f"Extractor generated {len(features)} features, expected 78"
    )


# ============================================================
# PRINT FEATURES
# ============================================================

print()
print("-" * 70)

for i, (name, value) in enumerate(
    zip(FEATURE_NAMES, features),
    start=1
):

    print(
        f"{i:02d}. "
        f"{name:<30} "
        f"{float(value):.10f}"
    )


# ============================================================
# MODEL PREDICTION
# ============================================================

print()
print("-" * 70)
print("MODEL PREDICTION")
print("-" * 70)

result = predict_attack(features)

print(result)

print("=" * 70)