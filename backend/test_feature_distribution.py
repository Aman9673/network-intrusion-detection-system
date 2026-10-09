import numpy as np
import joblib

from backend.realtime.flow_manager import Flow
from backend.realtime.feature_extractor import FeatureExtractor
from backend.predictor import FEATURE_NAMES, scaler


# ============================================================
# CREATE REALTIME TEST FLOW
# ============================================================

flow = Flow()

from scapy.all import IP, TCP, Raw


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

flow.add_packet(packet1, "forward")
flow.add_packet(packet2, "backward")


# ============================================================
# FEATURES
# ============================================================

extractor = FeatureExtractor(flow)

features = np.asarray(
    extractor.basic_features(),
    dtype=np.float64
)


# ============================================================
# SCALER STATISTICS
# ============================================================

mean_values = np.asarray(
    scaler.mean_,
    dtype=np.float64
)

scale_values = np.asarray(
    scaler.scale_,
    dtype=np.float64
)


# ============================================================
# STANDARDIZED VALUES
# ============================================================

scaled = (
    features - mean_values
) / np.where(
    scale_values == 0,
    1,
    scale_values
)


# ============================================================
# PRINT MOST EXTREME FEATURES
# ============================================================

print()
print("=" * 100)
print("REALTIME FEATURE DISTRIBUTION DIAGNOSTIC")
print("=" * 100)

print()

print(
    f"{'Feature':<32}"
    f"{'Realtime':>18}"
    f"{'Train Mean':>18}"
    f"{'Train Std':>18}"
    f"{'Z-Score':>14}"
)

print("-" * 100)


rows = []

for i in range(78):

    rows.append(
        (
            abs(scaled[i]),
            FEATURE_NAMES[i],
            features[i],
            mean_values[i],
            scale_values[i],
            scaled[i]
        )
    )


rows.sort(
    reverse=True,
    key=lambda x: x[0]
)


for _, name, value, train_mean, train_std, z in rows:

    print(
        f"{name:<32}"
        f"{value:>18.6f}"
        f"{train_mean:>18.6f}"
        f"{train_std:>18.6f}"
        f"{z:>14.2f}"
    )


print("=" * 100)

print()
print(
    "Features with |Z| > 10:",
    sum(abs(scaled) > 10)
)

print(
    "Features with |Z| > 20:",
    sum(abs(scaled) > 20)
)

print(
    "Features with |Z| > 50:",
    sum(abs(scaled) > 50)
)

print()