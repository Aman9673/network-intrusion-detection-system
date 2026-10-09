from scapy.all import IP, TCP, Raw

from backend.realtime.flow_manager import Flow
from backend.realtime.realtime_predictor import predict_flow


# =====================================================
# CREATE TEST FLOW
# =====================================================

flow = Flow()


# =====================================================
# TEST PACKET 1
# =====================================================

packet1 = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    )
    /
    TCP(
        sport=12345,
        dport=80,
        flags="S"
    )
    /
    Raw(
        b"GET / HTTP/1.1"
    )
)


flow.add_packet(
    packet1,
    "forward"
)


# =====================================================
# TEST PACKET 2
# =====================================================

packet2 = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10"
    )
    /
    TCP(
        sport=80,
        dport=12345,
        flags="SA"
    )
    /
    Raw(
        b"HTTP/1.1 200 OK"
    )
)


flow.add_packet(
    packet2,
    "backward"
)


# =====================================================
# PREDICT
# =====================================================

result = predict_flow(
    flow
)


# =====================================================
# OUTPUT
# =====================================================

print()
print("=" * 70)
print("REALTIME NIDS TEST")
print("=" * 70)

print(
    "Prediction:",
    result
)

print("=" * 70)