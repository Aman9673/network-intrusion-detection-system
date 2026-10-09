import time
from collections import defaultdict


# ============================================================
# FLOW
# ============================================================

class Flow:

    def __init__(self):
        self.start_time = time.time()
        self.last_seen = self.start_time

        self.forward_packets = []
        self.backward_packets = []

        self.forward_bytes = 0
        self.backward_bytes = 0

        self.flow_iat = []
        self.fwd_iat = []
        self.bwd_iat = []

        self.last_fwd_time = None
        self.last_bwd_time = None

        # IP information
        self.src_ip = None
        self.dst_ip = None

        # TCP flags
        self.flags = defaultdict(int)
        self.fwd_flags = defaultdict(int)
        self.bwd_flags = defaultdict(int)

        # Active / Idle
        self.active_periods = []
        self.idle_periods = []

        self.last_packet_time = None
        self.active_start = self.start_time

        self.ACTIVE_THRESHOLD = 1.0

    # ========================================================
    # ADD PACKET
    # ========================================================

    def add_packet(self, packet, direction):

        now = time.time()

        # ----------------------------------------------------
        # IP information
        # ----------------------------------------------------

        if packet.haslayer("IP"):

            ip = packet["IP"]

            if self.src_ip is None:
                self.src_ip = ip.src

            if self.dst_ip is None:
                self.dst_ip = ip.dst

        # ----------------------------------------------------
        # Packet byte length
        # CIC-IDS2018 uses IP packet length
        # ----------------------------------------------------

        if packet.haslayer("IP"):
            packet_bytes = len(packet["IP"])
        else:
            packet_bytes = len(packet)

        # ----------------------------------------------------
        # Active / Idle
        # ----------------------------------------------------

        if self.last_packet_time is not None:

            gap = now - self.last_packet_time

            if gap > self.ACTIVE_THRESHOLD:

                active_duration = (
                    self.last_packet_time - self.active_start
                )

                if active_duration > 0:
                    self.active_periods.append(active_duration)

                self.idle_periods.append(gap)

                self.active_start = now

        self.last_packet_time = now

        # ----------------------------------------------------
        # Forward
        # ----------------------------------------------------

        if direction == "forward":

            self.forward_packets.append(packet)
            self.forward_bytes += packet_bytes

            if self.last_fwd_time is not None:
                self.fwd_iat.append(
                    now - self.last_fwd_time
                )

            self.last_fwd_time = now

        # ----------------------------------------------------
        # Backward
        # ----------------------------------------------------

        else:

            self.backward_packets.append(packet)
            self.backward_bytes += packet_bytes

            if self.last_bwd_time is not None:
                self.bwd_iat.append(
                    now - self.last_bwd_time
                )

            self.last_bwd_time = now

        # ----------------------------------------------------
        # Flow IAT
        # ----------------------------------------------------

        if self.last_seen is not None:
            self.flow_iat.append(
                now - self.last_seen
            )

        self.last_seen = now

        # ----------------------------------------------------
        # TCP FLAGS
        # ----------------------------------------------------

        if packet.haslayer("TCP"):

            tcp = packet["TCP"]

            flag_values = {
                "FIN": bool(tcp.flags.F),
                "SYN": bool(tcp.flags.S),
                "RST": bool(tcp.flags.R),
                "PSH": bool(tcp.flags.P),
                "ACK": bool(tcp.flags.A),
                "URG": bool(tcp.flags.U),
                "ECE": bool(tcp.flags.E),
                "CWE": bool(tcp.flags.C),
            }

            for name, present in flag_values.items():

                if present:

                    # Total flow flag count
                    self.flags[name] += 1

                    # Directional flag count
                    if direction == "forward":
                        self.fwd_flags[name] += 1
                    else:
                        self.bwd_flags[name] += 1


# ============================================================
# FLOW MANAGER
# ============================================================

class FlowManager:

    def __init__(self):

        self.flows = {}

        self.FLOW_TIMEOUT = 5.0

    # ========================================================
    # FLOW KEY
    # ========================================================

    def get_flow_key(self, packet):

        if not packet.haslayer("IP"):
            return None

        ip = packet["IP"]

        src = ip.src
        dst = ip.dst
        proto = ip.proto

        sport = 0
        dport = 0

        if packet.haslayer("TCP"):

            sport = packet["TCP"].sport
            dport = packet["TCP"].dport

        elif packet.haslayer("UDP"):

            sport = packet["UDP"].sport
            dport = packet["UDP"].dport

        return (
            src,
            sport,
            dst,
            dport,
            proto
        )

    # ========================================================
    # UPDATE FLOW
    # ========================================================

    def update_flow(self, packet):

        key = self.get_flow_key(packet)

        if key is None:
            return None

        reverse = (
            key[2],
            key[3],
            key[0],
            key[1],
            key[4]
        )

        flow = None
        direction = "forward"
        flow_key = key

        # ----------------------------------------------------
        # Existing forward flow
        # ----------------------------------------------------

        if key in self.flows:

            flow = self.flows[key]
            direction = "forward"
            flow_key = key

        # ----------------------------------------------------
        # Existing backward flow
        # ----------------------------------------------------

        elif reverse in self.flows:

            flow = self.flows[reverse]
            direction = "backward"
            flow_key = reverse

        # ----------------------------------------------------
        # New flow
        # ----------------------------------------------------

        else:

            flow = Flow()

            self.flows[key] = flow

            direction = "forward"
            flow_key = key

        # ----------------------------------------------------
        # TIMEOUT
        # ----------------------------------------------------

        now = time.time()

        if (
            flow.last_seen is not None
            and now - flow.last_seen > self.FLOW_TIMEOUT
            and (
                len(flow.forward_packets)
                + len(flow.backward_packets)
            ) > 1
        ):

            finished_flow = flow

            if flow_key in self.flows:
                del self.flows[flow_key]

            # ------------------------------------------------
            # Create new flow
            # IMPORTANT: preserve actual packet direction
            # ------------------------------------------------

            new_flow = Flow()

            self.flows[key] = new_flow

            new_flow.add_packet(
                packet,
                direction
            )

            return finished_flow

        # ----------------------------------------------------
        # ADD PACKET
        # ----------------------------------------------------

        flow.add_packet(
            packet,
            direction
        )

        # ----------------------------------------------------
        # TCP FIN / RST
        # ----------------------------------------------------

        if packet.haslayer("TCP"):

            tcp = packet["TCP"]

            fin = bool(tcp.flags.F)
            rst = bool(tcp.flags.R)

            if fin or rst:

                finished_flow = flow

                if flow_key in self.flows:
                    del self.flows[flow_key]

                return finished_flow

        # ----------------------------------------------------
        # ACTIVE FLOW
        # ----------------------------------------------------

        return None

    # ========================================================
    # CHECK TIMEOUT FLOWS
    # ========================================================

    def collect_expired_flows(self):

        now = time.time()

        expired = []

        for key, flow in list(self.flows.items()):

            if (
                now - flow.last_seen
                >= self.FLOW_TIMEOUT
            ):

                if (
                    len(flow.forward_packets)
                    + len(flow.backward_packets)
                ) > 1:

                    expired.append(flow)

                del self.flows[key]

        return expired

    # ========================================================
    # FLUSH ALL FLOWS
    # ========================================================

    def flush(self):

        finished_flows = list(
            self.flows.values()
        )

        self.flows.clear()

        return finished_flows


# ============================================================
# GLOBAL FLOW MANAGER
# ============================================================

flow_manager = FlowManager()