from collections import defaultdict
from datetime import datetime
import random
import time

from .models import ThreatEvent


class MorphingStrategy:
    """Manages which conditions trigger IP morphing."""

    def __init__(self, time_fn=None, randint_fn=None):
        self.reply_triggered = True
        self.time_based = False
        self.time_interval = 30
        self.packet_count_based = False
        self.packet_threshold = 100
        self.random_intervals = False
        self.min_interval = 10
        self.max_interval = 60
        self.threat_triggered = True

        self._time_fn = time_fn or time.time
        self._randint_fn = randint_fn or random.randint
        self._packet_counters = defaultdict(int)
        self._last_morph_time = {}

    def _pair_key(self, ip1, ip2):
        return tuple(sorted([ip1, ip2]))

    def should_morph_on_reply(self):
        return self.reply_triggered

    def should_morph_time_based(self, ip1, ip2):
        if not self.time_based:
            return False

        key = self._pair_key(ip1, ip2)
        last = self._last_morph_time.get(key, 0)
        interval = (
            self._randint_fn(self.min_interval, self.max_interval)
            if self.random_intervals
            else self.time_interval
        )
        now = self._time_fn()
        if now - last >= interval:
            self._last_morph_time[key] = now
            return True
        return False

    def record_packet(self, ip1, ip2):
        if self.packet_count_based:
            self._packet_counters[self._pair_key(ip1, ip2)] += 1

    def should_morph_packet_count(self, ip1, ip2):
        if not self.packet_count_based:
            return False

        key = self._pair_key(ip1, ip2)
        if self._packet_counters[key] >= self.packet_threshold:
            self._packet_counters[key] = 0
            return True
        return False


class ThreatDetector:
    """Detects network threats such as port scanning."""

    def __init__(self, time_fn=None, now_fn=None, debug_sink=None):
        self.port_scan_threshold = 5
        self.port_scan_window = 10
        self._time_fn = time_fn or time.time
        self._now_fn = now_fn or (lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self._debug_sink = debug_sink or print
        self._attempts = defaultdict(lambda: {"ports": set(), "time": self._time_fn()})
        self.threats = []

    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        key = (src_ip, dst_ip)
        entry = self._attempts[key]
        now = self._time_fn()

        if now - entry["time"] > self.port_scan_window:
            entry["ports"] = set()
            entry["time"] = now

        entry["ports"].add(dst_port)
        count = len(entry["ports"])

        self._debug_sink(
            f"[IDS] {src_ip} -> {dst_ip}:{dst_port} | "
            f"unique ports in window: {count}/{self.port_scan_threshold} | "
            f"ports: {sorted(entry['ports'])}"
        )

        if count >= self.port_scan_threshold:
            threat = ThreatEvent(
                timestamp=self._now_fn(),
                threat_type="port_scan",
                source_ip=src_ip,
                details=f"Scanned {count} ports on {dst_ip}: {sorted(entry['ports'])}",
                severity="high",
            )
            self.threats.append(threat)
            self._debug_sink(
                f"[IDS] PORT SCAN DETECTED: {src_ip} -> {dst_ip} ({count} ports)"
            )
            entry["ports"] = set()
            entry["time"] = now
            return True

        return False
