from dataclasses import dataclass


@dataclass
class MorphEvent:
    timestamp: str
    protocol: str
    ip1: str
    ip2: str
    old_vip1: str
    new_vip1: str
    old_vip2: str
    new_vip2: str
    trigger: str


@dataclass
class ThreatEvent:
    timestamp: str
    threat_type: str
    source_ip: str
    details: str
    severity: str
