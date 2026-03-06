<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&height=220&color=0:0b1022,35:0e1f4d,100:00e5ff&text=VANTA&fontColor=ffffff&fontSize=64&fontAlignY=38&desc=Variable%20Network%20Topology%20Architecture&descAlignY=60&animation=fadeIn" alt="VANTA banner" />
</p>

<p align="center">
  <a href="https://github.com/">
    <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=21&pause=1300&color=00F5FF&center=true&vCenter=true&width=980&lines=Adaptive+SDN-based+Moving+Target+Defense;Scan+Detected+%E2%86%92+VIP+Morph+Triggered;Recon+Data+Expires+Fast" alt="Typing animation" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SDN-OpenFlow%201.3-00c2ff?style=for-the-badge&logo=openvswitch&logoColor=white" alt="OpenFlow badge" />
  <img src="https://img.shields.io/badge/Controller-Ryu-0ea5e9?style=for-the-badge&logo=python&logoColor=white" alt="Ryu badge" />
  <img src="https://img.shields.io/badge/Defense-Moving%20Target-10b981?style=for-the-badge" alt="MTD badge" />
  <img src="https://img.shields.io/badge/Status-Research%20Prototype-f59e0b?style=for-the-badge" alt="Status badge" />
</p>

# VANTA
Adaptive SDN-based Moving Target Defense (MTD) focused on invalidating attacker scan results through fast virtual IP (VIP) morphing.

## Why VANTA
External reconnaissance should become stale almost immediately.

| Phase | Device 1 | Device 2 (Vulnerable Device) |
|---|---|---|
| Scan output (t0) | `192.168.13.2` | `192.168.13.66` |
| After morph (t0 + ~1s) | `192.168.13.56` | `192.168.13.45` |

## Minimal Architecture
```mermaid
flowchart TB
    A["External Attacker"] --> B["OpenFlow Switch / OVS"]
    B --> C["VANTA Controller \n Ryu + Strategy Engine"]
    C --> D["VIP Mapper\nReal IP <-> Virtual IP"]
    C --> E["Threat Detector\nScan / Probe Patterns"]
    C --> F["Web Dashboard\nFlask + Socket.IO"]
    D --> G["Protected Hosts"]
    E --> C

    classDef core fill:#0e1f4d,stroke:#00e5ff,color:#ffffff,stroke-width:1px;
    classDef edge fill:#0a152f,stroke:#3b82f6,color:#dbeafe,stroke-width:1px;

    class C,D,E core;
    class A,B,F,G edge;
```

## How It Works
1. Hosts keep stable real identities internally.
2. Controller assigns attacker-facing VIPs.
3. Recon behavior is detected (for example rapid unique-port probes).
4. When scan activity goes idle (for example ~1 second), VIP mappings are shuffled.
5. Old attacker intel is invalidated; dashboard reflects the new map in real time.

## Project Scope (Primary Variant)
All active work is centered on `27/02/26/`.

```text
27/02/26/
+-- ultimate_mtd_controller.py   # Main Ryu + Flask controller
+-- attack_simulator.py          # Adversarial scenarios
+-- benchmark_suite.py           # Performance evaluation
+-- quick_start.md               # Run steps
+-- project_overview.md          # Research framing
+-- templates/
    +-- login.html
    +-- dashboard_ultimate.html
```

## Core Capabilities
- OpenFlow 1.3 SDN control plane (Ryu).
- VIP allocation and morphing.
- Strategy modes: reply, time, packet-count, threat-triggered, manual.
- Port-scan-oriented threat detection.
- Real-time dashboard updates via WebSocket.
- Authentication and session handling.
- CSV/JSON/PDF exports.

## Quick Start
```bash
# 1) Install dependencies
pip install ryu rich flask flask-socketio flask-login eventlet reportlab pandas scapy matplotlib seaborn psutil

# 2) Start controller
ryu-manager ultimate_mtd_controller.py

# 3) Start Mininet (new terminal)
sudo mn --controller=remote,port=6653 --topo=single,3 --mac

# 4) Open dashboard
http://localhost:5000
default: admin / mtd2024
```

## API Surface
| Endpoint | Method | Purpose |
|---|---|---|
| `/api/stats` | `GET` | Runtime metrics and event history |
| `/api/mappings` | `GET` | Current real-to-VIP map |
| `/api/strategy` | `GET/POST` | Read or update strategy config |
| `/api/morph/force` | `POST` | Trigger immediate morph |
| `/api/export/csv` | `GET` | Download morph history |
| `/api/export/json` | `GET` | Download full stats |
| `/api/export/pdf` | `GET` | Download PDF report |

## Experiment Checklist
- `python 27/02/26/attack_simulator.py --attack port_scan --target 10.0.0.2`
- `python 27/02/26/benchmark_suite.py --test latency`
- `python 27/02/26/benchmark_suite.py --test strategy_comparison`

## Metrics to Report
- Security: attack success reduction, scan completeness degradation, detection-to-morph delay.
- Performance: RTT/throughput overhead, CPU/memory usage, flow churn.

## Notes
- `benchmark_suite.py` assumes Linux/Mininet tools (`ping -c`, `iperf`).
- VANTA objective: force attacker reconnaissance data to expire faster than exploitation cycles.