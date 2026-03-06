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

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=vanta-project&label=README%20views&color=00e5ff&style=flat-square" alt="README views" />
</p>

# VANTA
Adaptive SDN-based Moving Target Defense (MTD) for scan disruption and attack resistance.
## What VANTA Does
VANTA is designed to break attacker reconnaissance.  
When an external scanner maps your network, the discovered IP-to-device mapping quickly becomes invalid because virtual IPs are shuffled by the SDN controller.

Example behavior:
- Before scan result:
  - `Device-1 -> 192.168.13.2`
  - `Vulnerable-Device -> 192.168.13.66`
- After scan completes (about 1 second of probe inactivity):
  - `Device-1 -> 192.168.13.56`
  - `Vulnerable-Device -> 192.168.13.45`

## Project Variant in Scope
This repository contains multiple experiments, but the primary research-grade variant is:
- `27/02/26/ultimate_mtd_controller.py`
- `27/02/26/attack_simulator.py`
- `27/02/26/benchmark_suite.py`
- `27/02/26/templates/login.html`
- `27/02/26/templates/dashboard_ultimate.html`

## Core Features
- SDN controller with OpenFlow 1.3 (Ryu).
- Virtual IP (VIP) allocation and rotation.
- Multiple morphing strategies:
  - Reply-triggered
  - Time-based
  - Packet-count-based
  - Threat-triggered
  - Manual force morph
- Threat detection (port-scan focused).
- Real-time dashboard (Flask + Socket.IO).
- Session auth (Flask-Login).
- Data export:
  - CSV
  - JSON
  - PDF (when reportlab is installed)

## How the System Works
1. Hosts communicate through SDN switch(es) connected to the controller.
2. Controller maps stable real host identities to attacker-facing virtual IPs.
3. Traffic and behavior are tracked per protocol and per source.
4. Recon indicators (e.g., rapid unique-port touching) trigger defensive response.
5. VIP mappings are remorphed and new flows are installed.
6. Dashboard updates in real time via WebSocket events.

## File Guide (27/02/26)
- `ultimate_mtd_controller.py`
  - Main Ryu + Flask app.
  - Strategy engine, threat detector, mapping state, APIs, websocket events.
- `attack_simulator.py`
  - Adversarial test generator (`port_scan`, `syn_flood`, `ping_flood`, `reconnaissance`, `brute_force`, `all`).
- `benchmark_suite.py`
  - Performance testing (`latency`, `throughput`, `cpu`, `memory`, `flow_table`, `strategy_comparison`, `all`).
- `quick_start.md`
  - Run sequence and experiment recipes.
- `project_overview.md`
  - Full minor-project structure, objectives, and research framing.

## API Surface (Controller)
- `GET /api/stats` -> runtime metrics and event history.
- `GET /api/mappings` -> current real-to-virtual mappings.
- `GET|POST /api/strategy` -> read/update strategy flags and thresholds.
- `POST /api/morph/force` -> manual mapping shuffle.
- `GET /api/export/csv` -> morph history CSV.
- `GET /api/export/json` -> full stats JSON.
- `GET /api/export/pdf` -> report PDF (if enabled).

## Quick Start
1. Install dependencies:
   - `pip install ryu rich flask flask-socketio flask-login eventlet reportlab pandas scapy matplotlib seaborn psutil`
2. Start controller:
   - `ryu-manager 27/02/26/ultimate_mtd_controller.py`
3. Start Mininet:
   - `sudo mn --controller=remote,port=6653 --topo=single,3 --mac`
4. Open dashboard:
   - `http://localhost:5000`
   - default: `admin / mtd2024`
5. Trigger traffic or attack simulation:
   - `python 27/02/26/attack_simulator.py --attack port_scan --target 10.0.0.2`

## Research Metrics to Report
- Security:
  - Attack success reduction
  - Scan completeness degradation
  - Detection-to-morph latency
- Performance:
  - RTT overhead
  - Throughput impact
  - Controller CPU/memory
  - Flow churn rate

## Known Notes
- This repo has multiple generations; keep experiments centered on `27/02/26`.
- `attack_simulator.py` may need a small import cleanup (`socket`) in some environments.
- `benchmark_suite.py` assumes Linux-style tooling (`ping -c`, `iperf`) for Mininet workflows.

## Project Name Expansion
**VANTA = Variable Network Topology Architecture**  
Goal: make recon results stale fast enough that attackers cannot reliably weaponize scan output.