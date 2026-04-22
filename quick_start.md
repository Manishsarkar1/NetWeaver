# VANTA Experiment Reproduction Guide

## Purpose
Use this guide to reproduce a lab experiment, collect measurements, and compare morphing behavior under controlled conditions.

## What You Will Run
- `ultimate_mtd_controller.py` as the research controller and observation backend
- Mininet with a remote OpenFlow controller
- Optional attack and benchmark scripts for stimulus and measurement

## Prerequisites
- Linux environment, VM, or WSL setup with working Mininet networking
- Python 3.8+
- Mininet and Open vSwitch
- Ryu

## 1) Install Dependencies
```bash
pip install -r requirements.txt
pip install pandas scapy matplotlib seaborn psutil
```

Optional experiment configuration:
```bash
export VANTA_SECRET_KEY='lab-secret'
export VANTA_ADMIN_USERNAME='admin'
export VANTA_ADMIN_PASSWORD='mtd2024'
export VANTA_MFA_CODE='246810'
export VANTA_DEPLOYMENT_MODE='baseline'
```

Windows PowerShell:
```powershell
$env:VANTA_SECRET_KEY='lab-secret'
$env:VANTA_ADMIN_USERNAME='admin'
$env:VANTA_ADMIN_PASSWORD='mtd2024'
$env:VANTA_MFA_CODE='246810'
$env:VANTA_DEPLOYMENT_MODE='baseline'
```

## 2) Run Unit Tests First
```bash
python -m unittest discover -s tests -v
```

## 3) Start the Research Controller
```bash
ryu-manager ultimate_mtd_controller.py
```

Expected:
- OpenFlow listener on port `6653`
- Observation UI on `http://localhost:5000`
- Default login: `admin / mtd2024`

## 4) Launch a Small Lab Topology
```bash
sudo mn --controller=remote,port=6653 --topo=single,3 --mac
```

## 5) Generate Baseline Traffic
Inside the Mininet CLI:
```bash
h1 ping -c 5 h2
```

This creates initial controller observations and VIP assignments.

## 6) Introduce an Adversarial Stimulus
From the host terminal or from a Mininet host shell:
```bash
python attack_simulator.py --attack port_scan --target 10.0.0.2
```

Other modes include:
- `syn_flood`
- `ping_flood`
- `reconnaissance`
- `brute_force`
- `all`

## 7) Collect Comparative Measurements
```bash
python benchmark_suite.py --test latency
python benchmark_suite.py --test strategy_comparison
python benchmark_suite.py --test all
```

## 8) Observation Endpoints
- `GET /api/stats`
- `GET /api/mappings`
- `GET/POST /api/strategy`
- `POST /api/morph/force`
- `GET /api/access/context`
- `GET /api/deployment/profile`
- `GET /api/health`

Treat these as experiment instrumentation rather than production APIs.

## Validation Checklist
- The switch connects to the controller.
- VIP mappings appear and change over time.
- Scan activity creates threat events.
- Morph events are visible in logs or the dashboard.
- Benchmark outputs are produced without runtime errors.

## Troubleshooting
1. `Port 6653 or 5000 already in use`
Stop older controller processes or move the ports.

2. `Mininet behaves oddly`
```bash
sudo mn -c
```

3. `Traffic appears but remapping does not happen`
Check the active strategy configuration and confirm packet exchange is occurring.

4. `Attack script fails`
Install `scapy` and run with the permissions required by your environment.

5. `Benchmark commands fail`
Ensure Linux utilities such as `ping` and `iperf` are available.

## Cleanup
```bash
# stop controller with Ctrl+C
sudo mn -c
```
