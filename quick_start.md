# VANTA Quick Start

## What You Will Run
- `ultimate_mtd_controller.py` as the SDN controller + dashboard backend.
- Mininet with remote controller mode.
- Optional attack and benchmark scripts for validation.

## Prerequisites
- Linux environment (native, VM, or WSL with networking support).
- Python 3.8+
- Mininet + Open vSwitch
- Ryu

## 1) Install Dependencies
```bash
pip install -r requirements.txt
pip install pandas scapy matplotlib seaborn psutil
```

Optional hardening before launch:
```bash
export VANTA_SECRET_KEY='replace-this-secret'
export VANTA_ADMIN_USERNAME='admin'
export VANTA_ADMIN_PASSWORD='replace-this-password'
export VANTA_MFA_CODE='246810'
export VANTA_DEPLOYMENT_MODE='hybrid'
```

Windows PowerShell:
```powershell
$env:VANTA_SECRET_KEY='replace-this-secret'
$env:VANTA_ADMIN_USERNAME='admin'
$env:VANTA_ADMIN_PASSWORD='replace-this-password'
$env:VANTA_MFA_CODE='246810'
$env:VANTA_DEPLOYMENT_MODE='hybrid'
```

## 2) Start VANTA Controller
```bash
ryu-manager ultimate_mtd_controller.py
```
Expected:
- OpenFlow listener on port `6653`
- Dashboard on `http://localhost:5000`
- Default login: `admin / mtd2024`
- Demo MFA code: `246810`

## 3) Start Mininet (New Terminal)
```bash
sudo mn --controller=remote,port=6653 --topo=single,3 --mac
```

## 4) Generate Baseline Traffic
Inside Mininet CLI:
```bash
h1 ping -c 5 h2
```
This should create packet activity, VIP assignments, and morph events on the dashboard.

## 5) Run Attack Simulation (Optional)
From host terminal (or via Mininet host shell):
```bash
python attack_simulator.py --attack port_scan --target 10.0.0.2
```
Other attack modes:
- `syn_flood`
- `ping_flood`
- `reconnaissance`
- `brute_force`
- `all`

## 6) Run Performance Benchmark (Optional)
```bash
python benchmark_suite.py --test latency
python benchmark_suite.py --test strategy_comparison
python benchmark_suite.py --test all
```

## 7) Useful Dashboard APIs
- `GET /api/stats`
- `GET /api/mappings`
- `GET/POST /api/strategy`
- `POST /api/morph/force`
- `GET /api/access/context`
- `GET /api/deployment/profile`
- `GET /api/health`

## Quick Validation Checklist
- Controller sees switch connection.
- Dashboard loads and updates in real-time.
- VIP mapping table changes over time.
- Port scan triggers threat events.
- Exports download correctly (CSV/JSON/PDF).
- Core logic tests pass with `python -m unittest discover -s tests -v`.

## Common Issues
1. `Port 6653 or 5000 already in use`
- Stop old processes or change ports.

2. `Mininet behaves oddly`
```bash
sudo mn -c
```
Then restart Mininet.

3. `Dashboard updates but no morphing`
- Confirm traffic includes ICMP/TCP/UDP exchanges.
- Check strategy settings in dashboard.

4. `Attack script fails`
- Ensure scapy is installed and run with proper permissions when required.

5. `Benchmark commands fail`
- Ensure Linux tools like `ping` and `iperf` are available.

## Cleanup
```bash
# stop controller with Ctrl+C
sudo mn -c
```
