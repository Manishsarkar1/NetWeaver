#!/bin/bash

echo "================================================"
echo "  MTD Web Dashboard - Quick Start"
echo "================================================"
echo ""

# Check if running as root for Mininet
if [ "$EUID" -eq 0 ]; then 
    echo "⚠️  Don't run this script as root!"
    echo "   The script will ask for sudo when needed."
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
echo "📋 Checking dependencies..."

if ! command_exists python3; then
    echo "❌ Python 3 not found. Please install Python 3."
    exit 1
fi

if ! command_exists pip; then
    echo "❌ pip not found. Please install pip."
    exit 1
fi

echo "✅ Python 3 and pip found"

# Check if Ryu is installed
if ! python3 -c "import ryu" 2>/dev/null; then
    echo "📦 Installing Ryu and dependencies..."
    pip install -r requirements.txt
else
    echo "✅ Ryu already installed"
fi

# Check if Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "📦 Installing Flask and dependencies..."
    pip install -r requirements.txt
else
    echo "✅ Flask already installed"
fi

echo ""
echo "================================================"
echo "  Starting MTD Controller with Web Dashboard"
echo "================================================"
echo ""
echo "🌐 Dashboard will be available at: http://localhost:5000"
echo "🎮 Controller will listen on port 6653 for OpenFlow"
echo ""
echo "Next steps:"
echo "1. Open http://localhost:5000 in your browser"
echo "2. In another terminal, run: sudo mn --controller=remote,port=6653 --topo=single,3"
echo "3. In Mininet CLI, run: h1 ping -c 5 h2"
echo ""
echo "Press Ctrl+C to stop the controller"
echo ""
echo "================================================"
echo ""

# Start the controller
ryu-manager mtd_web_dashboard.py