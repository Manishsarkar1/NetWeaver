#!/usr/bin/env python3
"""
MTD PERFORMANCE BENCHMARKING SUITE
Comprehensive performance evaluation for MTD system

USAGE:
    python benchmark_suite.py --test <test_type>
    
Available tests:
    - latency: Measure packet latency with/without MTD
    - throughput: Measure bandwidth with/without MTD
    - cpu: Measure CPU usage
    - memory: Measure memory consumption
    - flow_table: Measure flow table performance
    - strategy_comparison: Compare morphing strategies
    - all: Run complete benchmark suite

REQUIREMENTS:
    pip install pandas matplotlib seaborn psutil
"""

import subprocess
import time
import json
import csv
import argparse
import psutil
import statistics
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.panel import Panel

console = Console()

try:
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    console.print("[yellow]matplotlib/seaborn not available. Plotting disabled.[/yellow]")


class MTDBenchmark:
    """Comprehensive benchmarking suite for MTD system"""
    
    def __init__(self, controller_host='localhost', controller_port=5000):
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tests': []
        }
    
    def _log(self, message, style="white"):
        """Log message"""
        console.print(f"[{style}]{message}[/{style}]")
    
    def _save_results(self, filename=None):
        """Save benchmark results"""
        if filename is None:
            filename = f"benchmark_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self._log(f"Results saved to {filename}", "green")
        return filename

    def _summarize_series(self, values):
        """Return a compact summary for a numeric series."""
        if not values:
            return None

        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'avg': statistics.mean(values),
            'median': statistics.median(values),
            'stddev': statistics.stdev(values) if len(values) > 1 else 0,
        }

    def _percent_change(self, baseline, candidate):
        """Compute percent change while avoiding divide-by-zero."""
        if baseline == 0:
            return None
        return ((candidate - baseline) / baseline) * 100
    
    def _ping_test(self, target='10.0.0.2', count=100):
        """
        Run ping test and collect latency statistics
        
        Returns:
            dict: Statistics including min, max, avg, stddev
        """
        cmd = f"ping -c {count} -i 0.2 {target}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            output = result.stdout
            
            # Parse ping output
            latencies = []
            for line in output.split('\n'):
                if 'time=' in line:
                    time_str = line.split('time=')[1].split(' ')[0]
                    latencies.append(float(time_str))
            
            if latencies:
                return {
                    'count': len(latencies),
                    'min': min(latencies),
                    'max': max(latencies),
                    'avg': statistics.mean(latencies),
                    'median': statistics.median(latencies),
                    'stddev': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                    'raw_data': latencies
                }
            else:
                return None
        
        except Exception as e:
            self._log(f"Ping test error: {str(e)}", "red")
            return None
    
    def latency_benchmark(self, with_mtd=True, without_mtd=False):
        """
        Measure latency with and without MTD
        
        Args:
            with_mtd: Test with MTD enabled
            without_mtd: Test without MTD (baseline)
        """
        console.print(Panel(
            "[bold cyan]LATENCY BENCHMARK[/bold cyan]\n"
            "Measuring round-trip time (RTT)",
            border_style="cyan"
        ))
        
        test_results = {
            'test_name': 'latency',
            'timestamp': datetime.now().isoformat(),
            'scenarios': []
        }
        
        scenarios = []
        if without_mtd:
            scenarios.append(('baseline', 'Without MTD'))
        if with_mtd:
            scenarios.append(('mtd', 'With MTD'))
        
        for scenario_key, scenario_name in scenarios:
            self._log(f"\nTesting: {scenario_name}", "yellow")
            
            # Run ping test
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task(f"Running {scenario_name}...", total=100)
                stats = self._ping_test(count=100)
                progress.update(task, completed=100)
            
            if stats:
                test_results['scenarios'].append({
                    'name': scenario_name,
                    'key': scenario_key,
                    'statistics': {k: v for k, v in stats.items() if k != 'raw_data'},
                    'raw_data': stats['raw_data']
                })
                
                # Display results
                table = Table(title=f"[cyan]{scenario_name} - Latency Statistics[/cyan]")
                table.add_column("Metric", style="white")
                table.add_column("Value (ms)", style="green", justify="right")
                
                table.add_row("Packets", str(stats['count']))
                table.add_row("Min RTT", f"{stats['min']:.2f}")
                table.add_row("Max RTT", f"{stats['max']:.2f}")
                table.add_row("Avg RTT", f"{stats['avg']:.2f}")
                table.add_row("Median RTT", f"{stats['median']:.2f}")
                table.add_row("Std Dev", f"{stats['stddev']:.2f}")
                
                console.print(table)
        
        # Calculate overhead if both scenarios tested
        if len(test_results['scenarios']) == 2:
            baseline_avg = test_results['scenarios'][0]['statistics']['avg']
            mtd_avg = test_results['scenarios'][1]['statistics']['avg']
            overhead = self._percent_change(baseline_avg, mtd_avg)
            
            test_results['overhead_percentage'] = overhead
            
            if overhead is not None:
                console.print(f"\n[bold]Latency Overhead: {overhead:.2f}%[/bold]")
            else:
                console.print("\n[bold]Latency Overhead: unavailable (baseline average is zero)[/bold]")
        
        self.results['tests'].append(test_results)
        
        # Generate plot if available
        if PLOTTING_AVAILABLE and len(test_results['scenarios']) == 2:
            self._plot_latency_comparison(test_results)

        if test_results['scenarios']:
            test_results['summary'] = {
                'scenario_count': len(test_results['scenarios']),
                'statistics': {
                    scenario['key']: scenario['statistics']
                    for scenario in test_results['scenarios']
                }
            }
    
    def throughput_benchmark(self, duration=10):
        """
        Measure throughput using iperf
        
        Args:
            duration: Test duration in seconds
        """
        console.print(Panel(
            "[bold cyan]THROUGHPUT BENCHMARK[/bold cyan]\n"
            f"Measuring bandwidth for {duration} seconds",
            border_style="cyan"
        ))
        
        test_results = {
            'test_name': 'throughput',
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'scenarios': []
        }
        
        # Note: This requires iperf server running
        # Typically: h2 iperf -s &
        
        try:
            cmd = f"iperf -c 10.0.0.2 -t {duration} -f m"
            
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
            ) as progress:
                task = progress.add_task(f"Running iperf for {duration}s...", total=duration)
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=duration+10)
                output = result.stdout
                
                progress.update(task, completed=duration)
            
            # Parse iperf output
            throughput = None
            for line in output.split('\n'):
                if 'Mbits/sec' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'Mbits/sec' in part and i > 0:
                            try:
                                throughput = float(parts[i-1])
                                break
                            except:
                                pass
            
            if throughput:
                test_results['scenarios'].append({
                    'name': 'With MTD',
                    'throughput_mbps': throughput,
                    'duration': duration
                })
                
                table = Table(title="[cyan]Throughput Results[/cyan]")
                table.add_column("Metric", style="white")
                table.add_column("Value", style="green")
                
                table.add_row("Duration", f"{duration}s")
                table.add_row("Throughput", f"{throughput:.2f} Mbits/sec")
                table.add_row("Throughput", f"{throughput/8:.2f} MB/s")
                
                console.print(table)
            else:
                self._log("Could not parse throughput results", "red")
        
        except Exception as e:
            self._log(f"Throughput test error: {str(e)}", "red")
        
        self.results['tests'].append(test_results)
    
    def resource_utilization_benchmark(self, duration=60):
        """
        Monitor CPU and memory usage of MTD controller
        
        Args:
            duration: Monitoring duration in seconds
        """
        console.print(Panel(
            "[bold cyan]RESOURCE UTILIZATION BENCHMARK[/bold cyan]\n"
            f"Monitoring for {duration} seconds",
            border_style="cyan"
        ))
        
        test_results = {
            'test_name': 'resource_utilization',
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'samples': []
        }
        
        # Find Ryu controller process
        ryu_process = None
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'ryu-manager' in ' '.join(proc.info['cmdline']):
                    ryu_process = psutil.Process(proc.info['pid'])
                    break
            except:
                pass
        
        if not ryu_process:
            self._log("Could not find Ryu controller process", "red")
            return
        
        self._log(f"Monitoring process: {ryu_process.pid}", "green")
        
        interval = 1  # Sample every second
        samples = []
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
        ) as progress:
            task = progress.add_task(f"Monitoring for {duration}s...", total=duration)
            
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    cpu_percent = ryu_process.cpu_percent(interval=0.1)
                    memory_info = ryu_process.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024
                    
                    sample = {
                        'time': time.time() - start_time,
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb
                    }
                    samples.append(sample)
                    
                    progress.update(task, completed=time.time() - start_time)
                    time.sleep(interval)
                
                except Exception as e:
                    self._log(f"Monitoring error: {str(e)}", "red")
                    break
        
        if samples:
            cpu_values = [s['cpu_percent'] for s in samples]
            memory_values = [s['memory_mb'] for s in samples]
            
            test_results['samples'] = samples
            test_results['statistics'] = {
                'cpu': self._summarize_series(cpu_values),
                'memory': self._summarize_series(memory_values)
            }
            
            # Display results
            table = Table(title="[cyan]Resource Utilization Statistics[/cyan]")
            table.add_column("Resource", style="white")
            table.add_column("Min", style="green", justify="right")
            table.add_column("Max", style="green", justify="right")
            table.add_column("Avg", style="green", justify="right")
            table.add_column("Median", style="green", justify="right")
            
            table.add_row(
                "CPU %",
                f"{test_results['statistics']['cpu']['min']:.2f}",
                f"{test_results['statistics']['cpu']['max']:.2f}",
                f"{test_results['statistics']['cpu']['avg']:.2f}",
                f"{test_results['statistics']['cpu']['median']:.2f}"
            )
            table.add_row(
                "Memory (MB)",
                f"{test_results['statistics']['memory']['min']:.2f}",
                f"{test_results['statistics']['memory']['max']:.2f}",
                f"{test_results['statistics']['memory']['avg']:.2f}",
                f"{test_results['statistics']['memory']['median']:.2f}"
            )
            
            console.print(table)
            
            # Generate plot if available
            if PLOTTING_AVAILABLE:
                self._plot_resource_usage(test_results)
        
        self.results['tests'].append(test_results)
    
    def strategy_comparison_benchmark(self):
        """
        Compare different morphing strategies
        This requires interacting with the MTD controller API
        """
        console.print(Panel(
            "[bold cyan]MORPHING STRATEGY COMPARISON[/bold cyan]\n"
            "Testing different morphing strategies",
            border_style="cyan"
        ))
        
        strategies = [
            ('reply', 'Reply-Triggered'),
            ('time', 'Time-Based (30s)'),
            ('packet', 'Packet-Count (100)'),
            ('threat', 'Threat-Triggered')
        ]
        
        test_results = {
            'test_name': 'strategy_comparison',
            'timestamp': datetime.now().isoformat(),
            'strategies': []
        }
        
        for strategy_key, strategy_name in strategies:
            self._log(f"\nTesting strategy: {strategy_name}", "yellow")
            
            # Here you would configure the strategy via API and run tests
            # For now, we'll simulate with placeholder data
            
            # Simulate running attack simulation with this strategy
            # In real implementation, this would:
            # 1. Configure strategy via API
            # 2. Run attack simulation
            # 3. Measure effectiveness
            
            strategy_result = {
                'name': strategy_name,
                'key': strategy_key,
                'attacks_detected': 0,
                'morphs_triggered': 0,
                'false_positives': 0,
                'latency_overhead': 0.0,
                'notes': 'Placeholder until controller API-driven evaluation is wired in'
            }
            
            test_results['strategies'].append(strategy_result)

        test_results['summary'] = {
            'strategy_count': len(test_results['strategies']),
            'detected_attacks_total': sum(s['attacks_detected'] for s in test_results['strategies']),
            'morphs_triggered_total': sum(s['morphs_triggered'] for s in test_results['strategies']),
            'false_positives_total': sum(s['false_positives'] for s in test_results['strategies']),
        }
        
        self.results['tests'].append(test_results)
    
    def _plot_latency_comparison(self, test_results):
        """Generate latency comparison plot"""
        if not PLOTTING_AVAILABLE:
            return
        
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
            
            # Box plot
            data = [scenario['raw_data'] for scenario in test_results['scenarios']]
            labels = [scenario['name'] for scenario in test_results['scenarios']]
            
            ax1.boxplot(data, labels=labels)
            ax1.set_ylabel('Latency (ms)')
            ax1.set_title('Latency Distribution')
            ax1.grid(True, alpha=0.3)
            
            # Bar plot for statistics
            stats = [scenario['statistics'] for scenario in test_results['scenarios']]
            x = range(len(stats))
            width = 0.2
            
            ax2.bar([i-width for i in x], [s['min'] for s in stats], width, label='Min')
            ax2.bar(x, [s['avg'] for s in stats], width, label='Avg')
            ax2.bar([i+width for i in x], [s['max'] for s in stats], width, label='Max')
            
            ax2.set_ylabel('Latency (ms)')
            ax2.set_title('Latency Statistics')
            ax2.set_xticks(x)
            ax2.set_xticklabels(labels)
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            filename = f"latency_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            self._log(f"Plot saved to {filename}", "green")
            plt.close()
        
        except Exception as e:
            self._log(f"Plotting error: {str(e)}", "red")
    
    def _plot_resource_usage(self, test_results):
        """Generate resource usage plot"""
        if not PLOTTING_AVAILABLE:
            return
        
        try:
            samples = test_results['samples']
            times = [s['time'] for s in samples]
            cpu = [s['cpu_percent'] for s in samples]
            memory = [s['memory_mb'] for s in samples]
            
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
            
            # CPU usage
            ax1.plot(times, cpu, 'b-', linewidth=1)
            ax1.fill_between(times, cpu, alpha=0.3)
            ax1.set_ylabel('CPU Usage (%)')
            ax1.set_title('CPU Utilization Over Time')
            ax1.grid(True, alpha=0.3)
            ax1.axhline(y=statistics.mean(cpu), color='r', linestyle='--', label=f'Average: {statistics.mean(cpu):.2f}%')
            ax1.legend()
            
            # Memory usage
            ax2.plot(times, memory, 'g-', linewidth=1)
            ax2.fill_between(times, memory, alpha=0.3)
            ax2.set_xlabel('Time (seconds)')
            ax2.set_ylabel('Memory Usage (MB)')
            ax2.set_title('Memory Utilization Over Time')
            ax2.grid(True, alpha=0.3)
            ax2.axhline(y=statistics.mean(memory), color='r', linestyle='--', label=f'Average: {statistics.mean(memory):.2f} MB')
            ax2.legend()
            
            plt.tight_layout()
            filename = f"resource_usage_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            self._log(f"Plot saved to {filename}", "green")
            plt.close()
        
        except Exception as e:
            self._log(f"Plotting error: {str(e)}", "red")
    
    def run_full_benchmark(self):
        """Run complete benchmark suite"""
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]  MTD COMPLETE BENCHMARK SUITE        [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]\n")
        
        # 1. Latency
        self._log("\n1. Running latency benchmark...", "yellow")
        self.latency_benchmark(with_mtd=True)
        time.sleep(2)
        
        # 2. Throughput
        self._log("\n2. Running throughput benchmark...", "yellow")
        self.throughput_benchmark(duration=10)
        time.sleep(2)
        
        # 3. Resource utilization
        self._log("\n3. Running resource utilization benchmark...", "yellow")
        self.resource_utilization_benchmark(duration=30)
        time.sleep(2)
        
        # Save all results
        self.results['summary'] = {
            'tests_run': len(self.results['tests']),
            'generated_at': datetime.now().isoformat(),
        }
        filename = self._save_results()
        
        console.print(f"\n[bold green]✓ Complete benchmark suite finished![/bold green]")
        console.print(f"[green]Results saved to: {filename}[/green]")


def main():
    parser = argparse.ArgumentParser(description='MTD Performance Benchmarking Suite')
    parser.add_argument('--test', type=str, required=True,
                       choices=['latency', 'throughput', 'cpu', 'memory', 'resource', 'strategy', 'all'],
                       help='Benchmark test to run')
    parser.add_argument('--duration', type=int, default=10,
                       help='Test duration in seconds (where applicable)')
    
    args = parser.parse_args()
    
    benchmark = MTDBenchmark()
    
    if args.test == 'latency':
        benchmark.latency_benchmark()
    elif args.test == 'throughput':
        benchmark.throughput_benchmark(duration=args.duration)
    elif args.test in ['resource', 'cpu', 'memory']:
        benchmark.resource_utilization_benchmark(duration=args.duration)
    elif args.test == 'strategy':
        benchmark.strategy_comparison_benchmark()
    elif args.test == 'all':
        benchmark.run_full_benchmark()
    
    # Save results
    benchmark._save_results()


if __name__ == '__main__':
    main()
