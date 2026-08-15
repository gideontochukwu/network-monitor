"""
Network Data Collector
Pings network devices and saves results to the database
"""

import subprocess
import time
from datetime import datetime
import sys
import os
import random
import psutil

# Add the backend folder to path so we can import database.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import Database

class NetworkCollector:
    """Collects network data by pinging devices"""
    
    def __init__(self):
        self.db = Database()
    
    def ping_host(self, host):
        """
        Ping a host and return the response time in milliseconds
        Returns: (latency_ms, status)
        """
        try:
            # Windows ping command
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '1000', host],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Check if ping was successful
            if "time=" in result.stdout:
                # Extract the time value
                for part in result.stdout.split():
                    if "time=" in part:
                        time_str = part.split("=")[1].replace("ms", "")
                        latency = float(time_str)
                        return latency, "success"
            elif "Request timed out" in result.stdout:
                return None, "timeout"
            else:
                return None, "failed"
                
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            print(f"Error pinging {host}: {e}")
            return None, "error"
    
    def get_bandwidth_usage(self, host="8.8.8.8"):
        """
        Estimate bandwidth usage based on latency.
        NOTE: This is an ESTIMATE, not actual bandwidth measurement.
        """
        latency, status = self.ping_host(host)
        if latency is not None:
            usage = min(90, max(10, latency * 2))
            return round(usage, 1)
        return round(random.uniform(10, 50), 1)
    
    def get_packet_loss(self, host="8.8.8.8"):
        """Simulate packet loss monitoring (0-2%)"""
        latency, status = self.ping_host(host)
        if latency is not None and latency > 100:
            return round(random.uniform(0, 2), 1)
        return round(random.uniform(0, 0.5), 1)
    
    # ===== SYSTEM METRICS METHODS =====
    
    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=1)
    
    def get_memory_usage(self):
        return psutil.virtual_memory().percent
    
    def get_disk_usage(self, path='/'):
        return psutil.disk_usage(path).percent
    
    def get_system_uptime(self):
        return time.time() - psutil.boot_time()
    
    def get_process_count(self):
        return len(psutil.pids())
    
    def get_network_traffic(self):
        """Get network I/O statistics (bytes sent/received)"""
        net = psutil.net_io_counters()
        return {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv
        }
    
    def format_uptime(self, seconds):
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def collect_for_device(self, device):
        """Collect data for a single device"""
        device_id = device['id']
        name = device['name']
        ip = device['ip']
        
        print(f"📡 Pinging {name} ({ip})...")
        
        latency, status = self.ping_host(ip)
        
        if latency is not None:
            print(f"   ✅ Latency: {latency}ms")
        else:
            print(f"   ❌ {status}")
        
        self.db.save_ping_result(device_id, latency, status)
        
        bandwidth = self.get_bandwidth_usage(ip)
        print(f"   📊 Bandwidth: {bandwidth}%")
        self.db.save_metric(device_id, "bandwidth", bandwidth)
        
        packet_loss = self.get_packet_loss(ip)
        print(f"   📊 Packet Loss: {packet_loss}%")
        self.db.save_metric(device_id, "packet_loss", packet_loss)
        
        # System metrics (only for local device)
        if ip == "127.0.0.1" or ip == "localhost" or ip == "192.168.43.171":
            cpu = self.get_cpu_usage()
            memory = self.get_memory_usage()
            disk = self.get_disk_usage()
            uptime = self.get_system_uptime()
            processes = self.get_process_count()
            net = self.get_network_traffic()
            
            print(f"   💻 CPU: {cpu}%")
            print(f"   🧠 Memory: {memory}%")
            print(f"   💾 Disk: {disk}%")
            print(f"   ⏱️ Uptime: {self.format_uptime(uptime)}")
            print(f"   📋 Processes: {processes}")
            print(f"   📶 Net Sent: {net['bytes_sent']/1024/1024:.2f} MB")
            print(f"   📶 Net Recv: {net['bytes_recv']/1024/1024:.2f} MB")
            
            # Save system metrics
            self.db.save_system_metric(device_id, "cpu", cpu)
            self.db.save_system_metric(device_id, "memory", memory)
            self.db.save_system_metric(device_id, "disk", disk)
            self.db.save_system_metric(device_id, "uptime", uptime)
            self.db.save_system_metric(device_id, "processes", processes)
            self.db.save_system_metric(device_id, "net_sent", net['bytes_sent'])
            self.db.save_system_metric(device_id, "net_recv", net['bytes_recv'])
        
        return latency, status, bandwidth, packet_loss
    
    def run_collection(self, devices=None):
        if devices is None:
            devices = self.db.get_all_devices()
        
        if not devices:
            print("⚠️ No devices found in database.")
            return
        
        print("=" * 50)
        print(f"📊 Collecting data for {len(devices)} device(s)")
        print("=" * 50)
        
        for device in devices:
            self.collect_for_device(device)
        
        print("=" * 50)
        print("✅ Collection complete!")
        print("=" * 50)
    
    def run_continuous(self, interval=10):
        print(f"🔄 Starting continuous monitoring (every {interval} seconds)")
        print("Press Ctrl+C to stop")
        try:
            while True:
                self.run_collection()
                print(f"\n⏳ Waiting {interval} seconds...\n")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")

if __name__ == "__main__":
    collector = NetworkCollector()
    devices = collector.db.get_all_devices()
    if not devices:
        print("\n⚠️ No devices found. Adding default devices...")
        collector.db.add_device("Google DNS", "8.8.8.8")
        collector.db.add_device("Cloudflare DNS", "1.1.1.1")
    collector.run_collection()