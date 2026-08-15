"""
Auto Discovery Module
Scans the network and automatically adds new devices
"""

import subprocess
import ipaddress
import socket
import time
from database import Database

class AutoDiscovery:
    def __init__(self):
        self.db = Database()
    
    def get_my_network(self):
        """Automatically detect the current network range"""
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Determine network range based on IP
            if local_ip.startswith('192.168.'):
                network = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            elif local_ip.startswith('10.'):
                network = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            elif local_ip.startswith('172.'):
                parts = local_ip.split('.')
                if 16 <= int(parts[1]) <= 31:
                    network = f"{parts[0]}.{parts[1]}.0.0/16"
                else:
                    network = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            else:
                network = "192.168.1.0/24"
            
            print(f"🔍 Auto-detected network: {network}")
            return network
        except Exception as e:
            print(f"⚠️ Could not detect network: {e}")
            return "192.168.1.0/24"
    
    def get_existing_ips(self):
        """Get all IPs already in the database"""
        devices = self.db.get_all_devices()
        return [d['ip'] for d in devices]
    
    def ping_host(self, ip, timeout=1):
        """Ping a host to check if it's alive"""
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            if "time=" in result.stdout or "TTL=" in result.stdout:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ip
                return True, hostname
            return False, None
        except:
            return False, None
    
    def scan_network(self, network=None, timeout=0.5):
        """Scan a network for active devices"""
        if network is None:
            network = self.get_my_network()
        
        print(f"🔍 Scanning network: {network}")
        print("=" * 50)
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError:
            print(f"❌ Invalid network: {network}")
            return []
        
        existing_ips = self.get_existing_ips()
        discovered = []
        active_count = 0
        total = sum(1 for _ in network_obj.hosts())
        
        print(f"📡 Scanning {total} IP addresses...")
        print("=" * 50)
        
        for idx, ip in enumerate(network_obj.hosts()):
            ip_str = str(ip)
            is_alive, hostname = self.ping_host(ip_str, timeout)
            
            if is_alive:
                active_count += 1
                print(f"   ✅ {ip_str} - {hostname}")
                
                if ip_str not in existing_ips:
                    device_name = hostname if hostname != ip_str else f"Device-{ip_str.replace('.', '-')}"
                    self.db.add_device(device_name, ip_str)
                    discovered.append({
                        'ip': ip_str,
                        'hostname': hostname,
                        'name': device_name
                    })
            
            if (idx + 1) % 10 == 0:
                print(f"   Progress: {idx + 1}/{total} IPs checked...")
        
        print("=" * 50)
        print(f"✅ Scan complete!")
        print(f"   Active devices: {active_count}")
        print(f"   New devices discovered: {len(discovered)}")
        
        return discovered
    
    def continuous_discovery(self, interval=300):
        """Run auto-discovery continuously"""
        network = self.get_my_network()
        print(f"🔄 Starting continuous auto-discovery (every {interval} seconds)")
        print(f"📡 Network: {network}")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                print(f"\n⏰ Running auto-discovery at {time.strftime('%H:%M:%S')}")
                self.scan_network(network)
                print(f"\n⏳ Waiting {interval} seconds before next scan...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Auto-discovery stopped by user")

if __name__ == "__main__":
    discovery = AutoDiscovery()
    
    print("=" * 60)
    print("🌐 AUTO DISCOVERY TOOL")
    print("=" * 60)
    
    # Auto-detect network
    network = discovery.get_my_network()
    print(f"📡 Auto-detected network: {network}")
    
    discovery.scan_network(network)