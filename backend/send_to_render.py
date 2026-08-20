"""
Send data from local collector to Render cloud
"""

import subprocess
import time
import requests
import psutil
import socket
import json
import struct
import threading

# ==================== CONFIGURATION ====================

# REPLACE THIS WITH YOUR RENDER URL
RENDER_URL = "https://network-monitor-9mob.onrender.com/api/ingest"
DNS_INGEST_URL = "https://network-monitor-9mob.onrender.com/api/dns-ingest"

# ==================== NETWORK FUNCTIONS ====================

def get_local_ip():
    """Get the local IP address"""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return "127.0.0.1"

def ping_host(host):
    """Ping a host and return response time"""
    try:
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '1000', host],
            capture_output=True,
            text=True,
            timeout=5
        )
        if "time=" in result.stdout:
            for part in result.stdout.split():
                if "time=" in part:
                    time_str = part.split("=")[1].replace("ms", "")
                    return float(time_str), "success"
        return None, "failed"
    except:
        return None, "timeout"

# ==================== SYSTEM METRICS ====================

def get_system_metrics():
    """Get system metrics"""
    try:
        return {
            'cpu': psutil.cpu_percent(interval=1),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent,
        }
    except:
        return {}

# ==================== SEND TO RENDER ====================

def send_to_cloud(device_name, ip, latency, status, system_metrics):
    """Send data to Render cloud"""
    data = {
        'device_name': device_name,
        'ip': ip,
        'metrics': {
            'latency': latency,
            'status': status,
            'cpu': system_metrics.get('cpu'),
            'memory': system_metrics.get('memory'),
            'disk': system_metrics.get('disk'),
        }
    }
    
    try:
        response = requests.post(
            RENDER_URL,
            json=data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        if response.status_code == 200:
            print(f"✅ Data sent to cloud for {device_name}")
        else:
            print(f"❌ Failed to send data: {response.status_code}")
    except Exception as e:
        print(f"❌ Error sending data: {e}")

# ==================== DNS FUNCTIONS ====================

def extract_domain(data):
    """Extract domain from DNS query"""
    try:
        if len(data) < 13:
            return None
        offset = 12
        domain_parts = []
        while True:
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0:
                break
            try:
                domain_parts.append(data[offset+1:offset+1+length].decode('ascii'))
                offset += length + 1
            except:
                break
        if domain_parts:
            return '.'.join(domain_parts)
    except:
        pass
    return None

def capture_dns_requests():
    """Capture DNS requests on the local network"""
    try:
        # Create a raw socket to capture DNS requests
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.bind(('0.0.0.0', 0))
        sock.settimeout(2)
        
        try:
            packet, addr = sock.recvfrom(65535)
            # Parse DNS request
            ip_header = packet[:20]
            ip_len = (ip_header[0] & 0x0F) * 4
            udp_header = packet[ip_len:ip_len+8]
            dst_port = struct.unpack('!H', udp_header[2:4])[0]
            
            if dst_port == 53 or dst_port == 5353:
                dns_data = packet[ip_len+8:]
                domain = extract_domain(dns_data)
                if domain:
                    return domain
        except socket.timeout:
            pass
    except:
        pass
    return None

def send_dns_to_cloud(domain):
    """Send DNS request to Render cloud"""
    if not domain:
        return
    
    data = {
        'domain': domain,
        'timestamp': time.time()
    }
    
    try:
        response = requests.post(
            DNS_INGEST_URL,
            json=data,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code == 200:
            print(f"🌐 DNS: {domain}")
    except:
        pass

# ==================== DNS MONITORING THREAD ====================

def dns_monitor_thread():
    """Background thread for DNS monitoring"""
    print("🌐 Starting DNS monitoring thread...")
    while True:
        domain = capture_dns_requests()
        if domain:
            send_dns_to_cloud(domain)
        time.sleep(0.5)

# ==================== MAIN LOOP ====================

def main():
    """Main loop"""
    print("🚀 Starting Hybrid Data Sender")
    print(f"📡 Sending data to: {RENDER_URL}")
    print("=" * 50)
    
    # Check internet connection
    print("🌐 Checking internet connection...")
    try:
        response = requests.get("https://render.com", timeout=5)
        print("✅ Internet connection OK")
    except:
        print("❌ No internet connection!")
        return
    
    # Start DNS monitoring in background
    dns_thread = threading.Thread(target=dns_monitor_thread, daemon=True)
    dns_thread.start()
    
    # Devices to monitor
    devices_to_monitor = [
        {"name": "Google DNS", "ip": "8.8.8.8"},
        {"name": "Cloudflare DNS", "ip": "1.1.1.1"},
        {"name": "OpenDNS", "ip": "208.67.222.222"},
        {"name": "Quad9 DNS", "ip": "9.9.9.9"},
        {"name": "My PC", "ip": get_local_ip()},
        {"name": "My Phone", "ip": "10.189.109.91"},  # Replace with your phone's IP
        {"name": "My Router", "ip": "192.168.43.1"},   # Replace with your router's IP
    ]
    
    print(f"\n📡 Monitoring {len(devices_to_monitor)} devices")
    print("=" * 50)
    
    try:
        while True:
            for device in devices_to_monitor:
                name = device['name']
                ip = device['ip']
                
                # Ping the device
                latency, status = ping_host(ip)
                
                # Get system metrics (only for local PC)
                system_metrics = get_system_metrics() if ip == get_local_ip() else {}
                
                if latency is not None:
                    print(f"✅ {name} ({ip}): {latency}ms")
                else:
                    print(f"❌ {name} ({ip}): {status}")
                
                # Send to cloud
                send_to_cloud(name, ip, latency, status, system_metrics)
                
                time.sleep(5)  # Wait between devices
            
            print(f"\n⏳ Waiting 30 seconds before next round...\n")
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user")

if __name__ == "__main__":
    main()