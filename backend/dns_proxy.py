"""
DNS Proxy Monitor
Intercepts DNS requests by acting as a local DNS server
Works on Windows without admin privileges (port 5353)
or with admin privileges (port 53)
"""

import socket
import threading
import sqlite3
from datetime import datetime

class DNSProxy:
    def __init__(self, db_path="data/network_monitor.db"):
        self.db_path = db_path
        self.setup_database()
        self.domain_cache = set()
    
    def setup_database(self):
        """Create DNS logs table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        print("✅ DNS logs table ready")
    
    def save_dns_log(self, domain):
        """Save DNS request to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO dns_logs (domain, timestamp)
            VALUES (?, datetime('now'))
        ''', (domain,))
        conn.commit()
        conn.close()
        print(f"💾 Saved: {domain}")
    
    def handle_dns_request(self, data, addr, sock):
        """Handle incoming DNS request"""
        print(f"📦 Received {len(data)} bytes from {addr}")
        
        try:
            # Check if it's a query
            if len(data) < 13:
                print("   ⚠️ Packet too short")
                return
            
            # Print first 20 bytes for debugging
            print(f"   📊 First 20 bytes: {data[:20].hex()}")
            
            # Check if it's a query (QR bit = 0)
            flags = data[2:4]
            if (flags[0] & 0x80) != 0:
                print("   ⚠️ Not a query (response)")
                return
            
            print("   ✅ This is a DNS query")
            
            # Extract domain from question section
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
                except Exception as e:
                    print(f"   ⚠️ Error decoding: {e}")
                    break
            
            if not domain_parts:
                print("   ⚠️ No domain found")
                return
            
            domain = '.'.join(domain_parts)
            print(f"🌐 DNS Request: {domain}")
            
            # Save to database
            if domain not in self.domain_cache:
                self.domain_cache.add(domain)
                self.save_dns_log(domain)
            
            # Forward to real DNS server (Google DNS)
            try:
                forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                forward_sock.settimeout(5)
                forward_sock.sendto(data, ('8.8.8.8', 53))
                response, _ = forward_sock.recvfrom(4096)
                forward_sock.close()
                
                # Send response back to client
                sock.sendto(response, addr)
                print(f"   ✅ Forwarded response to {addr}")
            except Exception as e:
                print(f"   ⚠️ Forward error: {e}")
                
        except Exception as e:
            print(f"⚠️ Error handling DNS: {e}")
            import traceback
            traceback.print_exc()
    
    def start_proxy(self, port=5353):
        """Start DNS proxy on specified port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('192.168.43.171', port))
            
            print(f"🔍 DNS Proxy running on port {port}")
            print(f"   To use it, set your device's DNS to: 127.0.0.1:{port}")
            print("   Press Ctrl+C to stop")
            print("=" * 50)
            
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    threading.Thread(target=self.handle_dns_request, args=(data, addr, sock)).start()
                except Exception as e:
                    print(f"⚠️ Proxy error: {e}")
        except PermissionError:
            print(f"❌ Permission denied on port {port}!")
            print(f"   Try running as Administrator, or use port 5353")
        except KeyboardInterrupt:
            print("\n🛑 DNS Proxy stopped")
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    import sys
    
    # Check if user wants a specific port
    port = 5353  # Default (no admin required)
    
    if len(sys.argv) > 1 and sys.argv[1] == "admin":
        port = 53  # Admin required
    
    proxy = DNSProxy()
    proxy.start_proxy(port)