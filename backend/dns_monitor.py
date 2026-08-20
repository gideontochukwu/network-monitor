"""
DNS Monitoring Module
Captures DNS requests using raw sockets (works on Windows without Npcap)
"""

import socket
import struct
import time
import threading
import sqlite3
from datetime import datetime

class DNSMonitor:
    def __init__(self, db_path="data/network_monitor.db"):
        self.db_path = db_path
        self.running = False
        self.setup_database()
    
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
        print("✅ DNS logs table created")
    
    def get_dns_query(self, packet):
        """Extract domain from DNS packet"""
        try:
            # Skip DNS header (12 bytes)
            offset = 12
            domain_parts = []
            while True:
                length = packet[offset]
                if length == 0:
                    break
                # Extract each part of the domain
                domain_parts.append(packet[offset+1:offset+1+length].decode('ascii'))
                offset += length + 1
            return '.'.join(domain_parts)
        except:
            return None
    
    def parse_dns_packet(self, data):
        """Parse DNS packet and extract query"""
        try:
            if len(data) < 12:
                return None
            # Get flags (bytes 2-3)
            flags = struct.unpack('!H', data[2:4])[0]
            # Check if it's a query (QR bit = 0)
            if (flags & 0x8000) != 0:
                return None
            # Extract domain from question section
            return self.get_dns_query(data)
        except:
            return None
    
    def packet_handler(self, packet, addr):
        """Process captured packet"""
        try:
            # Parse IP header (first 20 bytes)
            ip_len = (packet[0] & 0x0F) * 4
            
            # Parse UDP header (starts after IP header)
            udp_header = packet[ip_len:ip_len+8]
            if len(udp_header) < 8:
                return
            
            dst_port = struct.unpack('!H', udp_header[2:4])[0]
            src_port = struct.unpack('!H', udp_header[0:2])[0]
            
            # Check if it's DNS (port 53)
            if dst_port == 53 or src_port == 53:
                # Parse DNS data
                dns_data = packet[ip_len+8:]
                domain = self.parse_dns_packet(dns_data)
                if domain:
                    print(f"🌐 DNS Request: {domain}")
                    # Save to database
                    self.save_dns_log(domain)
        except:
            pass
    
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
    
    def start_monitoring(self):
        """Start DNS monitoring"""
        try:
            # Create raw socket for UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.bind(('0.0.0.0', 0))
            
            self.running = True
            print("🔍 Listening for DNS requests... Press Ctrl+C to stop.")
            
            while self.running:
                try:
                    packet, addr = sock.recvfrom(65535)
                    self.packet_handler(packet, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"⚠️ Packet error: {e}")
        except PermissionError:
            print("❌ Permission denied! Please run as Administrator.")
        except KeyboardInterrupt:
            print("\n🛑 DNS monitoring stopped")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            self.running = False

if __name__ == "__main__":
    monitor = DNSMonitor()
    monitor.start_monitoring()