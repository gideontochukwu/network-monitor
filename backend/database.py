"""
Database Module
Stores network monitoring data using SQLite
"""

import sqlite3
import os
from datetime import datetime

class Database:
    def __init__(self, db_path="data/network_monitor.db"):
        """Initialize the database"""
        self.db_path = db_path
        
        # Create data folder if it doesn't exist
        os.makedirs("data", exist_ok=True)
        
        # Create tables
        self.create_tables()
        print(f"✅ Database initialized at: {db_path}")
    
    def get_connection(self):
        """Get a database connection"""
        return sqlite3.connect(self.db_path)
    
    def create_tables(self):
        """Create all necessary tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # ===== DEVICES TABLE =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # ===== PING METRICS TABLE =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ping_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                latency_ms REAL,
                status TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
        ''')
        
        # ===== METRICS TABLE (for bandwidth, packet loss) =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
        ''')
        
        # ===== SYSTEM METRICS TABLE (for CPU, Memory, Disk) =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
        ''')
        
        # ===== DNS LOGS TABLE =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # ===== ANOMALIES TABLE =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                latency_ms REAL NOT NULL,
                anomaly_score REAL NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
        ''')
        
        # ===== ALERTS TABLE =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                anomaly_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
            )
        ''')
        
        # ===== USERS TABLE =====
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Tables created successfully!")
    
    # ===== DEVICE METHODS =====
    
    def add_device(self, name, ip_address):
        """Add a new device to monitor"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO devices (name, ip_address)
            VALUES (?, ?)
        ''', (name, ip_address))
        device_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print(f"✅ Added device: {name} ({ip_address})")
        return device_id
    
    def get_all_devices(self):
        """Get all devices"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, ip_address FROM devices')
        rows = cursor.fetchall()
        conn.close()
        devices = []
        for row in rows:
            devices.append({
                'id': row[0],
                'name': row[1],
                'ip': row[2]
            })
        return devices
    
    # ===== PING METRICS METHODS =====
    
    def save_ping_result(self, device_id, latency_ms, status):
        """Save a ping result"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ping_metrics (device_id, latency_ms, status)
            VALUES (?, ?, ?)
        ''', (device_id, latency_ms, status))
        conn.commit()
        conn.close()
        print(f"   💾 Saved ping: {latency_ms}ms (Status: {status})")
    
    # ===== METRICS METHODS =====
    
    def save_metric(self, device_id, metric_type, value):
        """Save any metric (bandwidth, packet loss, etc.)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO metrics (device_id, metric_type, metric_value, timestamp)
            VALUES (?, ?, ?, datetime('now'))
        ''', (device_id, metric_type, value))
        conn.commit()
        conn.close()
        print(f"   💾 Saved {metric_type}: {value}")
    
    # ===== SYSTEM METRICS METHODS =====
    
    def save_system_metric(self, device_id, metric_type, value):
        """Save a system metric (CPU, memory, disk, etc.)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO system_metrics (device_id, metric_type, metric_value, timestamp)
            VALUES (?, ?, ?, datetime('now'))
        ''', (device_id, metric_type, value))
        conn.commit()
        conn.close()
        print(f"   💾 Saved system {metric_type}: {value}")
    
    # ===== USER METHODS =====
    
    def add_user(self, username, password_hash):
        """Add a new user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            ''', (username, password_hash))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    def get_user(self, username):
        """Get a user by username"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                'id': row[0],
                'username': row[1],
                'password_hash': row[2],
                'created_at': row[3]
            }
        return None
    
    def user_exists(self, username):
        """Check if a user exists"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    # ===== ANOMALY METHODS =====
    
    def save_anomaly(self, device_id, latency_ms, anomaly_score, timestamp=None):
        """Save an anomaly detection result"""
        conn = self.get_connection()
        cursor = conn.cursor()
        if timestamp is None:
            cursor.execute('''
                INSERT INTO anomalies (device_id, latency_ms, anomaly_score, timestamp)
                VALUES (?, ?, ?, datetime('now'))
            ''', (device_id, latency_ms, anomaly_score))
        else:
            cursor.execute('''
                INSERT INTO anomalies (device_id, latency_ms, anomaly_score, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (device_id, latency_ms, anomaly_score, timestamp))
        anomaly_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return anomaly_id
    
    def get_anomalies(self, device_id=None):
        """Get anomalies for a device or all devices"""
        conn = self.get_connection()
        cursor = conn.cursor()
        if device_id:
            cursor.execute('''
                SELECT id, latency_ms, anomaly_score, timestamp
                FROM anomalies
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT 20
            ''', (device_id,))
        else:
            cursor.execute('''
                SELECT id, device_id, latency_ms, anomaly_score, timestamp
                FROM anomalies
                ORDER BY timestamp DESC
                LIMIT 50
            ''')
        rows = cursor.fetchall()
        conn.close()
        anomalies = []
        for row in rows:
            if device_id:
                anomalies.append({
                    'id': row[0],
                    'latency_ms': row[1],
                    'anomaly_score': row[2],
                    'timestamp': row[3]
                })
            else:
                anomalies.append({
                    'id': row[0],
                    'device_id': row[1],
                    'latency_ms': row[2],
                    'anomaly_score': row[3],
                    'timestamp': row[4]
                })
        return anomalies
    
    # ===== ALERT METHODS =====
    
    def create_alert(self, anomaly_id, message, severity):
        """Create an alert for an anomaly"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (anomaly_id, message, severity)
            VALUES (?, ?, ?)
        ''', (anomaly_id, message, severity))
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return alert_id
    
    def get_active_alerts(self):
        """Get all active alerts"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT a.id, a.message, a.severity, a.created_at, a.status,
                   d.name as device_name, an.latency_ms
            FROM alerts a
            JOIN anomalies an ON a.anomaly_id = an.id
            JOIN devices d ON an.device_id = d.id
            WHERE a.status = 'active'
            ORDER BY a.created_at DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        alerts = []
        for row in rows:
            alerts.append({
                'id': row[0],
                'message': row[1],
                'severity': row[2],
                'created_at': row[3],
                'status': row[4],
                'device_name': row[5],
                'latency_ms': row[6]
            })
        return alerts
    
    def acknowledge_alert(self, alert_id):
        """Mark an alert as acknowledged"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE alerts SET status = 'acknowledged'
            WHERE id = ?
        ''', (alert_id,))
        conn.commit()
        conn.close()
    
    # ===== STATUS METHODS =====
    
    def get_latest_status(self):
        """Get the latest status for all devices"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.id, d.name, d.ip_address,
                   p.latency_ms, p.status, p.timestamp
            FROM devices d
            LEFT JOIN ping_metrics p ON d.id = p.device_id
            WHERE p.timestamp = (
                SELECT MAX(timestamp)
                FROM ping_metrics
                WHERE device_id = d.id
            )
        ''')
        rows = cursor.fetchall()
        conn.close()
        status = []
        for row in rows:
            status.append({
                'id': row[0],
                'name': row[1],
                'ip': row[2],
                'latency': row[3],
                'status': row[4],
                'timestamp': row[5]
            })
        return status

# ==================== TEST ====================

if __name__ == "__main__":
    print("=" * 50)
    print("📊 DATABASE TEST")
    print("=" * 50)
    
    db = Database()
    
    # Check if devices exist
    devices = db.get_all_devices()
    if not devices:
        print("⚠️ No devices found. Adding test devices...")
        db.add_device("Google DNS", "8.8.8.8")
        db.add_device("Cloudflare DNS", "1.1.1.1")
    
    # Show all devices
    devices = db.get_all_devices()
    print("\n📡 Devices in database:")
    for d in devices:
        print(f"   {d['name']} ({d['ip']})")
    
    print("\n✅ Database test complete!")
    print("=" * 50)