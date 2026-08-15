"""
Network Monitoring System - Main Flask Application
Serves the dashboard and API endpoints
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import sqlite3
import os
import sys
import secrets
import hashlib

# Add the backend folder to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database import Database
from anomaly_detector import AnomalyDetector

# ==================== App Setup ====================

app = Flask(__name__, 
            template_folder='../frontend',
            static_folder='../frontend')

# Secret key for session management (required for login)
app.secret_key = secrets.token_hex(16)

db = Database()

# ==================== Authentication ====================

# Simple user database (fallback if no database)
USERS = {
    'admin': 'admin123',
    'viewer': 'viewer123'
}

def authenticate(username, password):
    """Check if username/password is valid"""
    # First check database
    user = db.get_user(username)
    if user:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash == user['password_hash']:
            return True
    
    # Fallback to hardcoded users
    if username in USERS and USERS[username] == password:
        return True
    return False

# ==================== Page Routes ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    signup_success = request.args.get('signup_success')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if authenticate(username, password):
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html', success=signup_success)

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    """Serve the main dashboard page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/devices')
def devices_page():
    """Devices management page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('devices.html')

@app.route('/alerts')
def alerts_page():
    """Alerts page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('alerts.html')

@app.route('/analytics')
def analytics_page():
    """Analytics page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('analytics.html')

@app.route('/settings')
def settings_page():
    """Settings page"""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign up page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            return render_template('signup.html', error='Username and password are required')
        
        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match')
        
        if len(password) < 4:
            return render_template('signup.html', error='Password must be at least 4 characters')
        
        # Check if user already exists
        if db.user_exists(username):
            return render_template('signup.html', error='Username already taken')
        
        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Add user to database
        user_id = db.add_user(username, password_hash)
        
        if user_id:
            return redirect(url_for('login', signup_success='Account created! Please login.'))
        else:
            return render_template('signup.html', error='Something went wrong. Please try again.')
    
    return render_template('signup.html')

# ==================== API Routes ====================

@app.route('/api/ping-data')
def get_ping_data():
    """Get ping data for charts"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Get the first available device ID
    cursor.execute('SELECT id FROM devices LIMIT 1')
    device_row = cursor.fetchone()
    
    if not device_row:
        conn.close()
        return jsonify([])
    
    device_id = device_row[0]
    
    cursor.execute('''
        SELECT latency_ms, status, timestamp 
        FROM ping_metrics 
        WHERE device_id = ?
        ORDER BY timestamp DESC 
        LIMIT 20
    ''', (device_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    data = []
    for row in rows:
        data.append({
            'latency': row[0],
            'status': row[1],
            'timestamp': row[2]
        })
    
    return jsonify(data)

@app.route('/api/devices')
def get_devices():
    """Get all monitored devices"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    devices = db.get_all_devices()
    return jsonify(devices)

@app.route('/api/status')
def get_status():
    """Get overall network status"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT d.name, d.ip_address, p.latency_ms, p.status, p.timestamp
        FROM ping_metrics p
        JOIN devices d ON p.device_id = d.id
        WHERE p.id IN (
            SELECT MAX(id) 
            FROM ping_metrics 
            GROUP BY device_id
        )
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    status = []
    for row in rows:
        status.append({
            'device': row[0],
            'ip': row[1],
            'latency': row[2],
            'status': row[3],
            'timestamp': row[4]
        })
    
    return jsonify(status)

@app.route('/api/alerts')
def get_alerts():
    """Get all alerts"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT a.id, a.message, a.severity, a.status, a.created_at,
               d.name as device_name
        FROM alerts a
        JOIN anomalies an ON a.anomaly_id = an.id
        JOIN devices d ON an.device_id = d.id
        ORDER BY a.created_at DESC
        LIMIT 50
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    alerts = []
    for row in rows:
        alerts.append({
            'id': row[0],
            'message': row[1],
            'severity': row[2],
            'status': row[3],
            'created_at': row[4],
            'device_name': row[5]
        })
    
    return jsonify(alerts)

@app.route('/api/anomalies')
def get_anomalies():
    """Get recent anomalies for all devices"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    detector = AnomalyDetector()
    
    anomalies = detector.detect_anomalies(device_id=None)
    
    if anomalies:
        conn = db.get_connection()
        cursor = conn.cursor()
        for anomaly in anomalies:
            cursor.execute('SELECT name FROM devices WHERE id = ?', (anomaly['device_id'],))
            row = cursor.fetchone()
            anomaly['device_name'] = row[0] if row else f"Device {anomaly['device_id']}"
        conn.close()
    
    return jsonify(anomalies)

@app.route('/api/system-metrics')
def get_system_metrics():
    """Get system metrics (CPU, Memory, Disk)"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Latest values
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "cpu" ORDER BY timestamp DESC LIMIT 1')
    cpu_row = cursor.fetchone()
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "memory" ORDER BY timestamp DESC LIMIT 1')
    mem_row = cursor.fetchone()
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "disk" ORDER BY timestamp DESC LIMIT 1')
    disk_row = cursor.fetchone()
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "uptime" ORDER BY timestamp DESC LIMIT 1')
    uptime_row = cursor.fetchone()
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "processes" ORDER BY timestamp DESC LIMIT 1')
    proc_row = cursor.fetchone()
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "net_sent" ORDER BY timestamp DESC LIMIT 1')
    net_sent_row = cursor.fetchone()
    cursor.execute('SELECT metric_value FROM system_metrics WHERE metric_type = "net_recv" ORDER BY timestamp DESC LIMIT 1')
    net_recv_row = cursor.fetchone()
    
    # Histories
    cursor.execute('SELECT metric_value, timestamp FROM system_metrics WHERE metric_type = "cpu" ORDER BY timestamp DESC LIMIT 20')
    cpu_hist = cursor.fetchall()
    cursor.execute('SELECT metric_value, timestamp FROM system_metrics WHERE metric_type = "memory" ORDER BY timestamp DESC LIMIT 20')
    mem_hist = cursor.fetchall()
    cursor.execute('SELECT metric_value, timestamp FROM system_metrics WHERE metric_type = "disk" ORDER BY timestamp DESC LIMIT 20')
    disk_hist = cursor.fetchall()
    cursor.execute('SELECT metric_value, timestamp FROM system_metrics WHERE metric_type = "net_sent" ORDER BY timestamp DESC LIMIT 20')
    net_sent_hist = cursor.fetchall()
    cursor.execute('SELECT metric_value, timestamp FROM system_metrics WHERE metric_type = "net_recv" ORDER BY timestamp DESC LIMIT 20')
    net_recv_hist = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'cpu': cpu_row[0] if cpu_row else None,
        'memory': mem_row[0] if mem_row else None,
        'disk': disk_row[0] if disk_row else None,
        'uptime': uptime_row[0] if uptime_row else None,
        'processes': proc_row[0] if proc_row else None,
        'net_sent': net_sent_row[0] if net_sent_row else None,
        'net_recv': net_recv_row[0] if net_recv_row else None,
        'cpu_history': [{'value': row[0], 'timestamp': row[1]} for row in cpu_hist[::-1]],
        'memory_history': [{'value': row[0], 'timestamp': row[1]} for row in mem_hist[::-1]],
        'disk_history': [{'value': row[0], 'timestamp': row[1]} for row in disk_hist[::-1]],
        'net_sent_history': [{'value': row[0], 'timestamp': row[1]} for row in net_sent_hist[::-1]],
        'net_recv_history': [{'value': row[0], 'timestamp': row[1]} for row in net_recv_hist[::-1]]
    })

# ==================== Auto Discovery Route ====================

@app.route('/api/discover')
def discover_devices():
    """Auto-discover new devices (auto-detects network)"""
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        from discovery import AutoDiscovery
        discovery = AutoDiscovery()
        discovered = discovery.scan_network(timeout=0.5)
        return jsonify({
            'success': True,
            'discovered': discovered,
            'count': len(discovered),
            'network': discovery.get_my_network()
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== Main ====================

if __name__ == '__main__':
    # Render uses PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    print("=" * 60)
    print("🌐 NETWORK MONITORING SYSTEM WITH AI")
    print("=" * 60)
    print(f"📊 Dashboard: http://localhost:{port}")
    print("=" * 60)
    app.run(debug=False, host='0.0.0.0', port=port)