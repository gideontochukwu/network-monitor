"""
Anomaly Detection Module
Uses Isolation Forest to detect unusual network patterns
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import sqlite3
import pickle
import os

class AnomalyDetector:
    def __init__(self, db_path="data/network_monitor.db"):
        self.db_path = db_path
        self.model = None
    
    def get_training_data(self, device_id=1, hours=24):
        """Get historical ping data for training"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT latency_ms, timestamp
            FROM ping_metrics
            WHERE device_id = ? AND status = 'success'
            AND timestamp >= datetime('now', ?)
            ORDER BY timestamp ASC
        ''', (device_id, f'-{hours} hours'))
        
        rows = cursor.fetchall()
        conn.close()
        
        if len(rows) < 10:
            return None
        
        data = []
        for row in rows:
            if row[0] is not None:
                data.append([row[0]])
        return np.array(data)
    
    def train_model(self, device_id=1):
        """Train the Isolation Forest model"""
        print("🧠 Training anomaly detection model...")
        
        X = self.get_training_data(device_id)
        if X is None or len(X) < 10:
            print("❌ Not enough data to train. Need at least 10 ping records.")
            return False
        
        print(f"   Training on {len(X)} data points...")
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(X)
        print("✅ Model trained successfully!")
        return True
    
    def detect_anomalies(self, device_id=None, hours=1):
        """Detect anomalies in recent data"""
        # If model is not trained, return empty (don't auto-train)
        if self.model is None:
            print("⚠️ Model not trained. Please run train_model() first.")
            return []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if device_id is None:
            cursor.execute('''
                SELECT DISTINCT device_id FROM ping_metrics
                WHERE status = 'success'
                AND timestamp >= datetime('now', ?)
            ''', (f'-{hours} hours',))
            device_ids = [row[0] for row in cursor.fetchall()]
        else:
            device_ids = [device_id]
        
        all_anomalies = []
        
        for dev_id in device_ids:
            cursor.execute('''
                SELECT id, latency_ms, timestamp
                FROM ping_metrics
                WHERE device_id = ? AND status = 'success'
                AND timestamp >= datetime('now', ?)
                ORDER BY timestamp ASC
            ''', (dev_id, f'-{hours} hours'))
            
            rows = cursor.fetchall()
            if len(rows) < 3:
                continue
            
            X = np.array([[row[1]] for row in rows if row[1] is not None])
            if len(X) < 3:
                continue
            
            predictions = self.model.predict(X)
            
            for i, pred in enumerate(predictions):
                if pred == -1:
                    all_anomalies.append({
                        'device_id': dev_id,
                        'id': rows[i][0],
                        'latency': rows[i][1],
                        'timestamp': rows[i][2]
                    })
        
        conn.close()
        return all_anomalies
    
    def run_detection(self):
        """Run full detection cycle (train if needed, then detect)"""
        print("🔍 Running anomaly detection...")
        
        # Train model if not trained
        if self.model is None:
            print("⚠️ Model not trained. Training now...")
            self.train_model()
            if self.model is None:
                return []
        
        # Detect anomalies
        anomalies = self.detect_anomalies(device_id=None)
        
        if anomalies:
            print(f"⚠️ Found {len(anomalies)} anomalies!")
            for a in anomalies:
                print(f"   🔴 {a['latency']}ms at {a['timestamp']}")
        else:
            print("✅ No anomalies detected.")
        
        return anomalies

if __name__ == "__main__":
    print("=" * 50)
    print("🤖 ANOMALY DETECTION TEST")
    print("=" * 50)
    
    detector = AnomalyDetector()
    
    # Train the model
    detector.train_model()
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(device_id=None)
    
    print("\n📊 Results:")
    if anomalies:
        print(f"   🔴 {len(anomalies)} anomalies found")
        for a in anomalies:
            print(f"      Device {a['device_id']}: {a['latency']}ms")
    else:
        print("   ✅ No anomalies found")