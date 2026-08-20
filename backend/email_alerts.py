"""
Email Alert Module
Sends email notifications when anomalies are detected
"""

import yagmail
import os

class EmailAlert:
    def __init__(self, email=None, password=None):
        """
        Initialize email settings
        For Gmail, use an App Password (not your regular password)
        """
        # Use environment variables or hardcode for testing
        self.email = email or os.environ.get('EMAIL_USER', 'gideonjoshua2004@gmail.com')
        self.password = password or os.environ.get('EMAIL_PASSWORD', 'wwxd fufu rxay przd')
        self.recipient = os.environ.get('EMAIL_RECIPIENT', 'gideonjoshua2004@gmail.com')
    
    def send_alert(self, device_name, latency, timestamp):
        """
        Send an email alert for an anomaly
        """
        try:
            yag = yagmail.SMTP(self.email, self.password)
            
            subject = f"🚨 Network Anomaly Detected on {device_name}"
            
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #e74c3c;">⚠️ Network Anomaly Alert</h2>
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                    <p><strong>Device:</strong> {device_name}</p>
                    <p><strong>Latency:</strong> <span style="color: #e74c3c; font-weight: bold;">{latency}ms</span></p>
                    <p><strong>Time:</strong> {timestamp}</p>
                </div>
                
                <p style="margin-top: 20px;">This is an automated alert from your Network Monitoring System.</p>
                <p style="color: #7f8c8d; font-size: 14px;">Please check your network immediately.</p>
                
                <hr>
                <p style="color: #95a5a6; font-size: 12px;">
                    Network Monitoring System | AI-Powered Anomaly Detection
                </p>
            </body>
            </html>
            """
            
            yag.send(self.recipient, subject, body)
            print(f"📧 Email alert sent for {device_name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False

# ==================== Test ====================

if __name__ == "__main__":
    print("=" * 50)
    print("📧 EMAIL ALERT TEST")
    print("=" * 50)
    
    alert = EmailAlert()
    
    # Test with sample data
    success = alert.send_alert("Test Device", 500, "2026-07-08 14:30:00")
    
    if success:
        print("✅ Test email sent successfully!")
    else:
        print("❌ Test email failed. Please check your email settings.")