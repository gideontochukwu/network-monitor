import sqlite3

# Connect to database
conn = sqlite3.connect('data/network_monitor.db')
cursor = conn.cursor()

# Check all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

print("📊 Tables in database:")
for table in tables:
    print(f"   {table[0]}")

# Check if dns_logs exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dns_logs'")
result = cursor.fetchone()

if result:
    print("\n✅ dns_logs table exists!")
    
    # Check if there are any logs
    cursor.execute("SELECT COUNT(*) FROM dns_logs")
    count = cursor.fetchone()[0]
    print(f"   📊 DNS logs: {count} records")
    
    if count > 0:
        cursor.execute("SELECT domain, timestamp FROM dns_logs ORDER BY timestamp DESC LIMIT 5")
        rows = cursor.fetchall()
        print("\n📊 Recent DNS Requests:")
        for row in rows:
            print(f"   🌐 {row[0]} at {row[1]}")
else:
    print("\n❌ dns_logs table does NOT exist!")
    
    # Create the table
    cursor.execute('''
        CREATE TABLE dns_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    print("✅ dns_logs table created!")

conn.close()