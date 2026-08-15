import sqlite3

conn = sqlite3.connect('data/network_monitor.db')
cursor = conn.cursor()

# Remove devices with these IPs
ips = ['192.168.43.152', '192.168.43.171', '192.168.43.195']

for ip in ips:
    cursor.execute('DELETE FROM devices WHERE ip_address = ?', (ip,))

conn.commit()
print(f'✅ Removed {len(ips)} devices: {", ".join(ips)}')

# Show remaining devices
cursor.execute('SELECT name, ip_address FROM devices')
remaining = cursor.fetchall()
print('\n📡 Remaining devices:')
for name, ip in remaining:
    print(f'   {name} ({ip})')

conn.close()