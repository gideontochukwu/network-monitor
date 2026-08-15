"""
Simple User Authentication
"""

# User database (in production, use a real database)
USERS = {
    'admin': 'admin123',
    'viewer': 'viewer123'
}

def authenticate(username, password):
    """Check if username/password is valid"""
    if username in USERS and USERS[username] == password:
        return True
    return False

def add_user(username, password):
    """Add a new user (for testing)"""
    USERS[username] = password
    print(f"✅ User '{username}' added successfully!")