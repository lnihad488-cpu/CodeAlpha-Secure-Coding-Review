import sqlite3
import os
import bcrypt

# Secure approach: Sensitive data is read from environment variables
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

def secure_authenticate_user(username, provided_password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Secure approach: Using parameterized queries to prevent SQL Injection
    query = "SELECT password_hash FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_hash = result[0]
        # Secure password verification using bcrypt
        if bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash):
            return "Access Granted"
            
    return "Access Denied"