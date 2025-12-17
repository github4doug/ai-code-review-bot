"""
User Authentication Module
This file contains intentional issues for the AI Code Review Bot to catch
"""

import sqlite3
import hashlib

class UserAuth:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
    
    def login(self, username, password):
        """Authenticate user - CONTAINS SECURITY ISSUES!"""
        # SQL Injection vulnerability!
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return {"status": "success", "user": result}
        return {"status": "failed"}
    
    def register_user(self, username, password, email):
        """Register new user - CONTAINS MULTIPLE ISSUES!"""
        # No input validation
        # Storing plain text password!
        # No error handling
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        cursor = self.conn.cursor()
        cursor.execute(query)
        self.conn.commit()
        return True
    
    def hash_password(self, password):
        """Hash password using MD5 - WEAK ALGORITHM!"""
        return hashlib.md5(password.encode()).hexdigest()
    
    def get_user_data(self, user_id):
        """Fetch user data - POTENTIAL SQL INJECTION!"""
        query = f"SELECT * FROM users WHERE id={user_id}"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    
    def delete_user(self, username):
        """Delete user account - NO AUTHORIZATION CHECK!"""
        query = f"DELETE FROM users WHERE username='{username}'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        self.conn.commit()

def calculate_discount(price, user_level):
    """Calculate discount - CONTAINS BUG!"""
    discounts = {
        'bronze': 0.05,
        'silver': 0.10,
        'gold': 0.15,
        'platinum': 0.20
    }
    
    # Bug: What if user_level is not in dictionary?
    discount_rate = discounts[user_level]
    final_price = price - (price * discount_rate)
    return final_price

def process_payment(amount, currency='USD'):
    """Process payment - POOR ERROR HANDLING!"""
    # No validation of amount
    # No try-except block
    # Assumes currency is always valid
    
    conversion_rates = {
        'USD': 1.0,
        'EUR': 0.85,
        'GBP': 0.73
    }
    
    # Division by zero possible if amount is 0
    processing_fee = 2.50 / amount
    converted = amount * conversion_rates[currency]
    
    return converted + processing_fee

def send_email(to, subject, body):
    """Send email notification - INCOMPLETE IMPLEMENTATION"""
    # TODO: Actually implement email sending
    # No error handling
    # No validation of email format
    print(f"Sending email to {to}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")
    return True

# Global variable - BAD PRACTICE
user_sessions = {}

def create_session(user_id):
    """Create user session - SECURITY ISSUE!"""
    # Predictable session ID
    session_id = str(user_id) + "_session"
    user_sessions[session_id] = user_id
    return session_id

def validate_session(session_id):
    """Validate session - NO EXPIRATION!"""
    return session_id in user_sessions
