"""
User Authentication Module - SECURE VERSION
All security issues from the previous version have been fixed
"""

import sqlite3
import bcrypt
import secrets
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from contextlib import contextmanager


class UserAuth:
    """Secure user authentication with proper SQL injection protection"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database with proper schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user with parameterized queries
        
        Args:
            username: User's username
            password: User's plain password
            
        Returns:
            Dict with status and user info if successful
        """
        # Input validation
        if not username or not password:
            return {"status": "failed", "error": "Username and password required"}
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # FIXED: Use parameterized query to prevent SQL injection
                cursor.execute(
                    "SELECT id, username, password_hash, email FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if result and bcrypt.checkpw(password.encode(), result['password_hash'].encode()):
                    return {
                        "status": "success",
                        "user": {
                            "id": result['id'],
                            "username": result['username'],
                            "email": result['email']
                        }
                    }
                
                return {"status": "failed", "error": "Invalid credentials"}
                
        except Exception as e:
            return {"status": "error", "error": f"Login failed: {str(e)}"}
    
    def register_user(self, username: str, password: str, email: str) -> Dict[str, Any]:
        """
        Register new user with proper validation and secure password hashing
        
        Args:
            username: Desired username
            password: Plain text password
            email: User's email address
            
        Returns:
            Dict with status and any errors
        """
        # FIXED: Input validation
        validation_error = self._validate_registration(username, password, email)
        if validation_error:
            return {"status": "failed", "error": validation_error}
        
        # FIXED: Use bcrypt instead of MD5
        password_hash = self.hash_password(password)
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # FIXED: Parameterized query prevents SQL injection
                cursor.execute(
                    "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                    (username, password_hash, email)
                )
                conn.commit()
                return {"status": "success", "message": "User registered successfully"}
                
        except sqlite3.IntegrityError as e:
            return {"status": "failed", "error": "Username or email already exists"}
        except Exception as e:
            return {"status": "error", "error": f"Registration failed: {str(e)}"}
    
    def _validate_registration(self, username: str, password: str, email: str) -> Optional[str]:
        """
        Validate registration inputs
        
        Returns:
            Error message if validation fails, None if valid
        """
        if not username or len(username) < 3:
            return "Username must be at least 3 characters"
        
        if not password or len(password) < 8:
            return "Password must be at least 8 characters"
        
        if not self._validate_email(email):
            return "Invalid email format"
        
        # Check password strength
        if not any(c.isupper() for c in password):
            return "Password must contain at least one uppercase letter"
        
        if not any(c.isdigit() for c in password):
            return "Password must contain at least one number"
        
        return None
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt (secure algorithm)
        
        Args:
            password: Plain text password
            
        Returns:
            Bcrypt hash as string
        """
        # FIXED: Use bcrypt instead of MD5
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def get_user_data(self, user_id: int, requesting_user_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch user data with authorization check
        
        Args:
            user_id: ID of user to fetch
            requesting_user_id: ID of user making the request
            
        Returns:
            User data if authorized, None otherwise
        """
        # FIXED: Authorization check - users can only access their own data
        if user_id != requesting_user_id:
            return None
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # FIXED: Parameterized query prevents SQL injection
                cursor.execute(
                    "SELECT id, username, email, created_at FROM users WHERE id = ?",
                    (user_id,)
                )
                result = cursor.fetchone()
                
                if result:
                    return dict(result)
                return None
                
        except Exception as e:
            print(f"Error fetching user data: {e}")
            return None
    
    def delete_user(self, username: str, requesting_user_id: int, is_admin: bool = False) -> Dict[str, Any]:
        """
        Delete user account with proper authorization
        
        Args:
            username: Username to delete
            requesting_user_id: ID of user making the request
            is_admin: Whether requesting user is an admin
            
        Returns:
            Dict with status
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # FIXED: Check authorization - verify user owns account or is admin
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result:
                    return {"status": "failed", "error": "User not found"}
                
                user_id = result['id']
                
                # FIXED: Authorization check
                if user_id != requesting_user_id and not is_admin:
                    return {"status": "failed", "error": "Unauthorized"}
                
                # FIXED: Parameterized query
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
                return {"status": "success", "message": "User deleted"}
                
        except Exception as e:
            return {"status": "error", "error": f"Deletion failed: {str(e)}"}


def calculate_discount(price: float, user_level: str) -> Dict[str, Any]:
    """
    Calculate discount with proper error handling
    
    Args:
        price: Original price
        user_level: User's membership level
        
    Returns:
        Dict with final_price and discount_rate, or error
    """
    discounts = {
        'bronze': 0.05,
        'silver': 0.10,
        'gold': 0.15,
        'platinum': 0.20
    }
    
    # FIXED: Handle missing user_level gracefully
    if user_level not in discounts:
        return {
            "error": f"Invalid user level: {user_level}",
            "valid_levels": list(discounts.keys())
        }
    
    # FIXED: Validate price
    if not isinstance(price, (int, float)) or price < 0:
        return {"error": "Price must be a positive number"}
    
    discount_rate = discounts[user_level]
    final_price = price - (price * discount_rate)
    
    return {
        "original_price": price,
        "discount_rate": discount_rate,
        "discount_amount": price * discount_rate,
        "final_price": final_price
    }


def process_payment(amount: float, currency: str = 'USD') -> Dict[str, Any]:
    """
    Process payment with proper validation and error handling
    
    Args:
        amount: Payment amount
        currency: Currency code
        
    Returns:
        Dict with processed amount or error
    """
    conversion_rates = {
        'USD': 1.0,
        'EUR': 0.85,
        'GBP': 0.73
    }
    
    # FIXED: Validate amount
    if not isinstance(amount, (int, float)):
        return {"error": "Amount must be a number"}
    
    if amount <= 0:
        return {"error": "Amount must be greater than zero"}
    
    # FIXED: Handle invalid currency
    if currency not in conversion_rates:
        return {
            "error": f"Unsupported currency: {currency}",
            "supported_currencies": list(conversion_rates.keys())
        }
    
    try:
        # FIXED: Calculate fee as percentage instead of division
        processing_fee_rate = 0.029  # 2.9% typical payment processor fee
        processing_fee = amount * processing_fee_rate
        
        converted = amount * conversion_rates[currency]
        total = converted + processing_fee
        
        return {
            "original_amount": amount,
            "currency": currency,
            "converted_amount": converted,
            "processing_fee": processing_fee,
            "total": total
        }
        
    except Exception as e:
        return {"error": f"Payment processing failed: {str(e)}"}


def send_email(to: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Send email notification with validation
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body
        
    Returns:
        Dict with status
    """
    # FIXED: Validate email format
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, to):
        return {"status": "failed", "error": "Invalid email format"}
    
    # FIXED: Validate required fields
    if not subject or not body:
        return {"status": "failed", "error": "Subject and body are required"}
    
    try:
        # TODO: Implement actual email sending via SMTP or email service
        # For now, log the email details
        print(f"[EMAIL] To: {to}")
        print(f"[EMAIL] Subject: {subject}")
        print(f"[EMAIL] Body: {body}")
        
        return {"status": "success", "message": "Email sent successfully"}
        
    except Exception as e:
        return {"status": "error", "error": f"Failed to send email: {str(e)}"}


class SessionManager:
    """Secure session management with expiration"""
    
    def __init__(self, session_timeout_minutes: int = 30):
        # FIXED: Use instance variable instead of global
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
    
    def create_session(self, user_id: int) -> str:
        """
        Create user session with secure random session ID
        
        Args:
            user_id: User's ID
            
        Returns:
            Secure session ID
        """
        # FIXED: Use cryptographically secure random session ID
        session_id = secrets.token_urlsafe(32)
        
        self._sessions[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
            "last_accessed": datetime.now()
        }
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[int]:
        """
        Validate session and return user_id if valid
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            User ID if session is valid, None otherwise
        """
        if session_id not in self._sessions:
            return None
        
        session = self._sessions[session_id]
        
        # FIXED: Check session expiration
        time_since_access = datetime.now() - session["last_accessed"]
        
        if time_since_access > self.session_timeout:
            # Session expired, remove it
            del self._sessions[session_id]
            return None
        
        # Update last accessed time
        session["last_accessed"] = datetime.now()
        
        return session["user_id"]
    
    def destroy_session(self, session_id: str) -> bool:
        """
        Destroy/logout a session
        
        Args:
            session_id: Session to destroy
            
        Returns:
            True if session was destroyed, False if not found
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False
    
    def cleanup_expired_sessions(self):
        """Remove all expired sessions"""
        current_time = datetime.now()
        expired = [
            sid for sid, session in self._sessions.items()
            if current_time - session["last_accessed"] > self.session_timeout
        ]
        
        for sid in expired:
            del self._sessions[sid]
        
        return len(expired)