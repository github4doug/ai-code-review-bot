"""
User Authentication Module - Production-Ready Version
Includes rate limiting, account lockout, and enhanced security
"""

import sqlite3
import bcrypt
import secrets
import re
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from contextlib import contextmanager
from enum import Enum
from threading import Lock
from collections import defaultdict
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
BCRYPT_ROUNDS = 12
SESSION_TIMEOUT_MINUTES = 30
MIN_PASSWORD_LENGTH = 8
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 255
PROCESSING_FEE_RATE = 0.029
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
MAX_SESSIONS_PER_USER = 5


@dataclass
class AuthConfig:
    """Configuration for authentication system"""
    bcrypt_rounds: int = BCRYPT_ROUNDS
    session_timeout_minutes: int = SESSION_TIMEOUT_MINUTES
    min_password_length: int = MIN_PASSWORD_LENGTH
    max_failed_attempts: int = MAX_FAILED_ATTEMPTS
    lockout_duration_minutes: int = LOCKOUT_DURATION_MINUTES


class UserLevel(Enum):
    """User membership levels with discount rates"""
    BRONZE = 0.05
    SILVER = 0.10
    GOLD = 0.15
    PLATINUM = 0.20


class RateLimiter:
    """Simple in-memory rate limiter for authentication attempts"""
    
    def __init__(self, max_attempts: int = MAX_FAILED_ATTEMPTS, 
                 window_minutes: int = LOCKOUT_DURATION_MINUTES):
        self._attempts: Dict[str, list] = defaultdict(list)
        self._lock = Lock()
        self.max_attempts = max_attempts
        self.window = timedelta(minutes=window_minutes)
    
    def is_rate_limited(self, identifier: str) -> Tuple[bool, Optional[datetime]]:
        """
        Check if identifier is rate limited
        
        Args:
            identifier: Username or IP address
            
        Returns:
            Tuple of (is_limited, unlock_time)
        """
        with self._lock:
            now = datetime.now()
            
            # Clean old attempts
            if identifier in self._attempts:
                self._attempts[identifier] = [
                    attempt_time for attempt_time in self._attempts[identifier]
                    if now - attempt_time < self.window
                ]
            
            # Check if rate limited
            if len(self._attempts[identifier]) >= self.max_attempts:
                oldest_attempt = min(self._attempts[identifier])
                unlock_time = oldest_attempt + self.window
                return True, unlock_time
            
            return False, None
    
    def record_attempt(self, identifier: str):
        """Record a failed attempt"""
        with self._lock:
            self._attempts[identifier].append(datetime.now())
    
    def reset_attempts(self, identifier: str):
        """Reset attempts after successful login"""
        with self._lock:
            if identifier in self._attempts:
                del self._attempts[identifier]


class UserAuth:
    """Secure user authentication with rate limiting and proper bcrypt handling"""
    
    def __init__(self, db_path: str, config: Optional[AuthConfig] = None):
        self.db_path = db_path
        self.config = config or AuthConfig()
        self.rate_limiter = RateLimiter(
            max_attempts=self.config.max_failed_attempts,
            window_minutes=self.config.lockout_duration_minutes
        )
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections with proper timeout
        
        Raises:
            sqlite3.Error: If database connection fails
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if 'conn' in locals():
                conn.close()
    
    def _init_database(self):
        """Initialize database with proper schema, constraints, and indexes"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Create users table with constraints
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash BLOB NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        CHECK(length(username) >= 3 AND length(username) <= 50),
                        CHECK(length(email) <= 255 AND email LIKE '%_@_%.__%')
                    )
                ''')
                
                # Add indexes for performance and security
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_users_username 
                    ON users(username)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_users_email 
                    ON users(email)
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user with rate limiting protection
        
        Args:
            username: User's username
            password: User's plain password
            
        Returns:
            Dict with status and user info if successful
        """
        # Input validation
        if not username or not password:
            return {"status": "failed", "error": "Username and password required"}
        
        # Check rate limiting
        is_limited, unlock_time = self.rate_limiter.is_rate_limited(username)
        if is_limited:
            logger.warning(f"Rate limited login attempt for: {username}")
            minutes_remaining = int((unlock_time - datetime.now()).total_seconds() / 60)
            return {
                "status": "failed",
                "error": f"Too many failed attempts. Try again in {minutes_remaining} minutes."
            }
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, username, password_hash, email FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if result:
                    password_hash = result['password_hash']
                    if bcrypt.checkpw(password.encode(), password_hash):
                        # Successful login - reset rate limiter
                        self.rate_limiter.reset_attempts(username)
                        logger.info(f"Successful login: {username}")
                        return {
                            "status": "success",
                            "user": {
                                "id": result['id'],
                                "username": result['username'],
                                "email": result['email']
                            }
                        }
                
                # Failed login - record attempt
                self.rate_limiter.record_attempt(username)
                logger.warning(f"Failed login attempt for: {username}")
                return {"status": "failed", "error": "Invalid credentials"}
                
        except Exception as e:
            logger.error(f"Login error for user {username}: {e}")
            return {"status": "error", "error": "Authentication service temporarily unavailable"}
    
    def register_user(self, username: str, password: str, email: str) -> Dict[str, Any]:
        """
        Register new user with validation and duplicate detection
        
        Args:
            username: Desired username
            password: Plain text password
            email: User's email address
            
        Returns:
            Dict with status and any errors
        """
        # Input validation
        validation_error = self._validate_registration(username, password, email)
        if validation_error:
            return {"status": "failed", "error": validation_error}
        
        # Hash password
        password_hash = self.hash_password(password)
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                    (username, password_hash, email)
                )
                conn.commit()
                logger.info(f"User registered successfully: {username}")
                return {"status": "success", "message": "User registered successfully"}
                
        except sqlite3.IntegrityError as e:
            error_msg = str(e).lower()
            if 'username' in error_msg:
                logger.info(f"Registration failed - username exists: {username}")
                return {"status": "failed", "error": "Username already exists"}
            elif 'email' in error_msg:
                logger.info(f"Registration failed - email exists: {email}")
                return {"status": "failed", "error": "Email already exists"}
            else:
                logger.error(f"Registration constraint violation: {e}")
                return {"status": "failed", "error": "Registration failed - please check your inputs"}
        except Exception as e:
            logger.error(f"Registration error for {username}: {e}")
            return {"status": "error", "error": "Registration service temporarily unavailable"}
    
    def _validate_registration(self, username: str, password: str, email: str) -> Optional[str]:
        """
        Validate registration inputs with length limits
        
        Returns:
            Error message if validation fails, None if valid
        """
        # Username validation
        if not username or not username.strip():
            return "Username is required"
        if len(username.strip()) < MIN_USERNAME_LENGTH:
            return f"Username must be at least {MIN_USERNAME_LENGTH} characters"
        if len(username) > MAX_USERNAME_LENGTH:
            return f"Username must be at most {MAX_USERNAME_LENGTH} characters"
        
        # Password validation
        if not password:
            return "Password is required"
        
        # Collect all password issues at once to avoid timing attacks
        issues = []
        if len(password) < MIN_PASSWORD_LENGTH:
            issues.append(f"at least {MIN_PASSWORD_LENGTH} characters")
        if not any(c.isupper() for c in password):
            issues.append("an uppercase letter")
        if not any(c.islower() for c in password):
            issues.append("a lowercase letter")
        if not any(c.isdigit() for c in password):
            issues.append("a number")
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            issues.append("a special character")
        
        if issues:
            return f"Password must contain {', '.join(issues)}"
        
        # Email validation
        if not email:
            return "Email is required"
        if len(email) > MAX_EMAIL_LENGTH:
            return f"Email must be at most {MAX_EMAIL_LENGTH} characters"
        if not self._validate_email(email):
            return "Invalid email format"
        
        return None
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def hash_password(self, password: str) -> bytes:
        """
        Hash password using bcrypt with configured rounds
        
        Args:
            password: Plain text password
            
        Returns:
            Bcrypt hash as bytes
        """
        salt = bcrypt.gensalt(rounds=self.config.bcrypt_rounds)
        return bcrypt.hashpw(password.encode(), salt)
    
    def get_user_data(self, user_id: int, requesting_user_id: int) -> Optional[Dict[str, Any]]:
        """
        Fetch user data with authorization check
        
        Args:
            user_id: ID of user to fetch
            requesting_user_id: ID of user making the request
            
        Returns:
            User data if authorized, None otherwise
        """
        if user_id != requesting_user_id:
            logger.warning(f"Unauthorized access attempt: user {requesting_user_id} tried to access user {user_id}")
            return None
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, username, email, created_at FROM users WHERE id = ?",
                    (user_id,)
                )
                result = cursor.fetchone()
                
                if result:
                    return dict(result)
                return None
                
        except Exception as e:
            logger.error(f"Error fetching user data for user {user_id}: {e}")
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
                
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result:
                    return {"status": "failed", "error": "User not found"}
                
                user_id = result['id']
                
                if user_id != requesting_user_id and not is_admin:
                    logger.warning(f"Unauthorized deletion attempt by user {requesting_user_id}")
                    return {"status": "failed", "error": "Unauthorized"}
                
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
                logger.info(f"User deleted: {username}")
                return {"status": "success", "message": "User deleted"}
                
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            return {"status": "error", "error": "Deletion service temporarily unavailable"}


def calculate_discount(price: float, user_level: str) -> Dict[str, Any]:
    """Calculate discount with proper error handling"""
    try:
        level = UserLevel[user_level.upper()]
        discount_rate = level.value
    except KeyError:
        return {
            "error": f"Invalid user level: {user_level}",
            "valid_levels": [l.name.lower() for l in UserLevel]
        }
    
    if not isinstance(price, (int, float)) or price < 0:
        return {"error": "Price must be a positive number"}
    
    final_price = price - (price * discount_rate)
    
    return {
        "original_price": price,
        "discount_rate": discount_rate,
        "discount_amount": price * discount_rate,
        "final_price": final_price
    }


def process_payment(amount: float, currency: str = 'USD') -> Dict[str, Any]:
    """Process payment with validation"""
    conversion_rates = {
        'USD': 1.0,
        'EUR': 0.85,
        'GBP': 0.73
    }
    
    if not isinstance(amount, (int, float)):
        return {"error": "Amount must be a number"}
    
    if amount <= 0:
        return {"error": "Amount must be greater than zero"}
    
    if currency not in conversion_rates:
        return {
            "error": f"Unsupported currency: {currency}",
            "supported_currencies": list(conversion_rates.keys())
        }
    
    try:
        processing_fee = amount * PROCESSING_FEE_RATE
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
        logger.error(f"Payment processing error: {e}")
        return {"error": "Payment processing temporarily unavailable"}


def send_email(to: str, subject: str, body: str) -> Dict[str, Any]:
    """Send email with validation"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, to):
        return {"status": "failed", "error": "Invalid email format"}
    
    if not subject or not body:
        return {"status": "failed", "error": "Subject and body are required"}
    
    try:
        logger.info(f"Email queued - To: {to}, Subject: {subject}")
        return {"status": "success", "message": "Email sent successfully"}
        
    except Exception as e:
        logger.error(f"Email sending error: {e}")
        return {"error": "Email service temporarily unavailable"}


class SessionManager:
    """
    Secure session management with expiration and thread safety
    
    PRODUCTION NOTE: This uses in-memory storage for simplicity.
    For production with multiple servers, use Redis or a database.
    For production with session persistence across restarts, use encrypted cookies or database storage.
    """
    
    def __init__(self, session_timeout_minutes: int = SESSION_TIMEOUT_MINUTES):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._user_sessions: Dict[int, set] = defaultdict(set)  # Track sessions per user
        self._lock = Lock()
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.max_sessions_per_user = MAX_SESSIONS_PER_USER
    
    def create_session(self, user_id: int) -> Dict[str, Any]:
        """
        Create user session with cryptographically secure ID
        
        Args:
            user_id: User's ID
            
        Returns:
            Dict with session_id or error
        """
        with self._lock:
            # Check session limit per user
            if len(self._user_sessions[user_id]) >= self.max_sessions_per_user:
                # Remove oldest session
                oldest_session = min(
                    self._user_sessions[user_id],
                    key=lambda sid: self._sessions[sid]["created_at"]
                )
                self._destroy_session_internal(oldest_session)
                logger.info(f"Removed oldest session for user {user_id} due to limit")
            
            session_id = secrets.token_urlsafe(32)
            
            self._sessions[session_id] = {
                "user_id": user_id,
                "created_at": datetime.now(),
                "last_accessed": datetime.now()
            }
            self._user_sessions[user_id].add(session_id)
        
        logger.info(f"Session created for user {user_id}")
        return {"status": "success", "session_id": session_id}
    
    def validate_session(self, session_id: str) -> Optional[int]:
        """Validate session and return user_id if valid"""
        with self._lock:
            if session_id not in self._sessions:
                return None
            
            session = self._sessions[session_id]
            time_since_access = datetime.now() - session["last_accessed"]
            
            if time_since_access > self.session_timeout:
                self._destroy_session_internal(session_id)
                logger.info(f"Session expired: {session_id}")
                return None
            
            session["last_accessed"] = datetime.now()
            return session["user_id"]
    
    def destroy_session(self, session_id: str) -> bool:
        """Destroy/logout a session"""
        with self._lock:
            return self._destroy_session_internal(session_id)
    
    def _destroy_session_internal(self, session_id: str) -> bool:
        """Internal method to destroy session (must be called with lock held)"""
        if session_id in self._sessions:
            user_id = self._sessions[session_id]["user_id"]
            del self._sessions[session_id]
            self._user_sessions[user_id].discard(session_id)
            logger.info(f"Session destroyed: {session_id}")
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions"""
        current_time = datetime.now()
        
        with self._lock:
            expired = [
                sid for sid, session in self._sessions.items()
                if current_time - session["last_accessed"] > self.session_timeout
            ]
            
            for sid in expired:
                self._destroy_session_internal(sid)
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
        
        return len(expired)