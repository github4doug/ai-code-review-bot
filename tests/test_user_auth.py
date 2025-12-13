"""
Comprehensive test suite for user authentication module
Tests security features, edge cases, and concurrent operations
"""

import unittest
import sqlite3
import tempfile
import os
import bcrypt
from datetime import datetime, timedelta
from threading import Thread
import time

# Import the module to test
# Assuming the auth code is in demo/user_auth.py
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from demo.user_auth import (
    UserAuth, SessionManager, RateLimiter, UserLevel,
    calculate_discount, process_payment, send_email, AuthConfig
)


class TestUserAuth(unittest.TestCase):
    """Test cases for UserAuth class"""
    
    def setUp(self):
        """Create a temporary database for each test"""
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.auth = UserAuth(self.db_path)
    
    def tearDown(self):
        """Clean up temporary database"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_user_registration_success(self):
        """Test successful user registration"""
        result = self.auth.register_user(
            username="testuser",
            password="Test123!@#",
            email="test@example.com"
        )
        self.assertEqual(result["status"], "success")
    
    def test_user_registration_duplicate_username(self):
        """Test registration with duplicate username"""
        self.auth.register_user("testuser", "Test123!@#", "test1@example.com")
        result = self.auth.register_user("testuser", "Test123!@#", "test2@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("username", result["error"].lower())
    
    def test_user_registration_duplicate_email(self):
        """Test registration with duplicate email"""
        self.auth.register_user("testuser1", "Test123!@#", "test@example.com")
        result = self.auth.register_user("testuser2", "Test123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("email", result["error"].lower())
    
    def test_password_validation_too_short(self):
        """Test password validation - too short"""
        result = self.auth.register_user("testuser", "Test1!", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("8 characters", result["error"])
    
    def test_password_validation_no_uppercase(self):
        """Test password validation - missing uppercase"""
        result = self.auth.register_user("testuser", "test123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("uppercase", result["error"])
    
    def test_password_validation_no_lowercase(self):
        """Test password validation - missing lowercase"""
        result = self.auth.register_user("testuser", "TEST123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("lowercase", result["error"])
    
    def test_password_validation_no_number(self):
        """Test password validation - missing number"""
        result = self.auth.register_user("testuser", "TestTest!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("number", result["error"])
    
    def test_password_validation_no_special(self):
        """Test password validation - missing special character"""
        result = self.auth.register_user("testuser", "TestTest123", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("special", result["error"])
    
    def test_username_too_short(self):
        """Test username validation - too short"""
        result = self.auth.register_user("ab", "Test123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertIn("3 characters", result["error"])
    
    def test_username_too_long(self):
        """Test username validation - too long"""
        long_username = "a" * 51
        result = self.auth.register_user(long_username, "Test123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
    
    def test_email_validation_invalid(self):
        """Test email validation - invalid format"""
        result = self.auth.register_user("testuser", "Test123!@#", "notanemail")
        self.assertEqual(result["status"], "failed")
        self.assertIn("email", result["error"].lower())
    
    def test_login_success(self):
        """Test successful login"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        result = self.auth.login("testuser", "Test123!@#")
        self.assertEqual(result["status"], "success")
        self.assertIn("user", result)
        self.assertEqual(result["user"]["username"], "testuser")
    
    def test_login_wrong_password(self):
        """Test login with wrong password"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        result = self.auth.login("testuser", "WrongPassword123!")
        self.assertEqual(result["status"], "failed")
    
    def test_login_nonexistent_user(self):
        """Test login with non-existent user"""
        result = self.auth.login("nonexistent", "Test123!@#")
        self.assertEqual(result["status"], "failed")
    
    def test_bcrypt_hash_storage(self):
        """Test that bcrypt hashes are stored as bytes"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        
        with self.auth._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", ("testuser",))
            result = cursor.fetchone()
            
            # Verify hash is bytes
            self.assertIsInstance(result['password_hash'], bytes)
            # Verify it's a valid bcrypt hash
            self.assertTrue(bcrypt.checkpw(b"Test123!@#", result['password_hash']))
    
    def test_get_user_data_authorized(self):
        """Test getting user data when authorized"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        login_result = self.auth.login("testuser", "Test123!@#")
        user_id = login_result["user"]["id"]
        
        user_data = self.auth.get_user_data(user_id, user_id)
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data["username"], "testuser")
    
    def test_get_user_data_unauthorized(self):
        """Test getting user data when not authorized"""
        self.auth.register_user("testuser1", "Test123!@#", "test1@example.com")
        self.auth.register_user("testuser2", "Test123!@#", "test2@example.com")
        
        user_data = self.auth.get_user_data(user_id=1, requesting_user_id=2)
        self.assertIsNone(user_data)
    
    def test_delete_user_authorized(self):
        """Test deleting own user account"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        login_result = self.auth.login("testuser", "Test123!@#")
        user_id = login_result["user"]["id"]
        
        result = self.auth.delete_user("testuser", user_id)
        self.assertEqual(result["status"], "success")
    
    def test_delete_user_unauthorized(self):
        """Test deleting another user's account without admin"""
        self.auth.register_user("testuser1", "Test123!@#", "test1@example.com")
        self.auth.register_user("testuser2", "Test123!@#", "test2@example.com")
        
        result = self.auth.delete_user("testuser1", requesting_user_id=2)
        self.assertEqual(result["status"], "failed")
        self.assertIn("unauthorized", result["error"].lower())
    
    def test_delete_user_admin(self):
        """Test admin can delete any user"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        
        result = self.auth.delete_user("testuser", requesting_user_id=999, is_admin=True)
        self.assertEqual(result["status"], "success")


class TestRateLimiter(unittest.TestCase):
    """Test cases for RateLimiter class"""
    
    def setUp(self):
        """Create a rate limiter with short window for testing"""
        self.limiter = RateLimiter(max_attempts=3, window_minutes=1)
    
    def test_not_rate_limited_initially(self):
        """Test that new identifier is not rate limited"""
        is_limited, _ = self.limiter.is_rate_limited("test_user")
        self.assertFalse(is_limited)
    
    def test_rate_limited_after_max_attempts(self):
        """Test rate limiting after max attempts"""
        for _ in range(3):
            self.limiter.record_attempt("test_user")
        
        is_limited, unlock_time = self.limiter.is_rate_limited("test_user")
        self.assertTrue(is_limited)
        self.assertIsNotNone(unlock_time)
    
    def test_reset_attempts_clears_limit(self):
        """Test that reset_attempts clears rate limit"""
        for _ in range(3):
            self.limiter.record_attempt("test_user")
        
        self.limiter.reset_attempts("test_user")
        is_limited, _ = self.limiter.is_rate_limited("test_user")
        self.assertFalse(is_limited)
    
    def test_different_users_independent(self):
        """Test that different users have independent rate limits"""
        for _ in range(3):
            self.limiter.record_attempt("user1")
        
        is_limited, _ = self.limiter.is_rate_limited("user2")
        self.assertFalse(is_limited)


class TestSessionManager(unittest.TestCase):
    """Test cases for SessionManager class"""
    
    def setUp(self):
        """Create a session manager with short timeout for testing"""
        self.session_mgr = SessionManager(session_timeout_minutes=1)
    
    def test_create_session(self):
        """Test session creation"""
        result = self.session_mgr.create_session(user_id=1)
        self.assertEqual(result["status"], "success")
        self.assertIn("session_id", result)
        self.assertEqual(len(result["session_id"]), 43)  # token_urlsafe(32) length
    
    def test_validate_session_valid(self):
        """Test validating a valid session"""
        result = self.session_mgr.create_session(user_id=1)
        session_id = result["session_id"]
        
        user_id = self.session_mgr.validate_session(session_id)
        self.assertEqual(user_id, 1)
    
    def test_validate_session_invalid(self):
        """Test validating an invalid session"""
        user_id = self.session_mgr.validate_session("invalid_session_id")
        self.assertIsNone(user_id)
    
    def test_session_expiration(self):
        """Test that sessions expire after timeout"""
        result = self.session_mgr.create_session(user_id=1)
        session_id = result["session_id"]
        
        # Manually set last_accessed to past
        self.session_mgr._sessions[session_id]["last_accessed"] = \
            datetime.now() - timedelta(minutes=2)
        
        user_id = self.session_mgr.validate_session(session_id)
        self.assertIsNone(user_id)
    
    def test_destroy_session(self):
        """Test destroying a session"""
        result = self.session_mgr.create_session(user_id=1)
        session_id = result["session_id"]
        
        destroyed = self.session_mgr.destroy_session(session_id)
        self.assertTrue(destroyed)
        
        user_id = self.session_mgr.validate_session(session_id)
        self.assertIsNone(user_id)
    
    def test_max_sessions_per_user(self):
        """Test that old sessions are removed when limit is reached"""
        # Create max sessions
        session_ids = []
        for _ in range(5):
            result = self.session_mgr.create_session(user_id=1)
            session_ids.append(result["session_id"])
        
        # Create one more - should remove oldest
        result = self.session_mgr.create_session(user_id=1)
        new_session_id = result["session_id"]
        
        # Oldest session should be invalid
        user_id = self.session_mgr.validate_session(session_ids[0])
        self.assertIsNone(user_id)
        
        # New session should be valid
        user_id = self.session_mgr.validate_session(new_session_id)
        self.assertEqual(user_id, 1)
    
    def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions"""
        # Create some sessions
        for i in range(3):
            self.session_mgr.create_session(user_id=i)
        
        # Expire all sessions
        for session_id in list(self.session_mgr._sessions.keys()):
            self.session_mgr._sessions[session_id]["last_accessed"] = \
                datetime.now() - timedelta(minutes=2)
        
        cleaned = self.session_mgr.cleanup_expired_sessions()
        self.assertEqual(cleaned, 3)
        self.assertEqual(len(self.session_mgr._sessions), 0)


class TestConcurrency(unittest.TestCase):
    """Test concurrent operations for thread safety"""
    
    def setUp(self):
        """Create temporary database"""
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.auth = UserAuth(self.db_path)
        self.session_mgr = SessionManager()
    
    def tearDown(self):
        """Clean up"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_concurrent_registration(self):
        """Test concurrent user registrations"""
        results = []
        
        def register_user(username):
            result = self.auth.register_user(
                username=username,
                password="Test123!@#",
                email=f"{username}@example.com"
            )
            results.append(result)
        
        threads = [Thread(target=register_user, args=(f"user{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should succeed
        self.assertEqual(len([r for r in results if r["status"] == "success"]), 10)
    
    def test_concurrent_logins(self):
        """Test concurrent login attempts"""
        self.auth.register_user("testuser", "Test123!@#", "test@example.com")
        
        results = []
        
        def login():
            result = self.auth.login("testuser", "Test123!@#")
            results.append(result)
        
        threads = [Thread(target=login) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should succeed
        self.assertEqual(len([r for r in results if r["status"] == "success"]), 10)
    
    def test_concurrent_session_operations(self):
        """Test concurrent session creation and validation"""
        sessions = []
        
        def create_and_validate():
            result = self.session_mgr.create_session(user_id=1)
            session_id = result["session_id"]
            # Validate immediately to ensure session exists
            user_id = self.session_mgr.validate_session(session_id)
            sessions.append((session_id, user_id))
        
        # Only create 10 sessions (less than max of 5 per user to avoid eviction during test)
        threads = [Thread(target=create_and_validate) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All sessions should have been created
        self.assertEqual(len(sessions), 10)
        # Filter out None values (sessions that were evicted due to limit)
        valid_sessions = [(sid, uid) for sid, uid in sessions if uid is not None]
        # At least some sessions should be valid
        self.assertGreater(len(valid_sessions), 0)
        # All valid sessions should be for user 1
        self.assertTrue(all(user_id == 1 for _, user_id in valid_sessions))


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""
    
    def test_calculate_discount_valid_level(self):
        """Test discount calculation with valid level"""
        result = calculate_discount(100.0, "gold")
        self.assertEqual(result["original_price"], 100.0)
        self.assertEqual(result["discount_rate"], 0.15)
        self.assertEqual(result["final_price"], 85.0)
    
    def test_calculate_discount_invalid_level(self):
        """Test discount calculation with invalid level"""
        result = calculate_discount(100.0, "diamond")
        self.assertIn("error", result)
    
    def test_calculate_discount_negative_price(self):
        """Test discount calculation with negative price"""
        result = calculate_discount(-100.0, "gold")
        self.assertIn("error", result)
    
    def test_process_payment_valid(self):
        """Test payment processing with valid inputs"""
        result = process_payment(100.0, "USD")
        self.assertEqual(result["original_amount"], 100.0)
        self.assertIn("total", result)
    
    def test_process_payment_invalid_currency(self):
        """Test payment processing with invalid currency"""
        result = process_payment(100.0, "XXX")
        self.assertIn("error", result)
    
    def test_process_payment_zero_amount(self):
        """Test payment processing with zero amount"""
        result = process_payment(0.0, "USD")
        self.assertIn("error", result)
    
    def test_send_email_valid(self):
        """Test email sending with valid inputs"""
        result = send_email("test@example.com", "Test Subject", "Test Body")
        self.assertEqual(result["status"], "success")
    
    def test_send_email_invalid_address(self):
        """Test email sending with invalid email"""
        result = send_email("notanemail", "Test Subject", "Test Body")
        self.assertEqual(result["status"], "failed")
    
    def test_send_email_missing_subject(self):
        """Test email sending with missing subject"""
        result = send_email("test@example.com", "", "Test Body")
        self.assertEqual(result["status"], "failed")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def setUp(self):
        """Create temporary database"""
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.auth = UserAuth(self.db_path)
    
    def tearDown(self):
        """Clean up"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_empty_username(self):
        """Test registration with empty username"""
        result = self.auth.register_user("", "Test123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
    
    def test_empty_password(self):
        """Test registration with empty password"""
        result = self.auth.register_user("testuser", "", "test@example.com")
        self.assertEqual(result["status"], "failed")
    
    def test_empty_email(self):
        """Test registration with empty email"""
        result = self.auth.register_user("testuser", "Test123!@#", "")
        self.assertEqual(result["status"], "failed")
    
    def test_whitespace_only_inputs(self):
        """Test registration with whitespace-only inputs"""
        result = self.auth.register_user("   ", "Test123!@#", "test@example.com")
        self.assertEqual(result["status"], "failed")
    
    def test_unicode_username(self):
        """Test registration with unicode characters"""
        result = self.auth.register_user("用户名", "Test123!@#", "test@example.com")
        # Should succeed - unicode is valid
        self.assertEqual(result["status"], "success")
    
    def test_sql_injection_attempt_username(self):
        """Test that SQL injection in username doesn't work"""
        malicious_username = "admin' OR '1'='1"
        result = self.auth.register_user(
            malicious_username,
            "Test123!@#",
            "test@example.com"
        )
        # Should succeed (parameterized queries prevent injection)
        self.assertEqual(result["status"], "success")
        
        # Verify it's stored literally
        login_result = self.auth.login(malicious_username, "Test123!@#")
        self.assertEqual(login_result["status"], "success")


def run_tests():
    """Run all tests and generate report"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestUserAuth))
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiter))
    suite.addTests(loader.loadTestsFromTestCase(TestSessionManager))
    suite.addTests(loader.loadTestsFromTestCase(TestConcurrency))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result


if __name__ == "__main__":
    run_tests()