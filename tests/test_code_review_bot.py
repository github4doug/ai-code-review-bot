"""
Test suite for the AI Code Review Bot
Tests diff parsing, severity detection, and review generation
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock, mock_open
import sys

# Import the module to test
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from code_review_bot import (
    get_pr_diff,
    review_code,
    analyze_severity,
    format_review_comment,
    save_review
)


class TestDiffParsing(unittest.TestCase):
    """Test PR diff file reading and parsing"""
    
    def test_get_pr_diff_success(self):
        """Test successfully reading a diff file"""
        test_diff = """diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,3 +1,3 @@
 def hello():
-    print("old")
+    print("new")
"""
        with patch('builtins.open', mock_open(read_data=test_diff)):
            with patch('os.path.exists', return_value=True):
                result = get_pr_diff()
                self.assertIsNotNone(result)
                self.assertIn("diff --git", result)
                self.assertIn("print", result)
    
    def test_get_pr_diff_missing_file(self):
        """Test handling of missing diff file"""
        with patch('os.path.exists', return_value=False):
            result = get_pr_diff()
            self.assertIsNone(result)
    
    def test_get_pr_diff_empty_file(self):
        """Test handling of empty diff file"""
        with patch('builtins.open', mock_open(read_data="")):
            with patch('os.path.exists', return_value=True):
                result = get_pr_diff()
                self.assertIsNone(result)
    
    def test_get_pr_diff_whitespace_only(self):
        """Test handling of whitespace-only diff"""
        with patch('builtins.open', mock_open(read_data="   \n\n   ")):
            with patch('os.path.exists', return_value=True):
                result = get_pr_diff()
                self.assertIsNone(result)


class TestSeverityDetection(unittest.TestCase):
    """Test severity analysis of code reviews"""
    
    def test_severity_critical_explicit_blocking(self):
        """Test detection of explicit BLOCKING statement"""
        review = "BLOCKING: This should not be merged. SQL injection found."
        severity = analyze_severity(review)
        self.assertEqual(severity, "critical")
    
    def test_severity_critical_multiple_indicators(self):
        """Test detection of multiple critical indicators"""
        review = """
        🔴 CRITICAL: SQL injection vulnerability
        🔴 CRITICAL: Plaintext password storage
        🔴 CRITICAL: Authentication bypass
        """
        severity = analyze_severity(review)
        self.assertEqual(severity, "critical")
    
    def test_severity_critical_security_keywords(self):
        """Test detection of multiple security keywords"""
        review = """
        Found SQL injection in login function.
        Password stored in plaintext.
        XSS vulnerability in user input.
        """
        severity = analyze_severity(review)
        # Should be critical (3+ security keywords)
        self.assertEqual(severity, "critical")
    
    def test_severity_warning_single_critical(self):
        """Test warning level with single critical indicator"""
        review = "🔴 One security issue: missing input validation"
        severity = analyze_severity(review)
        self.assertEqual(severity, "warning")
    
    def test_severity_pass_no_issues(self):
        """Test pass level with no critical issues"""
        review = """
        ✅ No blocking issues found
        🟢 Code quality looks good
        Minor suggestions for improvement
        """
        severity = analyze_severity(review)
        self.assertEqual(severity, "pass")
    
    def test_severity_pass_only_suggestions(self):
        """Test pass level with only suggestions"""
        review = "Consider adding type hints. Could use better variable names."
        severity = analyze_severity(review)
        self.assertEqual(severity, "pass")
    
    def test_severity_critical_weak_hashing(self):
        """Test detection of weak hashing with explicit critical marker"""
        review = "🔴 CRITICAL: Using MD5 for password hashing is insecure."
        severity = analyze_severity(review)
        self.assertEqual(severity, "critical")
    
    def test_severity_critical_auth_bypass(self):
        """Test detection of authentication bypass with multiple indicators"""
        review = """
        🔴 Authentication bypass possible through parameter manipulation
        🔴 Authorization checks missing
        """
        severity = analyze_severity(review)
        self.assertEqual(severity, "critical")


class TestReviewFormatting(unittest.TestCase):
    """Test review comment formatting"""
    
    def test_format_critical_review(self):
        """Test formatting of critical severity review"""
        review = "SQL injection found in login"
        comment = format_review_comment(review, "critical")
        
        self.assertIn("🔴", comment)
        self.assertIn("BLOCKING ISSUES FOUND", comment)
        self.assertIn("DO NOT MERGE", comment)
        self.assertIn(review, comment)
        self.assertIn("CRITICAL", comment.upper())
    
    def test_format_warning_review(self):
        """Test formatting of warning severity review"""
        review = "Missing error handling"
        comment = format_review_comment(review, "warning")
        
        self.assertIn("🟡", comment)
        self.assertIn("Issues Found", comment)
        self.assertIn(review, comment)
        self.assertIn("Review Required", comment)
    
    def test_format_pass_review(self):
        """Test formatting of passing review"""
        review = "Code looks good with minor suggestions"
        comment = format_review_comment(review, "pass")
        
        self.assertIn("✅", comment)
        self.assertIn("Approved", comment)
        self.assertIn(review, comment)
        self.assertIn("Safe to Merge", comment)
    
    def test_format_contains_disclaimer(self):
        """Test that all reviews contain AI disclaimer"""
        for severity in ["critical", "warning", "pass"]:
            comment = format_review_comment("Test review", severity)
            self.assertIn("automatically generated by Claude AI", comment)
            self.assertIn("human judgment", comment)
    
    def test_format_contains_summary(self):
        """Test that reviews contain summary section"""
        comment = format_review_comment("Test", "critical")
        self.assertIn("Review Summary", comment)
        self.assertIn("Severity Level", comment)
        self.assertIn("Merge Recommendation", comment)


class TestReviewSaving(unittest.TestCase):
    """Test saving review results to files"""
    
    def test_save_review_success(self):
        """Test successful saving of review"""
        comment = "Test review comment"
        severity = "pass"
        
        mock_file = mock_open()
        with patch('builtins.open', mock_file):
            result = save_review(comment, severity)
            self.assertTrue(result)
            
            # Verify files were written
            self.assertEqual(mock_file.call_count, 2)  # comment + severity files
    
    def test_save_review_creates_correct_files(self):
        """Test that correct files are created"""
        comment = "Test comment"
        severity = "critical"
        
        files_written = {}
        
        def mock_open_with_tracking(filename, mode='r'):
            mock = mock_open()
            files_written[filename] = mock
            return mock.return_value
        
        with patch('builtins.open', side_effect=mock_open_with_tracking):
            save_review(comment, severity)
            
            self.assertIn('review_comment.md', files_written)
            self.assertIn('review_severity.txt', files_written)


class TestReviewGeneration(unittest.TestCase):
    """Test end-to-end review generation (mocked API calls)"""
    
    @patch('code_review_bot.Anthropic')
    def test_review_code_sql_injection(self, mock_anthropic):
        """Test that SQL injection is detected"""
        # Mock API response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="SQL injection vulnerability found")]
        mock_anthropic.return_value.messages.create.return_value = mock_response
        
        diff = """
+    query = f"SELECT * FROM users WHERE username='{username}'"
+    cursor.execute(query)
"""
        
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            review = review_code(diff)
            self.assertIsNotNone(review)
            self.assertIn("SQL injection", review)
    
    @patch('code_review_bot.Anthropic')
    def test_review_code_no_api_key(self, mock_anthropic):
        """Test handling of missing API key"""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                review_code("test diff")
    
    @patch('code_review_bot.Anthropic')
    def test_review_code_api_error(self, mock_anthropic):
        """Test handling of API errors"""
        mock_anthropic.return_value.messages.create.side_effect = Exception("API Error")
        
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            review = review_code("test diff")
            self.assertIsNone(review)


class TestEndToEndWorkflow(unittest.TestCase):
    """Test complete workflow from diff to saved review"""
    
    @patch('code_review_bot.Anthropic')
    def test_complete_workflow_critical(self, mock_anthropic):
        """Test complete workflow with critical issues"""
        # Setup
        test_diff = "SQL injection code here"
        mock_response = MagicMock()
        mock_response.content = [MagicMock(
            text="BLOCKING: SQL injection vulnerability found"
        )]
        mock_anthropic.return_value.messages.create.return_value = mock_response
        
        # Execute
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            review = review_code(test_diff)
            severity = analyze_severity(review)
            comment = format_review_comment(review, severity)
            
            # Verify
            self.assertIsNotNone(review)
            self.assertEqual(severity, "critical")
            self.assertIn("BLOCKING ISSUES FOUND", comment)
            self.assertIn("DO NOT MERGE", comment)
    
    @patch('code_review_bot.Anthropic')
    def test_complete_workflow_pass(self, mock_anthropic):
        """Test complete workflow with passing review"""
        test_diff = "Good code changes"
        mock_response = MagicMock()
        mock_response.content = [MagicMock(
            text="✅ No blocking issues found. Code looks good."
        )]
        mock_anthropic.return_value.messages.create.return_value = mock_response
        
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            review = review_code(test_diff)
            severity = analyze_severity(review)
            comment = format_review_comment(review, severity)
            
            self.assertEqual(severity, "pass")
            self.assertIn("Approved", comment)
            self.assertIn("Safe to Merge", comment)


class TestSecurityKeywordDetection(unittest.TestCase):
    """Test detection of various security keywords"""
    
    def test_detect_sql_injection_variations(self):
        """Test SQL injection detection with variations"""
        # Test cases that should trigger at least warning level
        test_cases = [
            ("SQL injection vulnerability", "critical"),  # Explicit phrase
            ("sql injection found", "warning"),  # Single keyword
            ("vulnerable to SQL injection", "warning"),  # Single keyword
        ]
        
        for case, expected_min in test_cases:
            severity = analyze_severity(case)
            # Should be at least warning level
            self.assertIn(severity, ["critical", "warning"], 
                         f"Failed to detect: {case}")
    
    def test_detect_xss(self):
        """Test XSS detection"""
        review = "Cross-site scripting (XSS) vulnerability found"
        severity = analyze_severity(review)
        self.assertIn(severity, ["critical", "warning"])
    
    def test_detect_csrf(self):
        """Test CSRF detection"""
        review = "Missing CSRF protection"
        severity = analyze_severity(review)
        self.assertIn(severity, ["critical", "warning"])
    
    def test_detect_weak_crypto(self):
        """Test weak cryptography detection with multiple issues"""
        test_cases = [
            ("Using MD5 for passwords and SHA1 for tokens", "critical"),  # 2 issues
            ("weak hash algorithm detected in authentication", "warning"),  # 1 issue
        ]
        
        for case, expected in test_cases:
            severity = analyze_severity(case)
            self.assertEqual(severity, expected, 
                           f"Failed to detect weak crypto: {case}")
    
    def test_detect_auth_issues(self):
        """Test authentication issue detection with multiple problems"""
        test_cases = [
            ("authentication bypass and plaintext password", "critical"),  # 2 issues
            ("authorization bypass in admin panel", "warning"),  # 1 issue
            ("insecure password storage with weak encryption", "critical"),  # 2 issues
        ]
        
        for case, expected in test_cases:
            severity = analyze_severity(case)
            self.assertEqual(severity, expected,
                           f"Failed to detect auth issue: {case}")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions"""
    
    def test_empty_review_text(self):
        """Test handling of empty review"""
        severity = analyze_severity("")
        self.assertEqual(severity, "pass")
    
    def test_very_long_review(self):
        """Test handling of very long review"""
        long_review = "Issue found. " * 1000
        severity = analyze_severity(long_review)
        self.assertIsNotNone(severity)
    
    def test_unicode_in_review(self):
        """Test handling of unicode characters"""
        review = "发现安全问题 🔴 CRITICAL: SQL注入"
        severity = analyze_severity(review)
        self.assertEqual(severity, "critical")
    
    def test_mixed_severity_indicators(self):
        """Test review with mixed severity signals"""
        review = """
        🔴 One critical issue
        🟢 Many good practices
        ✅ Overall good code
        """
        # Should be warning (one critical but overall positive)
        severity = analyze_severity(review)
        self.assertIn(severity, ["warning", "critical"])


def run_tests():
    """Run all tests with detailed output"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDiffParsing))
    suite.addTests(loader.loadTestsFromTestCase(TestSeverityDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestReviewFormatting))
    suite.addTests(loader.loadTestsFromTestCase(TestReviewSaving))
    suite.addTests(loader.loadTestsFromTestCase(TestReviewGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestEndToEndWorkflow))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityKeywordDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("CODE REVIEW BOT TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed! The code review bot is working correctly.")
    else:
        print("\n❌ Some tests failed. Review the output above.")
    
    print("="*70)
    
    return result


if __name__ == "__main__":
    run_tests()