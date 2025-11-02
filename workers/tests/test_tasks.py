"""
Unit tests for RQ scanner tasks

Tests run_graphql_scan() and run_idord_scan() with mocked dependencies.
"""
import pytest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open, call
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workers.service import tasks


class TestValidationFunctions:
    """Test input validation functions"""

    def test_validate_url_valid_http(self):
        """Test validate_url accepts valid HTTP URLs"""
        tasks.validate_url("http://example.com/api")
        tasks.validate_url("https://example.com/graphql")
        # Should not raise

    def test_validate_url_invalid_scheme(self):
        """Test validate_url rejects non-HTTP schemes"""
        with pytest.raises(ValueError, match="HTTP/HTTPS"):
            tasks.validate_url("ftp://example.com")

    def test_validate_url_dangerous_chars(self):
        """Test validate_url rejects shell metacharacters"""
        with pytest.raises(ValueError, match="dangerous characters"):
            tasks.validate_url("http://example.com; rm -rf /")

        with pytest.raises(ValueError, match="dangerous characters"):
            tasks.validate_url("http://example.com && cat /etc/passwd")

    def test_validate_url_invalid_structure(self):
        """Test validate_url rejects malformed URLs"""
        with pytest.raises(ValueError):
            tasks.validate_url("not-a-url")

    def test_validate_tokens_valid(self):
        """Test validate_tokens accepts valid token lists"""
        tasks.validate_tokens(["Bearer token1", "Bearer token2"])
        # Should not raise

    def test_validate_tokens_too_few(self):
        """Test validate_tokens rejects single token"""
        with pytest.raises(ValueError, match="At least 2 tokens"):
            tasks.validate_tokens(["Bearer token1"])

    def test_validate_tokens_too_many(self):
        """Test validate_tokens rejects excessive tokens"""
        with pytest.raises(ValueError, match="Maximum .* tokens"):
            tasks.validate_tokens([f"token{i}" for i in range(20)])

    def test_validate_tokens_dangerous_chars(self):
        """Test validate_tokens rejects dangerous characters"""
        with pytest.raises(ValueError, match="dangerous characters"):
            tasks.validate_tokens(["token1", "token2; rm -rf /"])

    def test_validate_id_range_valid(self):
        """Test validate_id_range accepts valid ranges"""
        tasks.validate_id_range(1, 100)
        # Should not raise

    def test_validate_id_range_negative(self):
        """Test validate_id_range rejects negative IDs"""
        with pytest.raises(ValueError, match="positive"):
            tasks.validate_id_range(-1, 100)

    def test_validate_id_range_inverted(self):
        """Test validate_id_range rejects start > end"""
        with pytest.raises(ValueError, match="start_id must be less than"):
            tasks.validate_id_range(100, 50)

    def test_validate_id_range_too_large(self):
        """Test validate_id_range rejects excessive ranges"""
        with pytest.raises(ValueError, match="Maximum range"):
            tasks.validate_id_range(1, 200000)


class TestRunGraphQLScan:
    """Test run_graphql_scan() function"""

    @pytest.fixture
    def mock_job(self):
        """Create mock RQ job"""
        job = MagicMock()
        job.id = "test-job-123"
        job.meta = {"scan_id": "scan-abc-123"}
        return job

    @pytest.fixture
    def mock_graphcrawler_output(self):
        """Create mock GraphCrawler output"""
        return {
            "findings": [
                {
                    "type": "GraphQL_Introspection",
                    "severity": "medium",
                    "title": "GraphQL introspection enabled",
                    "description": "Schema can be enumerated",
                    "evidence": {"query": "query IntrospectionQuery { __schema }"},
                    "solution": "Disable introspection in production",
                    "references": ["https://graphql.org/security"]
                }
            ]
        }

    @patch('workers.service.tasks.get_current_job')
    @patch('workers.service.tasks.subprocess.run')
    @patch('workers.service.tasks.tempfile.NamedTemporaryFile')
    @patch('workers.service.tasks.Path')
    @patch('workers.service.tasks.get_db_client')
    @patch('builtins.open', new_callable=mock_open)
    def test_run_graphql_scan_success(
        self, mock_file, mock_db, mock_path, mock_tempfile,
        mock_subprocess, mock_get_job, mock_job, mock_graphcrawler_output
    ):
        """Test successful GraphQL scan with findings"""
        # Setup mocks
        mock_get_job.return_value = mock_job

        # Mock tempfile
        temp_file = MagicMock()
        temp_file.name = "/tmp/graphcrawler_test-job-123_abc.json"
        mock_tempfile.return_value.__enter__.return_value = temp_file

        # Mock subprocess success
        process_result = MagicMock()
        process_result.returncode = 0
        process_result.stderr = ""
        process_result.stdout = "Scan completed"
        mock_subprocess.return_value = process_result

        # Mock Path.exists
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock file read
        mock_file.return_value.read.return_value = json.dumps(mock_graphcrawler_output)
        mock_file.return_value.__enter__.return_value.read.return_value = json.dumps(mock_graphcrawler_output)

        # Mock json.load
        with patch('json.load', return_value=mock_graphcrawler_output):
            # Call function
            result = tasks.run_graphql_scan(
                endpoint="https://api.example.com/graphql",
                auth_header="Bearer test-token"
            )

        # Assertions
        assert result["status"] == "completed"
        assert "result" in result
        assert mock_job.meta["progress"] == 100

        # Verify subprocess called correctly
        mock_subprocess.assert_called_once()
        cmd = mock_subprocess.call_args[0][0]
        assert str(tasks.GRAPHCRAWLER_PATH) in cmd
        assert "https://api.example.com/graphql" in cmd
        assert "Authorization: Bearer test-token" in cmd

    @patch('workers.service.tasks.get_current_job')
    @patch('workers.service.tasks.subprocess.run')
    @patch('workers.service.tasks.tempfile.NamedTemporaryFile')
    def test_run_graphql_scan_invalid_url(
        self, mock_tempfile, mock_subprocess, mock_get_job
    ):
        """Test GraphQL scan rejects invalid URL"""
        mock_get_job.return_value = None

        temp_file = MagicMock()
        temp_file.name = "/tmp/test.json"
        mock_tempfile.return_value.__enter__.return_value = temp_file

        with pytest.raises(ValueError, match="dangerous characters"):
            tasks.run_graphql_scan(
                endpoint="https://example.com; rm -rf /"
            )

    @patch('workers.service.tasks.get_current_job')
    @patch('workers.service.tasks.subprocess.run')
    @patch('workers.service.tasks.tempfile.NamedTemporaryFile')
    def test_run_graphql_scan_timeout(
        self, mock_tempfile, mock_subprocess, mock_get_job, mock_job
    ):
        """Test GraphQL scan handles timeout"""
        mock_get_job.return_value = mock_job

        temp_file = MagicMock()
        temp_file.name = "/tmp/test.json"
        mock_tempfile.return_value.__enter__.return_value = temp_file

        # Mock timeout
        import subprocess
        mock_subprocess.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=30)

        with pytest.raises(Exception, match="timed out"):
            tasks.run_graphql_scan(
                endpoint="https://api.example.com/graphql"
            )


class TestRunIDORScan:
    """Test run_idord_scan() function"""

    @pytest.fixture
    def mock_job(self):
        """Create mock RQ job"""
        job = MagicMock()
        job.id = "test-job-456"
        job.meta = {"scan_id": "scan-def-456"}
        return job

    @pytest.fixture
    def mock_idor_output(self):
        """Create mock IDOR scanner output"""
        return {
            "scan_info": {
                "endpoint": "https://api.example.com/users/{id}",
                "start_id": 1,
                "end_id": 100
            },
            "findings_count": 2,
            "findings": [
                {
                    "severity": "high",
                    "title": "IDOR vulnerability found",
                    "description": "User can access other users' data",
                    "evidence": "GET /users/123 returned 200",
                    "test_id": 123
                },
                {
                    "severity": "critical",
                    "title": "Admin IDOR vulnerability",
                    "description": "User can access admin data",
                    "evidence": "GET /users/1 returned admin profile",
                    "test_id": 1
                }
            ]
        }

    @patch('workers.service.tasks.get_current_job')
    @patch('workers.service.tasks.subprocess.run')
    @patch('workers.service.tasks.tempfile.NamedTemporaryFile')
    @patch('workers.service.tasks.Path')
    @patch('workers.service.tasks.get_db_client')
    @patch('builtins.open', new_callable=mock_open)
    def test_run_idor_scan_success(
        self, mock_file, mock_db, mock_path, mock_tempfile,
        mock_subprocess, mock_get_job, mock_job, mock_idor_output
    ):
        """Test successful IDOR scan with findings"""
        # Setup mocks
        mock_get_job.return_value = mock_job

        # Mock tempfile
        temp_file = MagicMock()
        temp_file.name = "/tmp/idor_test-job-456_xyz.json"
        mock_tempfile.return_value.__enter__.return_value = temp_file

        # Mock subprocess success
        process_result = MagicMock()
        process_result.returncode = 1  # 1 means findings found
        process_result.stderr = ""
        mock_subprocess.return_value = process_result

        # Mock Path.exists
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock json.load
        with patch('json.load', return_value=mock_idor_output):
            # Call function
            result = tasks.run_idord_scan(
                endpoint="https://api.example.com/users/{id}",
                tokens=["Bearer user1", "Bearer user2"],
                start_id=1,
                end_id=100,
                id_type="numeric"
            )

        # Assertions
        assert result["status"] == "completed"
        assert result["result"]["findings_count"] == 2
        assert mock_job.meta["progress"] == 100

        # Verify subprocess called correctly
        mock_subprocess.assert_called_once()
        cmd = mock_subprocess.call_args[0][0]
        assert str(tasks.CUSTOM_IDOR_PATH) in cmd
        assert "-u" in cmd
        assert "https://api.example.com/users/{id}" in cmd
        assert "-t" in cmd

    @patch('workers.service.tasks.get_current_job')
    def test_run_idor_scan_invalid_tokens(self, mock_get_job):
        """Test IDOR scan rejects invalid tokens"""
        mock_get_job.return_value = None

        with pytest.raises(ValueError, match="At least 2 tokens"):
            tasks.run_idord_scan(
                endpoint="https://api.example.com/users/{id}",
                tokens=["Bearer token1"],  # Only 1 token
                start_id=1,
                end_id=100
            )

    @patch('workers.service.tasks.get_current_job')
    def test_run_idor_scan_invalid_id_range(self, mock_get_job):
        """Test IDOR scan rejects invalid ID range"""
        mock_get_job.return_value = None

        with pytest.raises(ValueError, match="start_id must be less than"):
            tasks.run_idord_scan(
                endpoint="https://api.example.com/users/{id}",
                tokens=["Bearer token1", "Bearer token2"],
                start_id=100,
                end_id=50  # start > end
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
