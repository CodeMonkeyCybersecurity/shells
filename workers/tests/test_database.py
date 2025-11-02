"""
Unit tests for PostgreSQL database integration

Tests database client functionality with mocked connections.
"""
import pytest
import uuid
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, call
from contextlib import contextmanager

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workers.service.database import DatabaseClient, get_db_client


class TestDatabaseClient:
    """Test DatabaseClient class"""

    @pytest.fixture
    def db_client(self):
        """Create DatabaseClient with mocked DSN"""
        return DatabaseClient(dsn="postgresql://test:test@localhost/test")

    @pytest.fixture
    def mock_conn(self):
        """Create mock database connection"""
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        return conn, cursor

    def test_init_with_dsn(self):
        """Test initialization with explicit DSN"""
        dsn = "postgresql://user:pass@host:5432/db"
        client = DatabaseClient(dsn=dsn)
        assert client.dsn == dsn

    def test_init_with_env_var(self):
        """Test initialization with environment variable"""
        with patch.dict(os.environ, {"POSTGRES_DSN": "postgresql://env:env@env/env"}):
            client = DatabaseClient()
            assert client.dsn == "postgresql://env:env@env/env"

    def test_init_with_default(self):
        """Test initialization with default DSN"""
        with patch.dict(os.environ, {}, clear=True):
            client = DatabaseClient()
            assert client.dsn == "postgresql://shells:shells@postgres:5432/shells"

    @patch('workers.service.database.psycopg2.connect')
    def test_get_connection_success(self, mock_connect, db_client):
        """Test successful database connection"""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        with db_client.get_connection() as conn:
            assert conn == mock_conn

        mock_connect.assert_called_once_with(db_client.dsn)
        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch('workers.service.database.psycopg2.connect')
    def test_get_connection_rollback_on_error(self, mock_connect, db_client):
        """Test connection rollback on error"""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        with pytest.raises(ValueError):
            with db_client.get_connection() as conn:
                raise ValueError("Test error")

        mock_conn.rollback.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch('workers.service.database.psycopg2.connect')
    @patch('workers.service.database.uuid.uuid4')
    @patch('workers.service.database.datetime')
    def test_save_finding(self, mock_datetime, mock_uuid, mock_connect, db_client):
        """Test saving a single finding"""
        # Setup mocks
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        finding_id = "test-uuid-123"
        mock_uuid.return_value = finding_id

        now = datetime(2025, 10, 30, 12, 0, 0)
        mock_datetime.utcnow.return_value = now

        # Call save_finding
        result_id = db_client.save_finding(
            scan_id="scan-123",
            tool="test-tool",
            finding_type="TEST",
            severity="HIGH",
            title="Test finding",
            description="Test description",
            evidence="Test evidence",
            solution="Test solution",
            references=["https://example.com"],
            metadata={"key": "value"}
        )

        # Assertions
        assert result_id == finding_id
        mock_cursor.execute.assert_called_once()

        # Verify SQL query
        call_args = mock_cursor.execute.call_args
        query = call_args[0][0]
        assert "INSERT INTO findings" in query
        assert "scan_id" in query
        assert "tool" in query

    def test_save_finding_invalid_severity(self, db_client):
        """Test save_finding rejects invalid severity"""
        with patch('workers.service.database.psycopg2.connect'):
            with pytest.raises(ValueError, match="Invalid severity"):
                db_client.save_finding(
                    scan_id="scan-123",
                    tool="test-tool",
                    finding_type="TEST",
                    severity="INVALID",  # Invalid severity
                    title="Test finding"
                )

    @patch('workers.service.database.psycopg2.connect')
    @patch('workers.service.database.execute_values')
    @patch('workers.service.database.uuid.uuid4')
    def test_save_findings_batch(self, mock_uuid, mock_execute_values, mock_connect, db_client):
        """Test saving multiple findings in batch"""
        # Setup mocks
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        # Mock UUID generation
        mock_uuid.side_effect = [f"uuid-{i}" for i in range(3)]

        findings = [
            {
                "type": "IDOR",
                "severity": "HIGH",
                "title": "Finding 1",
            },
            {
                "type": "XSS",
                "severity": "MEDIUM",
                "title": "Finding 2",
                "description": "Test description"
            },
            {
                "type": "SQLi",
                "severity": "CRITICAL",
                "title": "Finding 3",
                "metadata": {"test": "data"}
            }
        ]

        # Call save_findings_batch
        result_ids = db_client.save_findings_batch(
            scan_id="scan-123",
            tool="test-tool",
            findings=findings
        )

        # Assertions
        assert len(result_ids) == 3
        assert result_ids == ["uuid-0", "uuid-1", "uuid-2"]
        mock_execute_values.assert_called_once()

    def test_save_findings_batch_missing_required_field(self, db_client):
        """Test save_findings_batch rejects findings with missing required fields"""
        with patch('workers.service.database.psycopg2.connect'):
            findings = [
                {
                    "type": "TEST",
                    # Missing severity and title
                }
            ]

            with pytest.raises(ValueError, match="missing required field"):
                db_client.save_findings_batch(
                    scan_id="scan-123",
                    tool="test-tool",
                    findings=findings
                )

    def test_save_findings_batch_invalid_severity(self, db_client):
        """Test save_findings_batch rejects invalid severity"""
        with patch('workers.service.database.psycopg2.connect'):
            findings = [
                {
                    "type": "TEST",
                    "severity": "INVALID",
                    "title": "Test"
                }
            ]

            with pytest.raises(ValueError, match="Invalid severity"):
                db_client.save_findings_batch(
                    scan_id="scan-123",
                    tool="test-tool",
                    findings=findings
                )

    def test_save_findings_batch_empty_list(self, db_client):
        """Test save_findings_batch handles empty list"""
        result_ids = db_client.save_findings_batch(
            scan_id="scan-123",
            tool="test-tool",
            findings=[]
        )
        assert result_ids == []

    @patch('workers.service.database.psycopg2.connect')
    def test_get_scan_findings_count(self, mock_connect, db_client):
        """Test getting findings count for a scan"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (42,)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        count = db_client.get_scan_findings_count("scan-123")

        assert count == 42
        mock_cursor.execute.assert_called_once()

    @patch('workers.service.database.psycopg2.connect')
    def test_get_findings_by_severity(self, mock_connect, db_client):
        """Test getting findings by severity"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        # Mock database rows
        mock_cursor.fetchall.return_value = [
            (
                "finding-1", "tool-1", "IDOR", "HIGH", "Title 1",
                "Description 1", "Evidence 1", "Solution 1",
                ["ref1"], {"meta": "data1"}, datetime.utcnow()
            ),
            (
                "finding-2", "tool-2", "XSS", "HIGH", "Title 2",
                "Description 2", "Evidence 2", "Solution 2",
                ["ref2"], {"meta": "data2"}, datetime.utcnow()
            )
        ]

        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        findings = db_client.get_findings_by_severity("scan-123", "HIGH")

        assert len(findings) == 2
        assert findings[0]["id"] == "finding-1"
        assert findings[0]["severity"] == "HIGH"
        assert findings[1]["id"] == "finding-2"

    @patch('workers.service.database.psycopg2.connect')
    @patch('workers.service.database.datetime')
    def test_create_scan_event(self, mock_datetime, mock_connect, db_client):
        """Test creating a scan event"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        now = datetime(2025, 10, 30, 12, 0, 0)
        mock_datetime.utcnow.return_value = now

        db_client.create_scan_event(
            scan_id="scan-123",
            event_type="progress",
            component="scanner",
            message="Scan started",
            metadata={"progress": 10}
        )

        mock_cursor.execute.assert_called_once()
        call_args = mock_cursor.execute.call_args
        query = call_args[0][0]
        assert "INSERT INTO scan_events" in query


class TestGetDBClient:
    """Test get_db_client convenience function"""

    def test_get_db_client_default(self):
        """Test get_db_client returns DatabaseClient instance"""
        client = get_db_client()
        assert isinstance(client, DatabaseClient)

    def test_get_db_client_with_dsn(self):
        """Test get_db_client with custom DSN"""
        dsn = "postgresql://custom:custom@custom/custom"
        client = get_db_client(dsn)
        assert isinstance(client, DatabaseClient)
        assert client.dsn == dsn


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
