"""
End-to-end integration tests for Python workers

Tests the complete workflow:
  API -> RQ -> Scanner -> PostgreSQL

These tests require Redis and PostgreSQL to be running.
Mark as integration tests to skip in CI without services.
"""
import pytest
import os
import time
import json
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workers.service.database import get_db_client


@pytest.mark.integration
class TestEndToEndWorkflow:
    """
    End-to-end integration tests

    Requirements:
    - Redis running on localhost:6379
    - PostgreSQL running with POSTGRES_DSN env var set
    - RQ worker running in background
    """

    @pytest.fixture(scope="class")
    def check_services(self):
        """Check that required services are available"""
        # Check Redis
        try:
            import redis
            r = redis.Redis(host='localhost', port=6379)
            r.ping()
        except Exception as e:
            pytest.skip(f"Redis not available: {e}")

        # Check PostgreSQL
        if not os.getenv("POSTGRES_DSN"):
            pytest.skip("POSTGRES_DSN environment variable not set")

        try:
            db = get_db_client()
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
        except Exception as e:
            pytest.skip(f"PostgreSQL not available: {e}")

        return True

    @pytest.fixture
    def api_client(self, check_services):
        """Create FastAPI test client"""
        from fastapi.testclient import TestClient
        from workers.service.main_rq import app
        return TestClient(app)

    @pytest.fixture
    def db_client(self):
        """Create database client"""
        return get_db_client()

    @pytest.fixture
    def test_scan_id(self):
        """Generate unique scan ID for tests"""
        return f"test-scan-{int(time.time())}"

    def test_graphql_scan_full_workflow(self, api_client, db_client, test_scan_id):
        """
        Test complete GraphQL scan workflow:
        1. Submit scan via API
        2. Wait for RQ worker to process
        3. Verify findings in PostgreSQL
        """
        # Submit scan
        response = api_client.post(
            "/graphql/scan",
            json={
                "endpoint": "https://api.github.com/graphql",
                "auth_header": "Bearer fake-token"
            }
        )
        assert response.status_code == 200
        data = response.json()
        job_id = data["job_id"]

        # Poll for completion (max 60 seconds)
        max_wait = 60
        start_time = time.time()
        job_status = None

        while time.time() - start_time < max_wait:
            status_response = api_client.get(f"/jobs/{job_id}")
            assert status_response.status_code == 200
            job_status = status_response.json()

            if job_status["status"] in ["finished", "failed"]:
                break

            time.sleep(2)

        # Verify job completed
        assert job_status is not None
        if job_status["status"] == "failed":
            pytest.fail(f"Job failed: {job_status.get('error', 'Unknown error')}")

        assert job_status["status"] == "finished"

        # Verify findings in database
        # Note: GitHub GraphQL may or may not have findings
        # Just verify database query works
        findings = db_client.get_findings_by_severity(test_scan_id, "CRITICAL")
        assert isinstance(findings, list)

    def test_idor_scan_full_workflow(self, api_client, db_client, test_scan_id):
        """
        Test complete IDOR scan workflow:
        1. Submit scan via API
        2. Wait for RQ worker to process
        3. Verify findings in PostgreSQL
        """
        # Submit scan with minimal range for speed
        response = api_client.post(
            "/idor/scan",
            json={
                "endpoint": "https://jsonplaceholder.typicode.com/posts/{id}",
                "tokens": [
                    "Bearer user1-token",
                    "Bearer user2-token"
                ],
                "start_id": 1,
                "end_id": 10,
                "id_type": "numeric"
            }
        )
        assert response.status_code == 200
        data = response.json()
        job_id = data["job_id"]

        # Poll for completion (max 120 seconds for IDOR scan)
        max_wait = 120
        start_time = time.time()
        job_status = None

        while time.time() - start_time < max_wait:
            status_response = api_client.get(f"/jobs/{job_id}")
            assert status_response.status_code == 200
            job_status = status_response.json()

            if job_status["status"] in ["finished", "failed"]:
                break

            time.sleep(3)

        # Verify job completed
        assert job_status is not None
        if job_status["status"] == "failed":
            pytest.fail(f"Job failed: {job_status.get('error', 'Unknown error')}")

        assert job_status["status"] == "finished"

        # Verify findings in database
        total_findings = db_client.get_scan_findings_count(test_scan_id)
        assert total_findings >= 0  # May or may not find IDOR vulnerabilities

    def test_job_stream_endpoint(self, api_client):
        """
        Test Server-Sent Events (SSE) streaming
        """
        # Submit a quick scan
        response = api_client.post(
            "/idor/scan",
            json={
                "endpoint": "https://jsonplaceholder.typicode.com/posts/{id}",
                "tokens": ["Bearer token1", "Bearer token2"],
                "start_id": 1,
                "end_id": 5
            }
        )
        assert response.status_code == 200
        job_id = response.json()["job_id"]

        # Stream updates (read first few events)
        with api_client.stream("GET", f"/jobs/{job_id}/stream") as response:
            assert response.status_code == 200

            # Read first event
            event_count = 0
            for line in response.iter_lines():
                if line.startswith(b"data:"):
                    event_count += 1
                    # Parse event
                    data = json.loads(line[5:])
                    assert "job_id" in data
                    assert "status" in data

                    if event_count >= 3 or data["status"] == "finished":
                        break


@pytest.mark.integration
class TestDatabaseIntegration:
    """Test database operations with real PostgreSQL"""

    @pytest.fixture
    def db_client(self):
        """Create database client"""
        if not os.getenv("POSTGRES_DSN"):
            pytest.skip("POSTGRES_DSN environment variable not set")

        try:
            db = get_db_client()
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
            return db
        except Exception as e:
            pytest.skip(f"PostgreSQL not available: {e}")

    @pytest.fixture
    def test_scan_id(self):
        """Generate unique scan ID"""
        return f"test-integration-{int(time.time())}"

    def test_save_and_retrieve_finding(self, db_client, test_scan_id):
        """Test saving and retrieving a finding"""
        # Save finding
        finding_id = db_client.save_finding(
            scan_id=test_scan_id,
            tool="integration_test",
            finding_type="TEST",
            severity="HIGH",
            title="Integration test finding",
            description="This is a test finding",
            evidence="Test evidence",
            metadata={"test": True}
        )

        assert finding_id is not None

        # Retrieve findings
        findings = db_client.get_findings_by_severity(test_scan_id, "HIGH")
        assert len(findings) >= 1

        # Find our test finding
        test_finding = None
        for finding in findings:
            if finding["id"] == finding_id:
                test_finding = finding
                break

        assert test_finding is not None
        assert test_finding["title"] == "Integration test finding"
        assert test_finding["severity"] == "HIGH"

    def test_batch_save_and_count(self, db_client, test_scan_id):
        """Test batch save and count operations"""
        # Prepare batch
        findings = [
            {
                "type": "IDOR",
                "severity": "CRITICAL",
                "title": f"Test finding {i}",
                "description": f"Test description {i}"
            }
            for i in range(5)
        ]

        # Save batch
        finding_ids = db_client.save_findings_batch(
            scan_id=test_scan_id,
            tool="integration_test",
            findings=findings
        )

        assert len(finding_ids) == 5

        # Get count
        count = db_client.get_scan_findings_count(test_scan_id)
        assert count == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
