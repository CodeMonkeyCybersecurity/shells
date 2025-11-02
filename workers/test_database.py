#!/usr/bin/env python3
"""
Test script for PostgreSQL database integration

Usage:
    export POSTGRES_DSN="postgresql://shells:password@localhost:5432/shells"
    python3 workers/test_database.py
"""
import os
import sys
from datetime import datetime

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workers.service.database import get_db_client


def test_database_connection():
    """Test basic database connectivity"""
    print("Testing PostgreSQL connection...")

    try:
        db = get_db_client()

        # Test connection by executing a simple query
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()

            if result[0] == 1:
                print("✓ Database connection successful")
                return True
            else:
                print("✗ Database connection failed: unexpected result")
                return False

    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False


def test_save_finding():
    """Test saving a single finding"""
    print("\nTesting save_finding()...")

    try:
        db = get_db_client()

        finding_id = db.save_finding(
            scan_id="test-scan-123",
            tool="test-tool",
            finding_type="TEST_FINDING",
            severity="HIGH",
            title="Test finding",
            description="This is a test finding",
            evidence="Test evidence",
            solution="Test solution",
            references=["https://example.com/ref1"],
            metadata={"test_key": "test_value"}
        )

        print(f"✓ Finding saved successfully: {finding_id}")
        return True

    except Exception as e:
        print(f"✗ save_finding() failed: {e}")
        return False


def test_save_findings_batch():
    """Test saving multiple findings in batch"""
    print("\nTesting save_findings_batch()...")

    try:
        db = get_db_client()

        findings = [
            {
                "type": "IDOR",
                "severity": "CRITICAL",
                "title": "Test IDOR finding 1",
                "description": "Test description 1",
                "evidence": "Test evidence 1",
            },
            {
                "type": "IDOR",
                "severity": "HIGH",
                "title": "Test IDOR finding 2",
                "description": "Test description 2",
                "metadata": {"endpoint": "/api/users/{id}"}
            },
        ]

        finding_ids = db.save_findings_batch(
            scan_id="test-scan-456",
            tool="custom_idor",
            findings=findings
        )

        print(f"✓ Batch saved successfully: {len(finding_ids)} findings")
        return True

    except Exception as e:
        print(f"✗ save_findings_batch() failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_get_findings():
    """Test retrieving findings"""
    print("\nTesting get_findings_by_severity()...")

    try:
        db = get_db_client()

        # Save a test finding first
        finding_id = db.save_finding(
            scan_id="test-scan-789",
            tool="test-tool",
            finding_type="TEST",
            severity="CRITICAL",
            title="Critical test finding",
        )

        # Retrieve critical findings
        critical_findings = db.get_findings_by_severity("test-scan-789", "CRITICAL")

        if len(critical_findings) > 0:
            print(f"✓ Retrieved {len(critical_findings)} critical findings")
            return True
        else:
            print("✗ No critical findings found")
            return False

    except Exception as e:
        print(f"✗ get_findings_by_severity() failed: {e}")
        return False


def test_get_scan_findings_count():
    """Test getting findings count"""
    print("\nTesting get_scan_findings_count()...")

    try:
        db = get_db_client()

        # Create scan with findings
        scan_id = f"test-scan-{int(datetime.utcnow().timestamp())}"

        db.save_finding(
            scan_id=scan_id,
            tool="test-tool",
            finding_type="TEST",
            severity="HIGH",
            title="Test finding 1",
        )

        db.save_finding(
            scan_id=scan_id,
            tool="test-tool",
            finding_type="TEST",
            severity="MEDIUM",
            title="Test finding 2",
        )

        count = db.get_scan_findings_count(scan_id)

        if count == 2:
            print(f"✓ Findings count correct: {count}")
            return True
        else:
            print(f"✗ Findings count incorrect: expected 2, got {count}")
            return False

    except Exception as e:
        print(f"✗ get_scan_findings_count() failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("PostgreSQL Database Integration Tests")
    print("=" * 60)

    # Check environment variable
    dsn = os.getenv("POSTGRES_DSN")
    if not dsn:
        print("\n✗ POSTGRES_DSN environment variable not set")
        print("\nUsage:")
        print('  export POSTGRES_DSN="postgresql://shells:password@localhost:5432/shells"')
        print("  python3 workers/test_database.py")
        sys.exit(1)

    print(f"\nUsing DSN: {dsn[:30]}...{dsn[-20:]}")

    # Run tests
    tests = [
        test_database_connection,
        test_save_finding,
        test_save_findings_batch,
        test_get_findings,
        test_get_scan_findings_count,
    ]

    results = []
    for test_func in tests:
        results.append(test_func())

    # Summary
    print("\n" + "=" * 60)
    print("Test Results")
    print("=" * 60)

    passed = sum(results)
    total = len(results)

    print(f"\nPassed: {passed}/{total}")

    if passed == total:
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
