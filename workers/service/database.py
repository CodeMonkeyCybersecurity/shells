"""
PostgreSQL Database Integration for Python Workers

Saves scan findings to PostgreSQL for integration with Shells Go application.

P0-4 FIX: PostgreSQL integration for findings persistence

IMPORTANT: Severity Normalization (2025-10-30)
- All severity values are normalized to lowercase before saving to database
- This matches Go's canonical format: "critical", "high", "medium", "low", "info"
- Accepts both uppercase and lowercase input for compatibility
- Ensures Python findings are queryable by Go CLI (shells results query --severity critical)
"""
import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

import psycopg2
from psycopg2.extras import Json, execute_values
from contextlib import contextmanager


class DatabaseClient:
    """PostgreSQL client for saving scan findings"""

    def __init__(self, dsn: Optional[str] = None):
        """
        Initialize database client

        Args:
            dsn: PostgreSQL connection string (defaults to env var POSTGRES_DSN)
        """
        self.dsn = dsn or os.getenv(
            "POSTGRES_DSN",
            "postgresql://shells:shells@postgres:5432/shells"
        )

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections

        Yields:
            psycopg2 connection

        Example:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM findings")
        """
        conn = psycopg2.connect(self.dsn)
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()

    def save_finding(
        self,
        scan_id: str,
        tool: str,
        finding_type: str,
        severity: str,
        title: str,
        description: str = "",
        evidence: str = "",
        solution: str = "",
        references: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Save a single finding to PostgreSQL

        Args:
            scan_id: Shells scan ID (from Go application)
            tool: Scanner tool name (e.g., "graphcrawler", "custom_idor")
            finding_type: Type of vulnerability (e.g., "IDOR", "GraphQL_Introspection")
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            title: Short finding title
            description: Detailed description
            evidence: Evidence of vulnerability
            solution: Remediation guidance
            references: List of reference URLs/CVEs
            metadata: Additional metadata as dict

        Returns:
            Finding ID (UUID)

        Raises:
            psycopg2.Error: If database operation fails
        """
        finding_id = str(uuid.uuid4())
        now = datetime.utcnow()

        # Normalize severity to lowercase (matches Go canonical format)
        # Accepts both uppercase and lowercase for compatibility
        severity_lower = severity.lower()

        # Validate severity (Go uses lowercase: critical, high, medium, low, info)
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if severity_lower not in valid_severities:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Must be one of {valid_severities} (case-insensitive)"
            )

        query = """
            INSERT INTO findings (
                id, scan_id, tool, type, severity, title, description,
                evidence, solution, refs, metadata, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                query,
                (
                    finding_id,
                    scan_id,
                    tool,
                    finding_type,
                    severity_lower,  # Use normalized lowercase severity
                    title,
                    description,
                    evidence,
                    solution,
                    Json(references or []),
                    Json(metadata or {}),
                    now,
                    now,
                ),
            )

        return finding_id

    def save_findings_batch(
        self, scan_id: str, tool: str, findings: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Save multiple findings in a single transaction

        Args:
            scan_id: Shells scan ID
            tool: Scanner tool name
            findings: List of finding dicts with keys:
                - type (required)
                - severity (required)
                - title (required)
                - description (optional)
                - evidence (optional)
                - solution (optional)
                - references (optional, list)
                - metadata (optional, dict)

        Returns:
            List of finding IDs (UUIDs)

        Raises:
            ValueError: If required fields missing
            psycopg2.Error: If database operation fails

        Example:
            findings = [
                {
                    "type": "IDOR",
                    "severity": "HIGH",
                    "title": "User can access other users' data",
                    "description": "User B can read User A's profile",
                    "evidence": "GET /api/users/123 -> 200 OK",
                    "metadata": {"user_id": 123, "endpoint": "/api/users/{id}"}
                }
            ]
            db.save_findings_batch(scan_id, "custom_idor", findings)
        """
        if not findings:
            return []

        now = datetime.utcnow()
        finding_ids = []
        values = []

        for finding in findings:
            # Validate required fields
            required = ["type", "severity", "title"]
            for field in required:
                if field not in finding:
                    raise ValueError(f"Finding missing required field: {field}")

            finding_id = str(uuid.uuid4())
            finding_ids.append(finding_id)

            # Normalize severity to lowercase (matches Go canonical format)
            severity_lower = finding["severity"].lower()

            # Validate severity (Go uses lowercase: critical, high, medium, low, info)
            valid_severities = ["critical", "high", "medium", "low", "info"]
            if severity_lower not in valid_severities:
                raise ValueError(
                    f"Invalid severity '{finding['severity']}'. "
                    f"Must be one of {valid_severities} (case-insensitive)"
                )

            values.append(
                (
                    finding_id,
                    scan_id,
                    tool,
                    finding["type"],
                    severity_lower,  # Use normalized lowercase severity
                    finding["title"],
                    finding.get("description", ""),
                    finding.get("evidence", ""),
                    finding.get("solution", ""),
                    Json(finding.get("references", [])),
                    Json(finding.get("metadata", {})),
                    now,
                    now,
                )
            )

        query = """
            INSERT INTO findings (
                id, scan_id, tool, type, severity, title, description,
                evidence, solution, refs, metadata, created_at, updated_at
            ) VALUES %s
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            execute_values(cursor, query, values)

        return finding_ids

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Update scan status in PostgreSQL

        Args:
            scan_id: Shells scan ID
            status: Status (pending, running, completed, failed)
            error_message: Error message if status is failed

        Raises:
            psycopg2.Error: If database operation fails
        """
        query = """
            UPDATE scans
            SET status = %s,
                error_message = %s,
                updated_at = %s
            WHERE id = %s
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                query,
                (status, error_message, datetime.utcnow(), scan_id),
            )

    def create_scan_event(
        self,
        scan_id: str,
        event_type: str,
        component: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Create a scan event in PostgreSQL (for UI display)

        Args:
            scan_id: Shells scan ID
            event_type: Event type (e.g., "progress", "finding", "error")
            component: Component name (e.g., "graphcrawler", "custom_idor")
            message: Human-readable message
            metadata: Additional metadata as dict

        Raises:
            psycopg2.Error: If database operation fails
        """
        query = """
            INSERT INTO scan_events (
                scan_id, event_type, component, message, metadata, created_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s
            )
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                query,
                (
                    scan_id,
                    event_type,
                    component,
                    message,
                    Json(metadata or {}),
                    datetime.utcnow(),
                ),
            )

    def get_scan_findings_count(self, scan_id: str) -> int:
        """
        Get total number of findings for a scan

        Args:
            scan_id: Shells scan ID

        Returns:
            Number of findings

        Raises:
            psycopg2.Error: If database operation fails
        """
        query = "SELECT COUNT(*) FROM findings WHERE scan_id = %s"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (scan_id,))
            count = cursor.fetchone()[0]

        return count

    def get_findings_by_severity(
        self, scan_id: str, severity: str
    ) -> List[Dict[str, Any]]:
        """
        Get all findings for a scan filtered by severity

        Args:
            scan_id: Shells scan ID
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO

        Returns:
            List of finding dicts

        Raises:
            psycopg2.Error: If database operation fails
        """
        query = """
            SELECT id, tool, type, severity, title, description,
                   evidence, solution, refs, metadata, created_at
            FROM findings
            WHERE scan_id = %s AND severity = %s
            ORDER BY created_at DESC
        """

        findings = []
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (scan_id, severity))

            for row in cursor.fetchall():
                findings.append(
                    {
                        "id": row[0],
                        "tool": row[1],
                        "type": row[2],
                        "severity": row[3],
                        "title": row[4],
                        "description": row[5],
                        "evidence": row[6],
                        "solution": row[7],
                        "references": row[8],
                        "metadata": row[9],
                        "created_at": row[10].isoformat(),
                    }
                )

        return findings


# Convenience function for RQ workers
def get_db_client(dsn: Optional[str] = None) -> DatabaseClient:
    """
    Get a database client instance

    Args:
        dsn: PostgreSQL connection string (defaults to env var)

    Returns:
        DatabaseClient instance

    Example:
        from workers.service.database import get_db_client

        db = get_db_client()
        db.save_finding(
            scan_id="scan-123",
            tool="custom_idor",
            finding_type="IDOR",
            severity="HIGH",
            title="Unauthorized access to user data"
        )
    """
    return DatabaseClient(dsn)
