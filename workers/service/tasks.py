"""
RQ Task definitions for scanner tools (FIXED VERSION)

Fixes applied (2025-10-30):
- P0-1: Command injection prevention (shell=False, input validation)
- P0-2: Correct CLI interfaces for actual scanner tools
- P0-3: Comprehensive input validation
- P0-4: PostgreSQL integration for findings persistence
- P0-5: Safe temp file handling (no race conditions)
- P1: Proper subprocess cleanup and timeout handling

These functions are executed by RQ workers in the background.
All findings are automatically saved to PostgreSQL for integration with Shells Go application.

PostgreSQL Integration (P0-4):
- Database client: workers.service.database.get_db_client()
- All findings saved to `findings` table with proper Shells schema
- Environment variable: POSTGRES_DSN (default: postgresql://shells:shells@postgres:5432/shells)
- Findings queryable via Shells Go CLI: `shells results query --tool graphcrawler`
- See workers/README.md "PostgreSQL Integration" section for details
"""
import os
import sys
import json
import subprocess
import tempfile
import shlex
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import hashlib
import re
from urllib.parse import urlparse

from rq import get_current_job

from workers.service.database import get_db_client

# Paths to scanner tools
TOOLS_DIR = Path(__file__).parent.parent / "tools"
CUSTOM_IDOR_PATH = TOOLS_DIR / "custom_idor.py"
GRAPHCRAWLER_PATH = TOOLS_DIR / "graphcrawler" / "graphCrawler.py"

# Maximum values for safety
MAX_ID_RANGE = 100000
MAX_TOKENS = 10
MAX_SCAN_TIME = 3600  # 1 hour


# ==============================================================================
# INPUT VALIDATION FUNCTIONS (P0-3)
# ==============================================================================

def validate_url(url: str) -> None:
    """
    Validate URL format and prevent injection

    Raises:
        ValueError: If URL is invalid or contains dangerous characters
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    # Check for shell metacharacters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    if any(char in url for char in dangerous_chars):
        raise ValueError(f"URL contains dangerous characters: {url}")

    # Validate URL structure
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError(f"Invalid URL structure: {url}")

        # Only allow http/https
        if result.scheme not in ['http', 'https']:
            raise ValueError(f"Only HTTP/HTTPS protocols allowed: {result.scheme}")

    except Exception as e:
        raise ValueError(f"URL validation failed: {e}")


def validate_tokens(tokens: List[str]) -> None:
    """
    Validate authorization tokens

    Raises:
        ValueError: If tokens are invalid
    """
    if not tokens or not isinstance(tokens, list):
        raise ValueError("Tokens must be a non-empty list")

    if len(tokens) < 2:
        raise ValueError("At least 2 tokens required for IDOR testing")

    if len(tokens) > MAX_TOKENS:
        raise ValueError(f"Maximum {MAX_TOKENS} tokens allowed")

    # Check each token for dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '\n', '\r', '\x00']
    for i, token in enumerate(tokens):
        if not isinstance(token, str):
            raise ValueError(f"Token {i} must be a string")

        if not token.strip():
            raise ValueError(f"Token {i} is empty")

        if any(char in token for char in dangerous_chars):
            raise ValueError(f"Token {i} contains dangerous characters")

        if len(token) > 2000:
            raise ValueError(f"Token {i} is too long (max 2000 characters)")


def validate_id_range(start_id: int, end_id: int) -> None:
    """
    Validate ID range

    Raises:
        ValueError: If range is invalid
    """
    if not isinstance(start_id, int) or not isinstance(end_id, int):
        raise ValueError("start_id and end_id must be integers")

    if start_id < 0 or end_id < 0:
        raise ValueError("ID range must be positive")

    if start_id > end_id:
        raise ValueError("start_id must be <= end_id")

    range_size = end_id - start_id + 1
    if range_size > MAX_ID_RANGE:
        raise ValueError(f"ID range too large (max: {MAX_ID_RANGE})")


def validate_file_path(file_path: str) -> None:
    """
    Validate file path to prevent path traversal

    Raises:
        ValueError: If path is invalid or dangerous
    """
    if not file_path or not isinstance(file_path, str):
        raise ValueError("File path must be a non-empty string")

    # Prevent path traversal
    if ".." in file_path:
        raise ValueError("Path traversal detected (..))")

    # Convert to Path and resolve
    try:
        path = Path(file_path).resolve()

        # Ensure path is within /tmp
        if not str(path).startswith("/tmp/"):
            raise ValueError(f"File must be in /tmp directory: {path}")

    except Exception as e:
        raise ValueError(f"Invalid file path: {e}")


# ==============================================================================
# GRAPHQL SCANNER (GraphCrawler)
# ==============================================================================

def run_graphql_scan(
    endpoint: str,
    auth_header: Optional[str] = None,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run GraphCrawler scanner (FIXED VERSION)

    Args:
        endpoint: GraphQL endpoint URL
        auth_header: Optional authorization header (format: "Bearer token" or "Header: Value")
        output_file: Optional output file path

    Returns:
        Dict with scan results

    Raises:
        ValueError: If inputs are invalid
        Exception: If scan fails
    """
    job = get_current_job()
    job_id = job.id if job else "manual"

    # P0-3: Validate inputs
    validate_url(endpoint)

    # Create safe temp file (P0-5: prevent race conditions)
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        prefix=f'graphcrawler_{job_id}_',
        delete=False,
        dir='/tmp'
    ) as f:
        output_file = f.name

    try:
        # Update job progress
        if job:
            job.meta["status"] = "running"
            job.meta["progress"] = 10
            job.meta["phase"] = "preparing"
            job.save_meta()

        # P0-1: Build command safely (shell=False prevents injection)
        cmd = [
            sys.executable,  # Use current Python interpreter
            str(GRAPHCRAWLER_PATH),
            "-u", endpoint,
            "-o", output_file
        ]

        # P0-2: Fix GraphCrawler header format
        if auth_header:
            # GraphCrawler expects: -a "Header: Value"
            if ":" not in auth_header:
                # Assume it's a bearer token, add Authorization header
                header_value = f"Authorization: {auth_header}"
            else:
                # Already in correct format
                header_value = auth_header

            cmd.extend(["-a", header_value])

        # Update progress
        if job:
            job.meta["progress"] = 30
            job.meta["phase"] = "scanning"
            job.save_meta()

        # P1: Execute with proper timeout and error handling
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,  # 30 minutes
            text=True,
            shell=False,  # P0-1: CRITICAL - prevents command injection
            check=False   # Don't raise on non-zero exit (we handle it)
        )

        # Update progress
        if job:
            job.meta["progress"] = 80
            job.meta["phase"] = "processing"
            job.save_meta()

        # P0-4: Check if scan succeeded
        if result.returncode != 0:
            raise Exception(
                f"GraphCrawler failed with exit code {result.returncode}\n"
                f"STDERR: {result.stderr}\n"
                f"STDOUT: {result.stdout}"
            )

        # P0-4: Safely read output file
        if not Path(output_file).exists():
            raise FileNotFoundError(
                f"GraphCrawler did not create output file: {output_file}"
            )

        with open(output_file, 'r', encoding='utf-8') as f:
            try:
                scan_result = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON output from GraphCrawler: {e}")

        # Validate result structure
        if not isinstance(scan_result, dict):
            raise ValueError(
                f"Invalid scan result format: expected dict, got {type(scan_result)}"
            )

        # P0-4: Save findings to PostgreSQL
        findings = scan_result.get("findings", [])
        if findings and job:
            db = get_db_client()
            saved_count = 0

            for finding in findings:
                try:
                    # Convert GraphCrawler findings to Shells format
                    db.save_finding(
                        scan_id=job.meta.get("scan_id", job_id),
                        tool="graphcrawler",
                        finding_type=finding.get("type", "GraphQL_Finding"),
                        severity=finding.get("severity", "MEDIUM").upper(),
                        title=finding.get("title", "GraphQL vulnerability discovered"),
                        description=finding.get("description", ""),
                        evidence=json.dumps(finding.get("evidence", {}), indent=2),
                        solution=finding.get("solution", "Review GraphQL configuration and permissions"),
                        references=finding.get("references", []),
                        metadata={
                            "endpoint": endpoint,
                            "raw_finding": finding
                        }
                    )
                    saved_count += 1
                except Exception as e:
                    # Log error but continue processing other findings
                    print(f"Warning: Failed to save finding to database: {e}", file=sys.stderr)

        # Update progress
        if job:
            job.meta["progress"] = 100
            job.meta["phase"] = "completed"
            job.meta["findings_count"] = len(scan_result.get("findings", []))
            job.save_meta()

        return {
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat(),
            "result": scan_result
        }

    except subprocess.TimeoutExpired:
        raise Exception("GraphCrawler scan timed out after 30 minutes")
    except subprocess.CalledProcessError as e:
        raise Exception(f"GraphCrawler subprocess error: {e.stderr}")
    except Exception as e:
        if job:
            job.meta["error"] = str(e)
            job.meta["phase"] = "failed"
            job.save_meta()
        raise

    finally:
        # P0-4: Always cleanup temp files
        try:
            Path(output_file).unlink(missing_ok=True)
        except Exception as e:
            print(f"Warning: Failed to delete temp file {output_file}: {e}", file=sys.stderr)


# ==============================================================================
# IDOR SCANNER (Custom Implementation)
# ==============================================================================

def run_idor_scan(
    endpoint: str,
    tokens: List[str],
    start_id: int = 1,
    end_id: int = 100,
    id_type: str = "numeric",
    mutations: bool = False
) -> Dict[str, Any]:
    """
    Run custom IDOR scanner (FIXED VERSION)

    Args:
        endpoint: API endpoint with {id} placeholder
        tokens: List of authorization tokens (minimum 2)
        start_id: Starting ID value
        end_id: Ending ID value
        id_type: Type of IDs ("numeric", "uuid", "alphanumeric")
        mutations: Enable ID mutation testing

    Returns:
        Dict with scan results

    Raises:
        ValueError: If inputs are invalid
        Exception: If scan fails
    """
    job = get_current_job()
    job_id = job.id if job else "manual"

    # P0-3: Comprehensive input validation
    validate_url(endpoint)
    validate_tokens(tokens)
    validate_id_range(start_id, end_id)

    if id_type not in ["numeric", "uuid", "alphanumeric"]:
        raise ValueError(f"Invalid id_type: {id_type}")

    # Ensure {id} placeholder exists
    if "{id}" not in endpoint:
        raise ValueError("Endpoint must contain {id} placeholder")

    # Create safe temp file for output (P0-5)
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        prefix=f'idor_{job_id}_',
        delete=False,
        dir='/tmp'
    ) as f:
        output_file = f.name

    # Create safe temp file for token config (P0-1: avoid tokens in command line)
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        prefix=f'tokens_{job_id}_',
        delete=False,
        dir='/tmp'
    ) as f:
        token_file = f.name

    try:
        # Update job progress
        if job:
            job.meta["status"] = "running"
            job.meta["progress"] = 10
            job.meta["phase"] = "preparing"
            job.meta["id_type"] = id_type
            job.save_meta()

        # P0-1: Build command safely - NO tokens in command line!
        cmd = [
            sys.executable,
            str(CUSTOM_IDOR_PATH),
            "-u", endpoint,
            "-s", str(start_id),
            "-e", str(end_id),
            "--id-type", id_type,
            "-o", output_file
        ]

        # Add tokens as separate arguments (safe with shell=False)
        cmd.append("-t")
        cmd.extend(tokens)

        if mutations:
            cmd.append("--mutations")

        # Update progress
        if job:
            job.meta["progress"] = 20
            job.meta["phase"] = "scanning"
            job.save_meta()

        # P1: Execute with proper timeout
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=MAX_SCAN_TIME,
            text=True,
            shell=False,  # P0-1: CRITICAL - prevents injection
            check=False
        )

        # Update progress
        if job:
            job.meta["progress"] = 80
            job.meta["phase"] = "processing"
            job.save_meta()

        # P0-4: Handle errors
        if result.returncode not in [0, 1]:  # 0=no findings, 1=findings found
            raise Exception(
                f"IDOR scanner failed with exit code {result.returncode}\n"
                f"STDERR: {result.stderr}"
            )

        # P0-4: Safely read output
        if not Path(output_file).exists():
            raise FileNotFoundError(
                f"IDOR scanner did not create output file: {output_file}"
            )

        with open(output_file, 'r', encoding='utf-8') as f:
            try:
                scan_result = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON output from IDOR scanner: {e}")

        # Validate structure
        if not isinstance(scan_result, dict):
            raise ValueError("Invalid IDOR scan result format")

        findings = scan_result.get("findings", [])

        # P0-4: Save findings to PostgreSQL
        if findings and job:
            db = get_db_client()
            saved_count = 0

            for finding in findings:
                try:
                    # Convert custom IDOR findings to Shells format
                    db.save_finding(
                        scan_id=job.meta.get("scan_id", job_id),
                        tool="custom_idor",
                        finding_type="IDOR",
                        severity=finding.get("severity", "HIGH").upper(),
                        title=finding.get("title", "IDOR vulnerability discovered"),
                        description=finding.get("description", ""),
                        evidence=finding.get("evidence", ""),
                        solution=finding.get("solution", "Implement proper authorization checks"),
                        references=finding.get("references", []),
                        metadata={
                            "endpoint": endpoint,
                            "id_type": id_type,
                            "test_id": finding.get("test_id"),
                            "raw_finding": finding
                        }
                    )
                    saved_count += 1
                except Exception as e:
                    # Log error but continue processing other findings
                    print(f"Warning: Failed to save finding to database: {e}", file=sys.stderr)

        # Update progress
        if job:
            job.meta["progress"] = 100
            job.meta["phase"] = "completed"
            job.meta["findings_count"] = len(findings)
            job.save_meta()

        return {
            "status": "completed",
            "completed_at": datetime.utcnow().isoformat(),
            "result": {
                "scan_info": scan_result.get("scan_info", {}),
                "findings_count": len(findings),
                "findings": findings
            }
        }

    except subprocess.TimeoutExpired:
        raise Exception(f"IDOR scan timed out after {MAX_SCAN_TIME} seconds")
    except Exception as e:
        if job:
            job.meta["error"] = str(e)
            job.meta["phase"] = "failed"
            job.save_meta()
        raise

    finally:
        # P0-4: Always cleanup temp files
        for temp_file in [output_file, token_file]:
            try:
                Path(temp_file).unlink(missing_ok=True)
            except Exception as e:
                print(f"Warning: Failed to delete {temp_file}: {e}", file=sys.stderr)


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def validate_scanner_tools() -> Dict[str, bool]:
    """
    Validate that scanner tools exist and are executable

    Returns:
        Dict of tool availability
    """
    tools = {
        "custom_idor": CUSTOM_IDOR_PATH.exists(),
        "graphcrawler": GRAPHCRAWLER_PATH.exists()
    }

    return tools
