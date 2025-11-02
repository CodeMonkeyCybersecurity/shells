"""
RQ Task definitions for scanner tools

These functions are executed by RQ workers in the background.
They should be importable and do NOT use FastAPI dependencies.
"""
import asyncio
import json
import os
from pathlib import Path
from typing import List, Optional
from datetime import datetime
import subprocess

from rq import get_current_job

# Paths to scanner tools
TOOLS_DIR = Path(__file__).parent.parent / "tools"
CUSTOM_IDOR_PATH = TOOLS_DIR / "custom_idor.py"  # Custom IDOR scanner (CLI-friendly)
GRAPHCRAWLER_PATH = TOOLS_DIR / "graphcrawler" / "graphCrawler.py"


def run_graphql_scan(endpoint: str, auth_header: Optional[str] = None, output_file: Optional[str] = None):
    """
    Run GraphCrawler scanner (executed by RQ worker)

    Args:
        endpoint: GraphQL endpoint URL
        auth_header: Optional authorization header
        output_file: Optional output file path
    """
    job = get_current_job()
    job_id = job.id

    output_file = output_file or f"/tmp/graphql_{job_id}.json"

    # Update job progress
    job.meta["status"] = "running"
    job.meta["progress"] = 10
    job.save_meta()

    try:
        cmd = [
            "python3",
            str(GRAPHCRAWLER_PATH),
            "-u", endpoint,
            "-o", output_file
        ]

        if auth_header:
            cmd.extend(["-a", auth_header])

        # Run scanner
        job.meta["progress"] = 30
        job.save_meta()

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,  # 30 minute timeout
            text=True
        )

        job.meta["progress"] = 80
        job.save_meta()

        # Parse results
        if result.returncode == 0:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    scan_result = json.load(f)
            else:
                scan_result = {"raw_output": result.stdout}

            job.meta["progress"] = 100
            job.meta["findings_count"] = len(scan_result.get("findings", []))
            job.save_meta()

            return {
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "result": scan_result
            }
        else:
            raise Exception(f"GraphCrawler failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        raise Exception("GraphCrawler scan timed out after 30 minutes")
    except Exception as e:
        job.meta["error"] = str(e)
        job.save_meta()
        raise


def run_idord_scan(
    endpoint: str,
    tokens: List[str],
    start_id: int = 1,
    end_id: int = 100,
    id_type: str = "numeric"
):
    """
    Run IDORD scanner (executed by RQ worker)

    Args:
        endpoint: API endpoint with {id} placeholder
        tokens: List of authorization tokens to test
        start_id: Starting ID value
        end_id: Ending ID value
        id_type: Type of IDs to test ("numeric", "uuid", "alphanumeric")
    """
    job = get_current_job()
    job_id = job.id

    # Update job progress
    job.meta["status"] = "running"
    job.meta["progress"] = 10
    job.meta["id_type"] = id_type
    job.save_meta()

    try:
        # Prepare command for IDORD tool
        cmd = [
            "python3",
            str(IDORD_PATH),
            "--url", endpoint,
            "--tokens", ",".join(tokens),
            "--start", str(start_id),
            "--end", str(end_id),
            "--id-type", id_type,
            "--output", f"/tmp/idord_{job_id}.json"
        ]

        job.meta["progress"] = 20
        job.save_meta()

        # Run IDORD scanner
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3600,  # 60 minute timeout
            text=True
        )

        job.meta["progress"] = 80
        job.save_meta()

        # Parse results
        findings = []
        output_file = f"/tmp/idord_{job_id}.json"

        if result.returncode == 0:
            # Try to parse IDORD output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    findings = json.load(f).get("findings", [])
            else:
                # Parse stdout for findings if no output file
                findings = parse_idord_output(result.stdout)

            job.meta["progress"] = 100
            job.meta["findings_count"] = len(findings)
            job.save_meta()

            return {
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "result": {
                    "findings_count": len(findings),
                    "findings": findings,
                    "id_type_tested": id_type,
                    "range_tested": f"{start_id}-{end_id}"
                }
            }
        else:
            raise Exception(f"IDORD scan failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        raise Exception("IDORD scan timed out after 60 minutes")
    except Exception as e:
        job.meta["error"] = str(e)
        job.save_meta()
        raise


def parse_idord_output(stdout: str) -> List[dict]:
    """
    Parse IDORD stdout output for findings

    Args:
        stdout: IDORD stdout output

    Returns:
        List of finding dictionaries
    """
    findings = []

    # Parse IDORD output format (customize based on actual IDORD output)
    for line in stdout.split("\n"):
        if "IDOR" in line and "FOUND" in line:
            # Example parsing logic - adjust based on actual IDORD output
            findings.append({
                "type": "IDOR",
                "description": line.strip(),
                "severity": "HIGH"
            })

    return findings
