"""
Shells Worker Service - FastAPI wrapper for Python bug bounty tools
Wraps GraphCrawler and IDORD (AyemunHossain/IDORD) with a REST API

IDORD: https://github.com/AyemunHossain/IDORD
GraphCrawler: https://github.com/gsmith257-cyber/GraphCrawler

This version uses Redis Queue (RQ) for persistent job storage instead of in-memory dict.
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, validator
import redis
from rq import Queue
from rq.job import Job

# Initialize Redis connection
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_conn = redis.from_url(REDIS_URL)
job_queue = Queue("shells-scanners", connection=redis_conn)

# Paths to scanner tools
TOOLS_DIR = Path(__file__).parent.parent / "tools"
IDORD_PATH = TOOLS_DIR / "idord" / "Wrapper" / "IDORD.py"
GRAPHCRAWLER_PATH = TOOLS_DIR / "graphcrawler" / "graphCrawler.py"

app = FastAPI(
    title="Shells Worker Service",
    description="Python bug bounty tools wrapped with REST API (Redis Queue)",
    version="2.0.0"
)


# Pydantic Models with Validation
class GraphQLScanRequest(BaseModel):
    endpoint: str
    auth_header: Optional[str] = None
    output_file: Optional[str] = None

    @validator('endpoint')
    def validate_endpoint(cls, v):
        from urllib.parse import urlparse
        if not v:
            raise ValueError("Endpoint URL required")

        # Validate URL structure
        try:
            result = urlparse(v)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL structure")
            if result.scheme not in ['http', 'https']:
                raise ValueError("Only HTTP/HTTPS protocols allowed")
        except Exception as e:
            raise ValueError(f"Invalid endpoint URL: {e}")

        # Check for dangerous characters
        dangerous = [';', '&', '|', '`', '$', '\n', '\r']
        if any(c in v for c in dangerous):
            raise ValueError("URL contains dangerous characters")

        return v

    @validator('auth_header')
    def validate_auth_header(cls, v):
        if v and len(v) > 2000:
            raise ValueError("Auth header too long (max 2000 characters)")
        return v


class IDORScanRequest(BaseModel):
    endpoint: str
    tokens: List[str]
    start_id: int = 1
    end_id: int = 100
    id_type: str = "numeric"  # "numeric", "uuid", "alphanumeric"
    mutations: bool = False

    @validator('endpoint')
    def validate_endpoint(cls, v):
        from urllib.parse import urlparse
        if not v:
            raise ValueError("Endpoint URL required")

        # Ensure {id} placeholder exists
        if '{id}' not in v:
            raise ValueError("Endpoint must contain {id} placeholder")

        # Validate URL structure
        try:
            # Replace {id} temporarily for URL validation
            test_url = v.replace('{id}', '1')
            result = urlparse(test_url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL structure")
            if result.scheme not in ['http', 'https']:
                raise ValueError("Only HTTP/HTTPS protocols allowed")
        except Exception as e:
            raise ValueError(f"Invalid endpoint URL: {e}")

        # Check for dangerous characters
        dangerous = [';', '&', '|', '`', '$', '\n', '\r']
        if any(c in v for c in dangerous):
            raise ValueError("URL contains dangerous characters")

        return v

    @validator('tokens')
    def validate_tokens(cls, v):
        if not v or len(v) < 2:
            raise ValueError("At least 2 tokens required for IDOR testing")
        if len(v) > 10:
            raise ValueError("Maximum 10 tokens allowed")

        # Check each token
        dangerous = [';', '&', '|', '`', '$', '\n', '\r', '\x00']
        for i, token in enumerate(v):
            if not token.strip():
                raise ValueError(f"Token {i} is empty")
            if any(c in token for c in dangerous):
                raise ValueError(f"Token {i} contains dangerous characters")
            if len(token) > 2000:
                raise ValueError(f"Token {i} too long (max 2000 characters)")

        return v

    @validator('start_id', 'end_id')
    def validate_id_values(cls, v):
        if v < 0:
            raise ValueError("ID must be positive")
        if v > 100000:
            raise ValueError("ID too large (max 100000)")
        return v

    @validator('end_id')
    def validate_id_range(cls, v, values):
        start = values.get('start_id', 1)
        if v < start:
            raise ValueError("end_id must be >= start_id")
        if (v - start) > 100000:
            raise ValueError("ID range too large (max 100000)")
        return v

    @validator('id_type')
    def validate_id_type(cls, v):
        if v not in ['numeric', 'uuid', 'alphanumeric']:
            raise ValueError("Invalid id_type (must be numeric, uuid, or alphanumeric)")
        return v


class JobStatus(BaseModel):
    job_id: str
    status: str  # queued, started, finished, failed
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    meta: Optional[Dict] = None


# API Endpoints
@app.get("/")
def root():
    return {
        "service": "Shells Worker Service",
        "version": "2.0.0",
        "storage": "Redis Queue (RQ)",
        "tools": {
            "graphcrawler": "https://github.com/gsmith257-cyber/GraphCrawler",
            "idord": "https://github.com/AyemunHossain/IDORD"
        },
        "endpoints": {
            "health": "/health",
            "graphql_scan": "/graphql/scan",
            "idor_scan": "/idor/scan",
            "job_status": "/jobs/{job_id}",
            "job_stream": "/jobs/{job_id}/stream",
            "list_jobs": "/jobs"
        }
    }


@app.get("/health")
def health():
    """Health check endpoint"""
    try:
        # Check Redis connection
        redis_conn.ping()
        redis_status = "healthy"
    except Exception as e:
        redis_status = f"unhealthy: {str(e)}"

    # Check if scanner tools exist
    idord_exists = IDORD_PATH.exists()
    graphcrawler_exists = GRAPHCRAWLER_PATH.exists()

    return {
        "status": "healthy" if redis_status == "healthy" else "degraded",
        "service": "Shells Worker Service",
        "version": "2.0.0",
        "redis": redis_status,
        "tools": {
            "idord": "available" if idord_exists else "missing",
            "graphcrawler": "available" if graphcrawler_exists else "missing"
        }
    }


@app.post("/graphql/scan", response_model=JobStatus)
async def scan_graphql(request: GraphQLScanRequest):
    """
    Scan a GraphQL endpoint using GraphCrawler
    Returns job_id immediately, job runs in background via RQ worker
    """
    # Enqueue job to Redis Queue
    job = job_queue.enqueue(
        "workers.service.tasks.run_graphql_scan",
        endpoint=request.endpoint,
        auth_header=request.auth_header,
        output_file=request.output_file,
        job_timeout="30m"
    )

    return JobStatus(
        job_id=job.id,
        status=job.get_status(),
        created_at=datetime.utcnow().isoformat()
    )


@app.post("/idor/scan", response_model=JobStatus)
async def scan_idor(request: IDORScanRequest):
    """
    Scan for IDOR vulnerabilities using IDORD tool
    Supports numeric, UUID, and alphanumeric ID types
    """
    # Enqueue job to Redis Queue
    job = job_queue.enqueue(
        "workers.service.tasks.run_idord_scan",
        endpoint=request.endpoint,
        tokens=request.tokens,
        start_id=request.start_id,
        end_id=request.end_id,
        id_type=request.id_type,
        job_timeout="60m"
    )

    return JobStatus(
        job_id=job.id,
        status=job.get_status(),
        created_at=datetime.utcnow().isoformat()
    )


@app.get("/jobs/{job_id}", response_model=JobStatus)
def get_job_status(job_id: str):
    """
    Get status of a scanning job
    """
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatus(
        job_id=job.id,
        status=job.get_status(),
        created_at=job.created_at.isoformat() if job.created_at else None,
        completed_at=job.ended_at.isoformat() if job.ended_at else None,
        result=job.result,
        error=str(job.exc_info) if job.is_failed else None,
        meta=job.meta
    )


@app.get("/jobs/{job_id}/stream")
async def stream_job_results(job_id: str):
    """
    Stream job status updates via Server-Sent Events (SSE)
    Client receives real-time progress updates
    """
    async def event_generator():
        try:
            job = Job.fetch(job_id, connection=redis_conn)
        except Exception:
            yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
            return

        while True:
            # Refresh job status
            job.refresh()

            # Send status update
            data = {
                "job_id": job.id,
                "status": job.get_status(),
                "progress": job.meta.get("progress", 0),
                "findings_count": job.meta.get("findings_count", 0),
                "result": job.result if job.is_finished else None,
                "error": str(job.exc_info) if job.is_failed else None
            }

            yield f"data: {json.dumps(data)}\n\n"

            # Stop streaming if job finished or failed
            if job.is_finished or job.is_failed:
                break

            # Wait 1 second before next update
            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )


@app.get("/jobs", response_model=List[JobStatus])
def list_jobs(status: Optional[str] = None, limit: int = 100):
    """
    List all jobs (optionally filtered by status)
    """
    # Get job registry based on status
    if status == "queued":
        from rq.registry import StartedJobRegistry
        registry = job_queue.started_job_registry
    elif status == "finished":
        from rq.registry import FinishedJobRegistry
        registry = FinishedJobRegistry(queue=job_queue)
    elif status == "failed":
        from rq.registry import FailedJobRegistry
        registry = FailedJobRegistry(queue=job_queue)
    else:
        # Return jobs from all registries
        job_ids = job_queue.job_ids[:limit]
        jobs = [Job.fetch(jid, connection=redis_conn) for jid in job_ids]
        return [
            JobStatus(
                job_id=job.id,
                status=job.get_status(),
                created_at=job.created_at.isoformat() if job.created_at else None,
                meta=job.meta
            )
            for job in jobs
        ]

    # Get jobs from specific registry
    job_ids = registry.get_job_ids()[:limit]
    jobs = [Job.fetch(jid, connection=redis_conn) for jid in job_ids]

    return [
        JobStatus(
            job_id=job.id,
            status=job.get_status(),
            created_at=job.created_at.isoformat() if job.created_at else None,
            completed_at=job.ended_at.isoformat() if job.ended_at else None,
            meta=job.meta
        )
        for job in jobs
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
