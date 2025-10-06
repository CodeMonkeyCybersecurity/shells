"""
Shells Worker Service - FastAPI wrapper for Python bug bounty tools
Wraps GraphCrawler and IDORD (AyemunHossain/IDORD) with a REST API

IDORD: https://github.com/AyemunHossain/IDORD
GraphCrawler: https://github.com/gsmith257-cyber/GraphCrawler
"""
import subprocess
import json
import uuid
import os
from datetime import datetime
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import asyncio

app = FastAPI(
    title="Shells Worker Service",
    description="Python bug bounty tools wrapped with REST API",
    version="1.0.0"
)

# Job storage (in-memory for now, use Redis in production)
jobs = {}

class GraphQLScanRequest(BaseModel):
    endpoint: str
    auth_header: Optional[str] = None
    output_file: Optional[str] = None

class IDORScanRequest(BaseModel):
    endpoint: str
    tokens: List[str]
    start_id: int = 1
    end_id: int = 100

class JobStatus(BaseModel):
    job_id: str
    status: str  # pending, running, completed, failed
    created_at: str
    completed_at: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None

@app.get("/")
def root():
    return {
        "service": "Shells Worker Service",
        "version": "1.0.0",
        "tools": {
            "graphcrawler": "https://github.com/gsmith257-cyber/GraphCrawler",
            "idord": "https://github.com/AyemunHossain/IDORD"
        },
        "endpoints": {
            "health": "/health",
            "graphql_scan": "/graphql/scan",
            "idor_scan": "/idor/scan",
            "job_status": "/jobs/{job_id}",
            "list_jobs": "/jobs"
        }
    }

@app.get("/health")
def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Shells Worker Service",
        "version": "1.0.0"
    }

@app.post("/graphql/scan", response_model=JobStatus)
async def scan_graphql(request: GraphQLScanRequest, background_tasks: BackgroundTasks):
    """
    Scan a GraphQL endpoint using GraphCrawler
    """
    job_id = str(uuid.uuid4())
    output_file = request.output_file or f"/tmp/graphql_{job_id}.json"

    job = {
        "job_id": job_id,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "type": "graphql",
        "request": request.dict()
    }
    jobs[job_id] = job

    # Run in background
    background_tasks.add_task(run_graphql_scan, job_id, request.endpoint, request.auth_header, output_file)

    return JobStatus(**job)

@app.post("/idor/scan", response_model=JobStatus)
async def scan_idor(request: IDORScanRequest, background_tasks: BackgroundTasks):
    """
    Scan for IDOR vulnerabilities using IDORD
    """
    job_id = str(uuid.uuid4())

    job = {
        "job_id": job_id,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "type": "idor",
        "request": request.dict()
    }
    jobs[job_id] = job

    # Run in background
    background_tasks.add_task(run_idor_scan, job_id, request.endpoint, request.tokens, request.start_id, request.end_id)

    return JobStatus(**job)

@app.get("/jobs/{job_id}", response_model=JobStatus)
def get_job_status(job_id: str):
    """
    Get status of a scanning job
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatus(**jobs[job_id])

@app.get("/jobs", response_model=List[JobStatus])
def list_jobs():
    """
    List all jobs
    """
    return [JobStatus(**job) for job in jobs.values()]

async def run_graphql_scan(job_id: str, endpoint: str, auth_header: Optional[str], output_file: str):
    """
    Run GraphCrawler in background
    """
    jobs[job_id]["status"] = "running"

    try:
        cmd = [
            "python3",
            "../GraphCrawler/graphCrawler.py",
            "-u", endpoint,
            "-o", output_file
        ]

        if auth_header:
            cmd.extend(["-a", auth_header])

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            # Read results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    result = json.load(f)
            else:
                result = {"raw_output": stdout.decode()}

            jobs[job_id]["status"] = "completed"
            jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            jobs[job_id]["result"] = result
        else:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = stderr.decode()

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)

async def run_idor_scan(job_id: str, endpoint: str, tokens: List[str], start_id: int, end_id: int):
    """
    Run IDOR scanner in background
    """
    jobs[job_id]["status"] = "running"

    try:
        # Custom IDOR scanning logic
        findings = []

        for user_id in range(start_id, end_id + 1):
            url = endpoint.replace("{id}", str(user_id))

            # Test with each token
            for token_a in tokens:
                for token_b in tokens:
                    if token_a == token_b:
                        continue

                    # Simulate IDOR test (in production, use actual HTTP requests)
                    import requests

                    try:
                        resp_a = requests.get(url, headers={"Authorization": f"Bearer {token_a}"}, timeout=5)
                        resp_b = requests.get(url, headers={"Authorization": f"Bearer {token_b}"}, timeout=5)

                        if resp_a.status_code == 200 and resp_b.status_code == 200:
                            if resp_a.text == resp_b.text:
                                findings.append({
                                    "type": "IDOR",
                                    "url": url,
                                    "user_id": user_id,
                                    "severity": "HIGH",
                                    "description": f"User B can access User A's resource at {url}"
                                })
                    except:
                        pass

        jobs[job_id]["status"] = "completed"
        jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        jobs[job_id]["result"] = {
            "findings_count": len(findings),
            "findings": findings
        }

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
