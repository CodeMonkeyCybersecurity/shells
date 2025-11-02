# Scanner CLI Interface Analysis

**Generated:** 2025-10-30
**Status:** CRITICAL FINDINGS - Current integration is BROKEN

---

## CRITICAL DISCOVERY: CLI Interface Mismatch

### Problem

The Python worker implementation (`workers/service/tasks.py`) assumes CLI interfaces that **DO NOT EXIST** in the actual scanner tools.

**Impact:** 100% of scans will fail

---

## IDORD (Insecure Direct Object Reference Detector)

### Actual Implementation

**Location:** `workers/tools/idord/Wrapper/IDORD.py`

**CLI Interface:** ❌ **NO COMMAND LINE INTERFACE**

**Actual Usage:**
```python
# IDORD.py is an INTERACTIVE wrapper script that:
# 1. Prompts user for URL via input()
# 2. Runs Django migrations
# 3. Runs Scrapy crawlers
# 4. Runs Attack.py script

# From IDORD.py:
def takeInput():
    os.system(f"clear")
    print("Please Enter the web link: ")
    text = input()  # ❌ INTERACTIVE INPUT - Will hang in background worker
    os.chdir('idord_infograther')
    file= open("link_to_crawl.txt","w")
    file.write(text)
    file.close()
```

**Execution Flow:**
1. Clear screen
2. **Prompt for URL interactively** ← BLOCKS worker
3. Delete SQLite database
4. Run Django migrations
5. Run 2 Scrapy crawlers (railsgoatNotLogin, railsgoatLogin)
6. Run Attack.py to test IDOR
7. Print results

**Dependencies:**
- Django (requires configured Django project)
- Scrapy (web crawling framework)
- SQLite database
- Hardcoded spider names (railsgoat specific)

### What Our Code Assumes (WRONG)

```python
# workers/service/tasks.py - INCORRECT ASSUMPTION
cmd = [
    "python3",
    str(IDORD_PATH),
    "--url", endpoint,        # ❌ NO SUCH FLAG
    "--tokens", ",".join(tokens),  # ❌ NO SUCH FLAG
    "--start", str(start_id),      # ❌ NO SUCH FLAG
    "--end", str(end_id),          # ❌ NO SUCH FLAG
    "--id-type", id_type,          # ❌ NO SUCH FLAG
    "--output", output_file        # ❌ NO SUCH FLAG
]
```

**Reality:** IDORD has **ZERO command line flags**

---

## GraphCrawler (GraphQL Schema Crawler)

### Actual Implementation

**Location:** `workers/tools/graphcrawler/graphCrawler.py`

**CLI Interface:** ✅ **HAS ARGPARSE** but different from what we use

**Actual Flags:**
```python
parser.add_argument("-u", "--url",
                    dest="url",
                    help="The Graphql endpoint URL.",
                    action='store',
                    required=True)

parser.add_argument("-o", "--output",
                    dest="output_path",
                    help="Saves schema to this filename + the url.",
                    action='store')

parser.add_argument("-e", "--explore",
                    dest="explore",
                    help="Explore mode",
                    action='store_true')

parser.add_argument("-i", "--inputFile",
                    dest="inputFile",
                    help="Add a file with endpoints",
                    action='store')

parser.add_argument("-s", "--schemaFile",
                    dest="schemaFile",
                    help="Add a file containing the Graphql schema")

parser.add_argument("-a", "--headers",
                    nargs='+',
                    dest="headers",
                    help="Adds specified headers to the request",
                    action='store')
```

**Correct Usage:**
```bash
# Basic scan
python3 graphCrawler.py -u https://api.example.com/graphql -o output.json

# With authentication
python3 graphCrawler.py -u https://api.example.com/graphql -a "Authorization: Bearer token" -o output.json
```

### What Our Code Assumes (PARTIALLY WRONG)

```python
# workers/service/tasks.py - MOSTLY CORRECT
cmd = [
    "python3",
    str(GRAPHCRAWLER_PATH),
    "-u", endpoint,              # ✅ CORRECT
    "-o", output_file            # ✅ CORRECT
]

if auth_header:
    cmd.extend(["-a", auth_header])  # ⚠️ PARTIALLY CORRECT
```

**Issue:** GraphCrawler expects headers in format: `-a "Key: Value" "Key2: Value2"`
Our code passes: `-a "Bearer token123"` (missing header name)

---

## CRITICAL ISSUES SUMMARY

### IDORD Integration: COMPLETELY BROKEN ❌

1. **No CLI interface**: IDORD.py is interactive, will hang waiting for input
2. **Wrong execution model**: Expects user to run interactively, not as subprocess
3. **Hardcoded for RailsGoat**: Spider names are hardcoded for specific test app
4. **Django dependency**: Requires Django project setup (migrations, database)
5. **No token support**: No concept of multi-user token testing
6. **No ID range support**: Crawls entire site, doesn't test specific ID ranges

**Verdict:** IDORD is **NOT SUITABLE** for API-based IDOR testing as implemented

### GraphCrawler Integration: MOSTLY CORRECT ✅

1. **CLI exists**: Has proper argparse interface
2. **URL flag correct**: `-u` flag works
3. **Output flag correct**: `-o` flag works
4. **Headers format issue**: `-a` flag needs "Header: Value" format, not just value

**Verdict:** GraphCrawler is **USABLE** with minor fixes

---

## RECOMMENDED SOLUTIONS

### Option 1: Write Custom IDOR Scanner (RECOMMENDED)

**Rationale:** IDORD is not fit for purpose as a CLI tool

**Implementation:** Create `workers/tools/custom_idor.py`

```python
#!/usr/bin/env python3
"""
Custom IDOR Scanner for Shells
Designed for CLI/API usage, not interactive
"""
import argparse
import json
import requests
from typing import List, Dict

def test_idor(endpoint: str, tokens: List[str], start_id: int, end_id: int, id_type: str) -> List[Dict]:
    """
    Test for IDOR vulnerabilities

    Args:
        endpoint: API endpoint with {id} placeholder
        tokens: List of bearer tokens to test
        start_id: Starting ID value
        end_id: Ending ID value
        id_type: Type of IDs (numeric, uuid, alphanumeric)

    Returns:
        List of findings
    """
    findings = []

    for user_id in generate_ids(start_id, end_id, id_type):
        url = endpoint.replace("{id}", str(user_id))

        # Test access with each token
        responses = {}
        for i, token in enumerate(tokens):
            try:
                resp = requests.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
                responses[i] = {
                    "status": resp.status_code,
                    "body": resp.text,
                    "token": f"token_{i}"
                }
            except requests.RequestException as e:
                responses[i] = {"error": str(e)}

        # Analyze for IDOR
        if check_idor(responses):
            findings.append({
                "type": "IDOR",
                "url": url,
                "user_id": user_id,
                "severity": "HIGH",
                "description": f"User B can access User A's resource at {url}",
                "evidence": responses
            })

    return findings

def generate_ids(start: int, end: int, id_type: str):
    """Generate IDs based on type"""
    if id_type == "numeric":
        return range(start, end + 1)
    elif id_type == "uuid":
        # Generate UUIDs
        import uuid
        return [str(uuid.UUID(int=i)) for i in range(start, end + 1)]
    elif id_type == "alphanumeric":
        # Generate alphanumeric IDs
        return [f"user_{i}" for i in range(start, end + 1)]

def check_idor(responses: Dict) -> bool:
    """Check if responses indicate IDOR vulnerability"""
    # If multiple users get same successful response, it's IDOR
    successful = [r for r in responses.values() if r.get("status") == 200]
    if len(successful) >= 2:
        # Check if responses are identical
        bodies = [r.get("body") for r in successful]
        return len(set(bodies)) == 1
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDOR vulnerability scanner")
    parser.add_argument("-u", "--url", required=True, help="API endpoint with {id}")
    parser.add_argument("-t", "--tokens", required=True, nargs='+', help="Bearer tokens")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start ID")
    parser.add_argument("-e", "--end", type=int, default=100, help="End ID")
    parser.add_argument("--id-type", choices=["numeric", "uuid", "alphanumeric"], default="numeric")
    parser.add_argument("-o", "--output", help="Output JSON file")

    args = parser.parse_args()

    findings = test_idor(args.url, args.tokens, args.start, args.end, args.id_type)

    result = {
        "findings_count": len(findings),
        "findings": findings
    }

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))
```

**Benefits:**
- ✅ Proper CLI interface
- ✅ Non-interactive (works in background)
- ✅ Supports tokens, ID ranges, ID types
- ✅ JSON output
- ✅ No Django/Scrapy dependencies

---

### Option 2: Wrapper Script for IDORD

Create `workers/tools/idord_wrapper.py` to adapt IDORD's interface

**Problems:**
- IDORD is fundamentally designed for interactive web crawling
- Not designed for API testing with specific ID ranges
- Would require extensive modifications

**Verdict:** Not worth the effort, Option 1 is better

---

### Option 3: Fix GraphCrawler Headers

**File:** `workers/service/tasks.py`

```python
def run_graphql_scan(endpoint: str, auth_header: Optional[str] = None, output_file: Optional[str] = None):
    cmd = [
        "python3",
        str(GRAPHCRAWLER_PATH),
        "-u", endpoint,
        "-o", output_file
    ]

    if auth_header:
        # GraphCrawler expects: -a "Header: Value"
        # If auth_header is "Bearer token123", convert to "Authorization: Bearer token123"
        if not ":" in auth_header:
            # Assume it's a bearer token
            header_value = f"Authorization: {auth_header}"
        else:
            # Already in correct format
            header_value = auth_header

        cmd.extend(["-a", header_value])

    # ... rest of function
```

---

## ACTION ITEMS (Priority Order)

### P0-CRITICAL (Week 1, Day 1-2)

1. **Create custom IDOR scanner** (`workers/tools/custom_idor.py`)
   - Implement Option 1 above
   - Add proper CLI interface
   - Add unit tests

2. **Fix GraphCrawler headers** (`workers/service/tasks.py`)
   - Implement Option 3 above
   - Convert bearer tokens to proper header format

3. **Update tasks.py to use correct CLIs**
   - Point IDORD integration to custom_idor.py
   - Fix GraphCrawler header format

4. **Test end-to-end**
   - Verify GraphCrawler works
   - Verify custom IDOR scanner works
   - Add integration tests

### After Fixing (Week 1, Day 3-5)

5. Continue with input validation (Phase 1.2)
6. Fix command injection (Phase 1.3)
7. Add PostgreSQL integration (Phase 1.4)

---

## CONCLUSION

**Current Status:** Python worker integration is **FUNDAMENTALLY BROKEN** ❌

**Root Cause:** Incorrect assumptions about scanner CLI interfaces

**Fix Required:** Custom IDOR scanner + GraphCrawler header fix

**Timeline:** 2 days to get working scanner integration

**Impact:** Blocks all Python worker testing until fixed
