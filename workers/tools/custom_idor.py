#!/usr/bin/env python3
"""
Custom IDOR Scanner for Shells Security Scanner
Designed for CLI/API usage with proper non-interactive interface

IDOR (Insecure Direct Object Reference) testing with:
- Numeric ID testing (1, 2, 3, ...)
- UUID testing (550e8400-e29b-41d4-a716-446655440000)
- Alphanumeric ID testing (user_42, abc123)
- Multi-user token comparison
- ID mutation testing (±1, ±10, *2, /2)

Usage:
    python3 custom_idor.py -u "https://api.example.com/users/{id}" \\
        -t "Bearer token1" "Bearer token2" \\
        -s 1 -e 100 --id-type numeric -o results.json
"""
import argparse
import json
import sys
import uuid as uuid_module
from typing import List, Dict, Optional, Any
from datetime import datetime
from urllib.parse import urlparse
import hashlib

try:
    import requests
except ImportError:
    print("Error: requests library required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)


class IDORScanner:
    """IDOR vulnerability scanner"""

    def __init__(self, endpoint: str, tokens: List[str], start_id: int, end_id: int,
                 id_type: str = "numeric", timeout: int = 5, mutations: bool = False):
        self.endpoint = endpoint
        self.tokens = tokens
        self.start_id = start_id
        self.end_id = end_id
        self.id_type = id_type
        self.timeout = timeout
        self.mutations = mutations
        self.findings = []

        # Validate inputs
        self._validate()

    def _validate(self):
        """Validate scanner inputs"""
        if "{id}" not in self.endpoint:
            raise ValueError("Endpoint must contain {id} placeholder")

        if not self.tokens or len(self.tokens) < 2:
            raise ValueError("At least 2 tokens required for IDOR testing")

        if self.start_id < 0 or self.end_id < 0:
            raise ValueError("ID range must be positive")

        if self.start_id > self.end_id:
            raise ValueError("start_id must be <= end_id")

        # Validate URL format
        try:
            result = urlparse(self.endpoint)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format")
        except Exception as e:
            raise ValueError(f"Invalid endpoint URL: {e}")

    def scan(self) -> Dict[str, Any]:
        """Run IDOR scan and return results"""
        print(f"[*] Starting IDOR scan: {self.endpoint}", file=sys.stderr)
        print(f"[*] ID range: {self.start_id}-{self.end_id} ({self.id_type})", file=sys.stderr)
        print(f"[*] Testing with {len(self.tokens)} tokens", file=sys.stderr)

        ids_to_test = self._generate_ids()
        total_ids = len(ids_to_test)

        print(f"[*] Total IDs to test: {total_ids}", file=sys.stderr)

        for i, test_id in enumerate(ids_to_test, 1):
            if i % 10 == 0:
                print(f"[*] Progress: {i}/{total_ids} IDs tested", file=sys.stderr)

            self._test_id(test_id)

        print(f"[+] Scan complete: {len(self.findings)} findings", file=sys.stderr)

        return {
            "scan_info": {
                "endpoint": self.endpoint,
                "id_type": self.id_type,
                "range_tested": f"{self.start_id}-{self.end_id}",
                "tokens_tested": len(self.tokens),
                "mutations_enabled": self.mutations,
                "timestamp": datetime.utcnow().isoformat()
            },
            "findings_count": len(self.findings),
            "findings": self.findings
        }

    def _generate_ids(self) -> List[str]:
        """Generate IDs to test based on type"""
        ids = []

        if self.id_type == "numeric":
            ids = list(range(self.start_id, self.end_id + 1))

            if self.mutations:
                # Add ID mutations: ±1, ±10, *2, /2
                mutations = []
                for id_val in ids:
                    mutations.extend([
                        id_val - 1,
                        id_val + 1,
                        id_val - 10,
                        id_val + 10,
                        id_val * 2,
                        id_val // 2 if id_val > 1 else id_val
                    ])
                ids.extend([m for m in mutations if m > 0])
                ids = sorted(set(ids))  # Remove duplicates

        elif self.id_type == "uuid":
            # Generate UUIDs deterministically
            for i in range(self.start_id, self.end_id + 1):
                # Generate deterministic UUID from integer
                namespace = uuid_module.UUID('00000000-0000-0000-0000-000000000000')
                test_uuid = uuid_module.uuid5(namespace, str(i))
                ids.append(str(test_uuid))

        elif self.id_type == "alphanumeric":
            # Generate alphanumeric IDs
            for i in range(self.start_id, self.end_id + 1):
                ids.append(f"user_{i}")
                if self.mutations:
                    ids.extend([
                        f"user{i}",      # Without underscore
                        f"USER_{i}",     # Uppercase
                        f"u{i}",         # Short form
                        f"{i}_user",     # Reversed
                    ])

        return [str(id_val) for id_val in ids]

    def _test_id(self, test_id: str):
        """Test a single ID with all tokens"""
        url = self.endpoint.replace("{id}", test_id)

        responses = {}
        for idx, token in enumerate(self.tokens):
            try:
                headers = {"Authorization": token} if token else {}

                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )

                responses[idx] = {
                    "token_index": idx,
                    "status_code": resp.status_code,
                    "body": resp.text,
                    "body_hash": hashlib.sha256(resp.text.encode()).hexdigest(),
                    "content_length": len(resp.text),
                    "headers": dict(resp.headers)
                }

            except requests.exceptions.Timeout:
                responses[idx] = {"error": "timeout"}
            except requests.exceptions.RequestException as e:
                responses[idx] = {"error": str(e)}

        # Analyze responses for IDOR
        finding = self._analyze_responses(test_id, url, responses)
        if finding:
            self.findings.append(finding)

    def _analyze_responses(self, test_id: str, url: str, responses: Dict) -> Optional[Dict]:
        """Analyze responses to detect IDOR vulnerability"""

        # Filter successful responses (2xx status codes)
        successful = {
            idx: resp for idx, resp in responses.items()
            if isinstance(resp, dict) and resp.get("status_code", 0) // 100 == 2
        }

        if len(successful) < 2:
            # Need at least 2 successful responses to compare
            return None

        # Check if different users get identical responses (IDOR indicator)
        body_hashes = [resp["body_hash"] for resp in successful.values()]

        if len(set(body_hashes)) == 1:
            # All successful responses are identical - likely IDOR
            token_indices = list(successful.keys())

            # Calculate severity
            severity = self._calculate_severity(successful)

            return {
                "type": "IDOR",
                "severity": severity,
                "id_tested": test_id,
                "url": url,
                "title": f"IDOR Vulnerability: Multiple users access same resource",
                "description": (
                    f"Resource at {url} is accessible by multiple users with different "
                    f"authorization tokens. Tokens {token_indices} all received identical "
                    f"responses, indicating insecure direct object reference."
                ),
                "evidence": {
                    "affected_tokens": token_indices,
                    "response_status": successful[token_indices[0]]["status_code"],
                    "response_hash": body_hashes[0],
                    "content_length": successful[token_indices[0]]["content_length"],
                    "all_responses": successful
                },
                "cvss_score": self._calculate_cvss(severity),
                "remediation": (
                    "Implement proper authorization checks to ensure users can only "
                    "access their own resources. Validate that the authenticated user "
                    "has permission to access the requested resource ID."
                )
            }

        return None

    def _calculate_severity(self, successful_responses: Dict) -> str:
        """Calculate severity based on response characteristics"""
        # Check if responses contain sensitive data indicators
        sample_body = list(successful_responses.values())[0]["body"].lower()

        sensitive_keywords = [
            "password", "ssn", "social security", "credit card",
            "email", "phone", "address", "dob", "date of birth"
        ]

        if any(keyword in sample_body for keyword in sensitive_keywords):
            return "CRITICAL"

        # Check content length (larger responses more likely to contain sensitive data)
        content_length = list(successful_responses.values())[0]["content_length"]
        if content_length > 1000:
            return "HIGH"
        elif content_length > 100:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        severity_scores = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.5,
            "LOW": 3.5
        }
        return severity_scores.get(severity, 5.0)


def main():
    parser = argparse.ArgumentParser(
        description="IDOR vulnerability scanner for API endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test numeric IDs 1-100
  %(prog)s -u "https://api.example.com/users/{id}" -t "Bearer token1" "Bearer token2" -s 1 -e 100

  # Test UUIDs with mutations
  %(prog)s -u "https://api.example.com/api/v1/profiles/{id}" \\
      -t "Bearer token1" "Bearer token2" "Bearer token3" \\
      -s 1 -e 50 --id-type uuid --mutations -o results.json

  # Test alphanumeric IDs
  %(prog)s -u "https://api.example.com/documents/{id}" \\
      -t "token1" "token2" -s 1 -e 100 --id-type alphanumeric
        """
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="API endpoint URL with {id} placeholder (e.g., 'https://api.example.com/users/{id}')"
    )
    parser.add_argument(
        "-t", "--tokens",
        required=True,
        nargs='+',
        help="Authorization tokens to test (minimum 2 required)"
    )
    parser.add_argument(
        "-s", "--start",
        type=int,
        default=1,
        help="Starting ID value (default: 1)"
    )
    parser.add_argument(
        "-e", "--end",
        type=int,
        default=100,
        help="Ending ID value (default: 100)"
    )
    parser.add_argument(
        "--id-type",
        choices=["numeric", "uuid", "alphanumeric"],
        default="numeric",
        help="Type of IDs to test (default: numeric)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="HTTP request timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--mutations",
        action="store_true",
        help="Enable ID mutation testing (±1, ±10, *2, /2)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file path (default: stdout)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    try:
        scanner = IDORScanner(
            endpoint=args.url,
            tokens=args.tokens,
            start_id=args.start,
            end_id=args.end,
            id_type=args.id_type,
            timeout=args.timeout,
            mutations=args.mutations
        )

        results = scanner.scan()

        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results saved to {args.output}", file=sys.stderr)
        else:
            print(json.dumps(results, indent=2))

        # Exit code based on findings
        sys.exit(0 if results["findings_count"] == 0 else 1)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
