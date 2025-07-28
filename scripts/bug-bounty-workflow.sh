#!/bin/bash
# Bug Bounty Optimized Workflow for High-Value Vulnerability Discovery
# Focus: Auth Bypass, API Security, Business Logic, Request Smuggling, SSRF, Access Control

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SHELLS_BIN="${SHELLS_BIN:-./shells}"
CONFIG_FILE="${CONFIG_FILE:-./config/bug-bounty-optimized.yaml}"
OUTPUT_DIR="${OUTPUT_DIR:-./bounty-results}"
TARGET="$1"

# Validate input
if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: $0 <target-domain>${NC}"
    echo -e "Example: $0 example.com"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR/$TARGET"
SCAN_ID=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="$OUTPUT_DIR/$TARGET/$SCAN_ID"
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}🎯 Bug Bounty Workflow - High-Value Vulnerability Discovery${NC}"
echo -e "${BLUE}Target: ${YELLOW}$TARGET${NC}"
echo -e "${BLUE}Scan ID: ${YELLOW}$SCAN_ID${NC}"
echo -e "${BLUE}Output: ${YELLOW}$REPORT_DIR${NC}\n"

# Function to run command and check results
run_scan() {
    local module=$1
    local description=$2
    local output_file=$3
    
    echo -e "${GREEN}[*] ${description}...${NC}"
    if $SHELLS_BIN --config "$CONFIG_FILE" $module > "$output_file" 2>&1; then
        echo -e "${GREEN}[✓] ${description} completed${NC}"
        
        # Check for high/critical findings
        if grep -E "(CRITICAL|HIGH|VULNERABLE)" "$output_file" > /dev/null 2>&1; then
            echo -e "${RED}[!] High-value vulnerabilities found!${NC}"
            return 0
        fi
    else
        echo -e "${YELLOW}[!] ${description} completed with warnings${NC}"
    fi
    return 1
}

# Phase 1: Smart Attack Surface Discovery
echo -e "\n${BLUE}=== Phase 1: Smart Attack Surface Discovery ===${NC}"

# Discover authentication endpoints first
echo -e "${GREEN}[*] Discovering authentication endpoints...${NC}"
$SHELLS_BIN auth discover --target "$TARGET" \
    --output "$REPORT_DIR/auth-endpoints.json" \
    --format json &

# Discover API endpoints in parallel
echo -e "${GREEN}[*] Discovering API endpoints...${NC}"
$SHELLS_BIN api discover --target "$TARGET" \
    --output "$REPORT_DIR/api-endpoints.json" \
    --graphql --rest --swagger &

# Quick subdomain enumeration focused on high-value targets
echo -e "${GREEN}[*] Smart subdomain discovery...${NC}"
$SHELLS_BIN discover "$TARGET" \
    --smart-mode \
    --focus "api,auth,admin,portal,dashboard,console,payment,internal" \
    --output "$REPORT_DIR/subdomains.json" &

wait # Wait for all discovery tasks

# Phase 2: High-Value Vulnerability Testing
echo -e "\n${BLUE}=== Phase 2: Testing High-Value Vulnerabilities ===${NC}"

# 1. Authentication Bypass Testing (Highest Priority)
echo -e "\n${YELLOW}[1] Authentication Bypass Testing${NC}"

# Test SAML vulnerabilities
run_scan "auth test --target $TARGET --protocol saml --all-attacks" \
    "Testing for SAML vulnerabilities (Golden SAML, signature bypass)" \
    "$REPORT_DIR/saml-vulns.json"

# Test OAuth2/JWT vulnerabilities
run_scan "auth test --target $TARGET --protocol oauth2 --jwt-attacks" \
    "Testing OAuth2/JWT vulnerabilities (algorithm confusion, token attacks)" \
    "$REPORT_DIR/oauth-jwt-vulns.json"

# Test authentication chains
run_scan "auth chain --target $TARGET --max-depth 5" \
    "Finding authentication bypass chains" \
    "$REPORT_DIR/auth-chains.json"

# 2. API Security Testing
echo -e "\n${YELLOW}[2] API Security Testing${NC}"

# GraphQL specific tests
if grep -q "graphql" "$REPORT_DIR/api-endpoints.json" 2>/dev/null; then
    run_scan "api test --target $TARGET --graphql --introspection --injection" \
        "Testing GraphQL vulnerabilities" \
        "$REPORT_DIR/graphql-vulns.json"
fi

# REST API authorization testing
run_scan "api test --target $TARGET --rest --auth-bypass --method-override" \
    "Testing REST API authorization" \
    "$REPORT_DIR/api-auth-vulns.json"

# 3. Business Logic Testing
echo -e "\n${YELLOW}[3] Business Logic Testing${NC}"

# Identify and test payment/transaction endpoints
if grep -E "(payment|checkout|cart|order)" "$REPORT_DIR/api-endpoints.json" 2>/dev/null; then
    run_scan "logic test --target $TARGET --payment --race-conditions" \
        "Testing payment manipulation vulnerabilities" \
        "$REPORT_DIR/payment-logic-vulns.json"
fi

# Test for IDOR and privilege escalation
run_scan "logic test --target $TARGET --idor --privilege-escalation" \
    "Testing access control and IDOR vulnerabilities" \
    "$REPORT_DIR/access-control-vulns.json"

# 4. Request Smuggling Testing
echo -e "\n${YELLOW}[4] Request Smuggling Testing${NC}"

run_scan "smuggle detect --target https://$TARGET --all-techniques" \
    "Testing for request smuggling vulnerabilities" \
    "$REPORT_DIR/smuggling-vulns.json"

# If smuggling is detected, test exploitation
if [ $? -eq 0 ]; then
    run_scan "smuggle exploit --target https://$TARGET --cache-poison --auth-bypass" \
        "Exploiting request smuggling for impact" \
        "$REPORT_DIR/smuggling-exploit.json"
fi

# 5. SSRF Testing
echo -e "\n${YELLOW}[5] SSRF Testing${NC}"

# Test common SSRF vectors
run_scan "ssrf test --target $TARGET --webhooks --url-params --cloud-metadata" \
    "Testing for SSRF vulnerabilities" \
    "$REPORT_DIR/ssrf-vulns.json"

# 6. Access Control Testing
echo -e "\n${YELLOW}[6] Access Control & IDOR Testing${NC}"

run_scan "access test --target $TARGET --idor --uuid-prediction --role-testing" \
    "Testing access control vulnerabilities" \
    "$REPORT_DIR/idor-vulns.json"

# Phase 3: Exploitation and Impact Demonstration
echo -e "\n${BLUE}=== Phase 3: Exploitation & Impact Demonstration ===${NC}"

# Generate proof of concepts for found vulnerabilities
echo -e "${GREEN}[*] Generating proof of concepts...${NC}"
$SHELLS_BIN poc generate \
    --scan-results "$REPORT_DIR" \
    --output "$REPORT_DIR/poc" \
    --safe-mode

# Phase 4: Report Generation
echo -e "\n${BLUE}=== Phase 4: Report Generation ===${NC}"

# Aggregate all findings
echo -e "${GREEN}[*] Aggregating findings...${NC}"
$SHELLS_BIN results aggregate \
    --input "$REPORT_DIR" \
    --severity "critical,high,medium" \
    --output "$REPORT_DIR/all-findings.json"

# Generate bug bounty report
echo -e "${GREEN}[*] Generating bug bounty report...${NC}"
$SHELLS_BIN report generate \
    --findings "$REPORT_DIR/all-findings.json" \
    --format markdown \
    --template bug-bounty \
    --output "$REPORT_DIR/report.md"

# Generate executive summary
echo -e "${GREEN}[*] Generating executive summary...${NC}"
cat > "$REPORT_DIR/executive-summary.md" << EOF
# Bug Bounty Report - $TARGET
**Scan Date:** $(date)
**Scan ID:** $SCAN_ID

## High-Value Findings Summary

### Critical Vulnerabilities
$(grep -c "CRITICAL" "$REPORT_DIR/all-findings.json" 2>/dev/null || echo "0") findings

### High Vulnerabilities  
$(grep -c "HIGH" "$REPORT_DIR/all-findings.json" 2>/dev/null || echo "0") findings

### Top Attack Vectors
1. Authentication Bypass: $(ls -1 "$REPORT_DIR"/auth-*.json 2>/dev/null | wc -l) findings
2. API Security: $(ls -1 "$REPORT_DIR"/api-*.json 2>/dev/null | wc -l) findings
3. Business Logic: $(ls -1 "$REPORT_DIR"/*logic*.json 2>/dev/null | wc -l) findings
4. Request Smuggling: $(ls -1 "$REPORT_DIR"/smuggling*.json 2>/dev/null | wc -l) findings
5. SSRF: $(ls -1 "$REPORT_DIR"/ssrf*.json 2>/dev/null | wc -l) findings
6. Access Control: $(ls -1 "$REPORT_DIR"/*access*.json 2>/dev/null | wc -l) findings

## Recommended Next Steps
1. Review critical findings in $REPORT_DIR/report.md
2. Test proof of concepts in $REPORT_DIR/poc/
3. Validate impact and create bug bounty submission
EOF

# Display summary
echo -e "\n${BLUE}=== Scan Complete ===${NC}"
echo -e "${GREEN}[✓] Results saved to: $REPORT_DIR${NC}"
echo -e "${GREEN}[✓] Main report: $REPORT_DIR/report.md${NC}"
echo -e "${GREEN}[✓] PoCs: $REPORT_DIR/poc/${NC}"

# Check for critical findings
if grep -q "CRITICAL" "$REPORT_DIR/all-findings.json" 2>/dev/null; then
    echo -e "\n${RED}[!!!] CRITICAL VULNERABILITIES FOUND!${NC}"
    echo -e "${RED}Review immediately: $REPORT_DIR/report.md${NC}"
fi

# Optional: Open report in browser
if command -v xdg-open > /dev/null; then
    echo -e "\n${YELLOW}Open report in browser? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        # Convert markdown to HTML first
        if command -v pandoc > /dev/null; then
            pandoc "$REPORT_DIR/report.md" -o "$REPORT_DIR/report.html"
            xdg-open "$REPORT_DIR/report.html"
        else
            xdg-open "$REPORT_DIR/report.md"
        fi
    fi
fi