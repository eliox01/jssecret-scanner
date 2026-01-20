#!/usr/bin/env bash
# JavaScript Secret Scanner v2.1
# Optimized for Offensive Security Research
# Enhanced with better error handling and pattern detection

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'  # No Color

# Configuration
readonly MAX_TIMEOUT=10
readonly MAX_PARALLEL_JOBS=5

# Output helper functions
print_info() { echo -e "${BLUE}[i]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_section() { echo -e "${YELLOW}--- $1 ---${NC}"; }

# Main scanning function
scan_js_file() {
    local url=$1
    local temp_file=$(mktemp)
    
    print_info "Scanning: ${url}"
    
    # Download file with timeout and error handling
    if ! curl -s -L --max-time "$MAX_TIMEOUT" \
         -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
         "$url" -o "$temp_file" 2>/dev/null; then
        print_error "Failed to download: ${url}"
        rm -f "$temp_file"
        return 1
    fi
    
    # Check if file has content
    if [ ! -s "$temp_file" ]; then
        print_error "Empty response: ${url}"
        rm -f "$temp_file"
        return 1
    fi
    
    echo ""
    print_success "Results for: ${url}"
    
    local findings=0
    
    # --- 1. GitLab Tokens ---
    print_section "GitLab Tokens"
    if grep -qE "glpat-[0-9a-zA-Z_-]{20,40}" "$temp_file"; then
        grep -oE "glpat-[0-9a-zA-Z_-]{20,40}" "$temp_file" | while read -r token; do
            echo "  ${CYAN}FOUND:${NC} $token"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 2. GitHub Personal Access Tokens ---
    print_section "GitHub PAT Tokens"
    if grep -qE "ghp_[0-9a-zA-Z]{36}" "$temp_file"; then
        grep -oE "ghp_[0-9a-zA-Z]{36}" "$temp_file" | while read -r token; do
            echo "  ${CYAN}FOUND:${NC} $token"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 3. AWS Access Keys ---
    print_section "AWS Access Keys"
    if grep -qE "AKIA[0-9A-Z]{16}" "$temp_file"; then
        grep -oE "AKIA[0-9A-Z]{16}" "$temp_file" | while read -r key; do
            echo "  ${CYAN}FOUND:${NC} $key"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 4. AWS Secret Keys ---
    print_section "AWS Secret Keys (40 chars)"
    if grep -qE "['\"][0-9a-zA-Z/+=]{40}['\"]" "$temp_file"; then
        grep -oE "['\"][0-9a-zA-Z/+=]{40}['\"]" "$temp_file" | head -n 5 | while read -r secret; do
            echo "  ${CYAN}POTENTIAL:${NC} $secret"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 5. Generic API Keys ---
    print_section "Generic API Keys"
    if grep -qiE "(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}" "$temp_file"; then
        grep -oiE "(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}" "$temp_file" | head -n 10 | while read -r key; do
            echo "  ${CYAN}FOUND:${NC} $key"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 6. Tenable/Hexadecimal Tokens ---
    print_section "Hexadecimal Tokens (64 chars)"
    if grep -qE "\b[a-f0-9]{64}\b" "$temp_file"; then
        grep -oE "\b[a-f0-9]{64}\b" "$temp_file" | head -n 5 | while read -r token; do
            echo "  ${CYAN}FOUND:${NC} $token"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 7. Environment Variables ---
    print_section "process.env Variables"
    if grep -qE "process\.env\.[A-Z_]+" "$temp_file"; then
        grep -oE "process\.env\.[A-Z_]+" "$temp_file" | sort -u | while read -r var; do
            echo "  ${CYAN}FOUND:${NC} $var"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 8. JWT Tokens ---
    print_section "JWT Tokens"
    if grep -qE "eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" "$temp_file"; then
        grep -oE "eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" "$temp_file" | head -n 3 | while read -r jwt; do
            echo "  ${CYAN}FOUND:${NC} ${jwt:0:50}..."
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 9. Private Keys ---
    print_section "Private Keys"
    if grep -qE "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----" "$temp_file"; then
        echo "  ${RED}CRITICAL:${NC} Private key detected!"
        ((findings++)) || true
    else
        echo "  None found"
    fi
    
    # --- 10. Internal/Hidden Endpoints ---
    print_section "Internal API Endpoints"
    if grep -qE "https?://[a-zA-Z0-9.-]*(internal|dev|staging|local|localhost|127\.0\.0\.1)[a-zA-Z0-9./_-]*" "$temp_file"; then
        grep -oE "https?://[a-zA-Z0-9.-]*(internal|dev|staging|local|localhost|127\.0\.0\.1)[a-zA-Z0-9./_-]*" "$temp_file" | sort -u | head -n 10 | while read -r endpoint; do
            echo "  ${CYAN}FOUND:${NC} $endpoint"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    # --- 11. Database Connection Strings ---
    print_section "Database Connections"
    if grep -qiE "(mongodb|mysql|postgres|postgresql)://[a-zA-Z0-9:@._-]+" "$temp_file"; then
        grep -oiE "(mongodb|mysql|postgres|postgresql)://[a-zA-Z0-9:@._-]+" "$temp_file" | while read -r conn; do
            echo "  ${RED}CRITICAL:${NC} $conn"
            ((findings++)) || true
        done
    else
        echo "  None found"
    fi
    
    echo ""
    if [ "$findings" -gt 0 ]; then
        print_success "Total findings: $findings"
    else
        print_info "No secrets detected"
    fi
    echo "----------------------------------------"
    
    rm -f "$temp_file"
}

# Export function for parallel execution
export -f scan_js_file print_info print_success print_error print_section
export RED GREEN YELLOW BLUE CYAN NC MAX_TIMEOUT

# Main execution logic
main() {
    if [ $# -eq 0 ]; then
        echo "Usage: $0 <url1> <url2> ..."
        echo "Example: $0 https://example.com/app.js https://example.com/vendor.js"
        exit 1
    fi
    
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  JavaScript Secret Scanner v2.1       ║${NC}"
    echo -e "${GREEN}║  Scanning $# file(s) in parallel        ║${NC}"
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo ""
    
    # Use GNU parallel if available, otherwise use background jobs
    if command -v parallel &> /dev/null; then
        printf '%s\n' "$@" | parallel -j "$MAX_PARALLEL_JOBS" scan_js_file
    else
        # Fallback to manual background jobs with job limiting
        local job_count=0
        for url in "$@"; do
            scan_js_file "$url" &
            ((job_count++))
            
            # Limit concurrent jobs
            if [ "$job_count" -ge "$MAX_PARALLEL_JOBS" ]; then
                wait -n  # Wait for any job to finish
                ((job_count--))
            fi
        done
        
        # Wait for all remaining jobs
        wait
    fi
    
    echo ""
    print_success "All scans completed!"
}

main "$@"