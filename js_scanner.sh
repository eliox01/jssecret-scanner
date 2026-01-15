#!/bin/bash

# JavaScript Secret Scanner
# Scans JS files for sensitive parameters and secrets

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to scan a single JS file
scan_js_file() {
    local url=$1
    local temp_file=$(mktemp)
    
    echo -e "${GREEN}[+] Scanning: ${url}${NC}"
    
    # Download the JS file
    if curl -s -L "$url" -o "$temp_file"; then
        echo -e "${YELLOW}[*] File downloaded successfully${NC}"
        
        # Scan for API keys
        echo -e "\n${YELLOW}=== API Keys ===${NC}"
        grep -oE "(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}" "$temp_file" | head -10
        
        # Scan for AWS keys
        echo -e "\n${YELLOW}=== AWS Keys ===${NC}"
        grep -oE "AKIA[0-9A-Z]{16}" "$temp_file"
        
        # Scan for tokens
        echo -e "\n${YELLOW}=== Tokens ===${NC}"
        grep -oE "(access[_-]?token|auth[_-]?token|bearer)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}" "$temp_file" | head -10
        
        # Scan for passwords
        echo -e "\n${YELLOW}=== Passwords ===${NC}"
        grep -oE "(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^'\"]{6,}" "$temp_file" | head -10
        
        # Scan for API endpoints
        echo -e "\n${YELLOW}=== API Endpoints ===${NC}"
        grep -oE "(https?://[a-zA-Z0-9.-]+/api[a-zA-Z0-9/._-]*)" "$temp_file" | sort -u | head -20
        
        # Scan for internal URLs
        echo -e "\n${YELLOW}=== Internal/Private URLs ===${NC}"
        grep -oE "(https?://[a-zA-Z0-9.-]*(internal|private|local|dev|staging|test)[a-zA-Z0-9.-]*[a-zA-Z0-9/._-]*)" "$temp_file" | sort -u | head -10
        
        # Scan for environment variables
        echo -e "\n${YELLOW}=== Environment Variables ===${NC}"
        grep -oE "process\.env\.[A-Z_]+" "$temp_file" | sort -u | head -10
        
        # Scan for database connections
        echo -e "\n${YELLOW}=== Database Strings ===${NC}"
        grep -oE "(mongodb|mysql|postgres|redis)://[^'\"[:space:]]+" "$temp_file" | head -5
        
        # Scan for JWT tokens
        echo -e "\n${YELLOW}=== JWT Tokens ===${NC}"
        grep -oE "eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" "$temp_file" | head -5
        
    else
        echo -e "${RED}[-] Failed to download file${NC}"
    fi
    
    # Cleanup
    rm -f "$temp_file"
    echo -e "\n${GREEN}[+] Scan complete for: ${url}${NC}\n"
}

# Main script
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}JavaScript Secret Scanner${NC}"
echo -e "${GREEN}================================${NC}\n"

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <javascript-url> [additional-urls...]"
    echo ""
    echo "Examples:"
    echo "  $0 http://example.com/app/dist/app-main.f94e7a89473663b2.js"
    echo "  $0 https://privatedomain.com/webconsole/main-POL5DYFH.js"
    exit 1
fi

# Scan each provided URL
for url in "$@"; do
    scan_js_file "$url"
done

echo -e "${GREEN}[+] All scans completed${NC}"
