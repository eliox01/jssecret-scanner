# JS-Secret-Scanner 🛡️

A lightweight Bash utility for offensive security research and ethical bug hunting. This tool automates the discovery of hardcoded secrets, internal endpoints, and insecure logic within minified JavaScript bundles.

## Features
- **Fast Pattern Matching:** Uses optimized regex to find API keys, AWS secrets, and JWTs.
- **De-obfuscation:** Breaks minified one-liners for better grep accuracy.
- **Environment Discovery:** Identifies leaking internal/dev subdomains.

## Installation & Usage
1. Clone the repo: `git clone https://github.com/YOUR_USERNAME/secret-scanner.git`
2. Make executable: `chmod +x js_scanner.sh`
3. Run: `./js_scanner.sh <URL>`

## Disclaimer
This tool is intended for ethical research and authorized security audits only.
