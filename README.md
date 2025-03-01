# ONI - Ultimate WAF Bypass Tool

ONI is an advanced Web Application Firewall (WAF) bypass tool designed to test and evade security mechanisms using multiple encoding and obfuscation techniques. It helps security researchers analyze WAF behavior and identify bypassable vulnerabilities.

## Features
- Supports multiple WAF bypass techniques:
  - Base64 & Double Base64 Encoding
  - URL & Double URL Encoding
  - Case Insensitive Payloads
  - Space Obfuscation
  - Hex Encoding
  - Mixed Encoding
- Automatic WAF detection
- Randomized user-agents and headers for stealth
- Saves results to a JSON file
- Supports custom payload input

## Installation
Ensure you have **Python 3** installed. Then, install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage
Run ONI using the following syntax:

```bash
python oni.py -u <target_url> -p <payload> [-o]
```

### Arguments:
- `-u`, `--url` : Target URL (e.g., `http://victim.com`)
- `-p`, `--payload` : Attack payload (e.g., `' OR 1=1 --`)
- `-o`, `--output` : Save results to a JSON file

### Example:
```bash
python oni.py -u "http://example.com/search" -p "' OR 1=1 --" -o
```

## WAF Detection
ONI first scans for potential WAF presence by sending known test payloads. If a WAF is detected, it proceeds with bypass attempts using different encoding methods.

## Output Example
```
ONI - ULTIMATE WAF BYPASS TOOL
Made by: davycipher

Scanning for WAF presence...
WAF Detected! Blocking Status: 403

Executing Oni's Bypass Techniques...
[ Base64 Bypass ] ➜ J09SIG9yID0xIC0tJw==
[ URL Encoding ] ➜ %27%20OR%201%3D1%20--
[ Hex Encoding ] ➜ %27%20%4f%52%20%31%3d%31%20--

Results:
[Base64] Status Code: 200
[URL Encoding] Status Code: 403
[Hex Encoding] Status Code: 200

Results saved in oni_results_1700000000.json
```

## Disclaimer
ONI is designed for **educational and ethical hacking purposes only**. The author is not responsible for any misuse of this tool.



