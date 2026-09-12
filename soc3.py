import json
import subprocess
import time
import os
import requests  # We use raw HTTP requests to bypass ollama library version bugs
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Lock

# --- CONFIGURATION ---
EVE_LOG_PATH = "/var/log/suricata/eve.json"
MODEL_NAME = "gemma3:4b"  # Your model name from 'ollama list'
OLLAMA_API_URL = "http://127.0.0.1:11434/api/generate"

# SECURITY: List of IPs that the script will NEVER block in UFW
SAFE_WHITELIST = ["127.0.0.1", "192.168.1.100"] 

# THREADING & PERFORMANCE: Configuration for non-blocking workers and timeouts
MAX_WORKERS = 10           # Maximum number of concurrent analysis threads
THREAD_TIMEOUT = 45        # Timeout in seconds for the entire thread execution

# CACHE CONFIGURATION (Cleans up repeated alerts within a timeframe)
CACHE_TIMEOUT_SECONDS = 300  # How long (5 minutes) to remember LLM decision per IP
# ---------------------

# Thread-safe storage and locks for deduplication
cache_lock = Lock()
BLOCKED_CACHE = {}       # Stores {ip: {"block": bool, "reason": str, "timestamp": float}}
ALREADY_PROCESSING = set() # Track IPs currently being evaluated by Ollama

def apply_ufw_rule(ip_address, reason):
    """This function blocks rogue IP using Ubuntu Firewall UFW"""
    if ip_address in SAFE_WHITELIST:
        print(f"[*] Blocking skipped: IP address {ip_address} is on the whitelist.")
        return

    print(f"[!] Blocking the IP: {ip_address} (Reason: {reason})")
    try:
        # Checking if this IP is already blocked
        check_rule = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
        if ip_address in check_rule.stdout:
            print(f"[*] Address {ip_address} is already on the list.")
            return

        # Call command to ban IP
        result = subprocess.run(["sudo", "ufw", "deny", "from", ip_address, "to", "any"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] Successfully blocked {ip_address} in UFW.")
            # Reload firewall configuration
            subprocess.run(["sudo", "ufw", "reload"], capture_output=True)
        else:
            print(f"[-] Error during adding the rule to UFW: {result.stderr}")
    except Exception as e:
        print(f"[-] System Error: {e}")

def ask_ollama_to_analyze(alert_data):
    """Sends SURICATA alert details to Ollama LLM for evaluation via native HTTP API"""
    prompt = f"""
    Analyse this alert from Suricata IDS against the security of Linux based system.
    Decide if it is a threat and if this IP needs to be blocked with the usage of Ubuntu Firewall ufw.

    Alert details:
    - Source IP (Attacker): {alert_data.get('src_ip')}
    - Source port: {alert_data.get('src_port')}
    - Destination IP: {alert_data.get('dest_ip')}
    - Destination Port: {alert_data.get('dest_port')}
    - Signature/Description: {alert_data.get('alert', {}).get('category')} - {alert_data.get('alert', {}).get('signature')}
    - Protocol: {alert_data.get('proto')}

    Respond EXACTLY in JSON format with two keys:
    1. "block": true or false
    2. "reason": short explanation in single sentence.
    Do not add any markdown block formatters. Only pure JSON.
    """
    
    # Payload structured explicitly for Ollama Local API Daemon
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "format": "json",
        "stream": False
    }
    
    try:
        # Sending direct HTTP POST request to local Ollama socket
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=30)
        
        if response.status_code == 200:
            response_json = response.json()
            response_text = response_json.get('response', '').strip()
            
            # Parsing clean JSON string from LLM output
            decision = json.loads(response_text)
            return decision.get("block", False), decision.get("reason", "No reason provided")
        else:
            return False, f"Ollama API returned HTTP Status {response.status_code}"
            
    except Exception as e:
        print(f"[-] Problem with Ollama communication or JSON parsing: {e}")
        return False, str(e)

def process_alert_worker(data):
    """Worker function executed inside a thread to handle LLM analysis and blocking"""
    src_ip = data.get("src_ip")
    if not src_ip:
        return

    now = time.time()
    
    # 1. Check if we already have a valid, recent cached decision for this IP
    with cache_lock:
        if src_ip in BLOCKED_CACHE:
            cached_item = BLOCKED_CACHE[src_ip]
            if now - cached_item["timestamp"] < CACHE_TIMEOUT_SECONDS:
                should_block = cached_item["block"]
                reason = cached_item["reason"]
                # Bypass Ollama, act straight on cache
                if should_block:
                    apply_ufw_rule(src_ip, f"[Cached] {reason}")
                return
            else:
                # Cache expired, remove it
                del BLOCKED_CACHE[src_ip]

    # 2. If no cache, perform real LLM analysis
    should_block, reason = ask_ollama_to_analyze(data)
    
    # 3. Store the result back into cache and clean active processing state
    with cache_lock:
        BLOCKED_CACHE[src_ip] = {
            "block": should_block,
            "reason": reason,
            "timestamp": now
        }
        if src_ip in ALREADY_PROCESSING:
            ALREADY_PROCESSING.remove(src_ip)
    
    if should_block:
        apply_ufw_rule(src_ip, reason)
    else:
        print(f"[*] LLM decided: No blocking for {src_ip}. The reason: {reason}")

def watch_suricata_logs():
    """Tracks adding lines in the file eve.json (works similar as tail -f)."""
    print(f"[*] Starting Suricata log analysis: {EVE_LOG_PATH}...")
    
    if not os.path.exists(EVE_LOG_PATH):
        print(f"[-] The file {EVE_LOG_PATH} does not exist. Make sure that Suricata works and is generating JSON logs.")
        return

    # Using ThreadPoolExecutor to handle non-blocking processing
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        with open(EVE_LOG_PATH, "r") as f:
            # Rewind the pointer to the end of the log file to parse only new entries
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                    
                try:
                    data = json.loads(line)
                    # Looking for events categorized strictly as 'alert'
                    if data.get("event_type") == "alert":
                        src_ip = data.get("src_ip")
                        if not src_ip:
                            continue
                        
                        # Anti-spam check: Skip if thread is currently evaluating this exact IP
                        with cache_lock:
                            if src_ip in ALREADY_PROCESSING:
                                continue
                            ALREADY_PROCESSING.add(src_ip)

                        print(f"\n[i] New alert detected for the IP: {src_ip}. Dispatching to worker thread...")
                        
                        # Submit task to executor (non-blocking call)
                        future = executor.submit(process_alert_worker, data)
                        
                        # Setup a callback or checking mechanism to handle thread timeouts asynchronously
                        def done_callback(fut, ip=src_ip):
                            try:
                                # This enforces the timeout check when the thread finishes or fails
                                fut.result(timeout=THREAD_TIMEOUT)
                            except TimeoutError:
                                print(f"[-] Thread execution timeout exceeded ({THREAD_TIMEOUT}s) for IP: {ip}")
                                with cache_lock:
                                    if ip in ALREADY_PROCESSING:
                                        ALREADY_PROCESSING.remove(ip)
                            except Exception as ex:
                                print(f"[-] Exception occurred in thread execution: {ex}")
                                with cache_lock:
                                    if ip in ALREADY_PROCESSING:
                                        ALREADY_PROCESSING.remove(ip)
                                
                        future.add_done_callback(done_callback)
                            
                except json.JSONDecodeError:
                    continue
                except KeyboardInterrupt:
                    print("\n[*] Monitoring script stopped.")
                    break

if __name__ == "__main__":
    watch_suricata_logs()

