import json
import subprocess
import time
import os
import requests  # We use raw HTTP requests to bypass ollama library version bugs

# --- CONFIGURATION ---
EVE_LOG_PATH = "/var/log/suricata/eve.json"
MODEL_NAME = "gemma3:4b"  # Your model name from 'ollama list'
OLLAMA_API_URL = "http://127.0.0.1:11434/api/generate"

# SECURITY: List of IPs that the script will NEVER block in UFW
SAFE_WHITELIST = ["127.0.0.1", "192.168.1.100"] 
# ---------------------

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

def watch_suricata_logs():
    """Tracks adding lines in the file eve.json (works similar as tail -f)."""
    print(f"[*] Starting Suricata log analysis: {EVE_LOG_PATH}...")
    
    if not os.path.exists(EVE_LOG_PATH):
        print(f"[-] The file {EVE_LOG_PATH} does not exist. Make sure that Suricata works and is generating JSON logs.")
        return

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
                    print(f"\n[i] New alert detected for the IP: {src_ip}. Sending query to LLM...")
                    
                    should_block, reason = ask_ollama_to_analyze(data)
                    
                    if should_block and src_ip:
                        apply_ufw_rule(src_ip, reason)
                    else:
                        print(f"[*] LLM decided: No blocking. The reason: {reason}")
                        
            except json.JSONDecodeError:
                continue
            except KeyboardInterrupt:
                print("\n[*] Monitoring script stopped.")
                break

if __name__ == "__main__":
    watch_suricata_logs()

