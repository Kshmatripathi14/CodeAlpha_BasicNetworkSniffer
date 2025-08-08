import os
import subprocess
import re

def detect_interface():
    """Detect the first non-loopback network interface."""
    try:
        output = subprocess.check_output(["ip", "link"], text=True)
        interfaces = re.findall(r'^\d+: (\w+):', output, re.MULTILINE)
        for iface in interfaces:
            if iface != "lo":
                return iface
    except Exception as e:
        print(f"[!] Error detecting interface: {e}")
    return None

def run_suricata():
    iface = detect_interface()
    if not iface:
        print("[!] Could not detect a network interface. Please enter manually.")
        iface = input("Interface: ")

    print(f"[+] Using interface: {iface}")

    # Ensure logs folder exists
    os.makedirs("logs", exist_ok=True)

    # Start Suricata
    cmd = [
        "sudo", "suricata",
        "-c", "suricata.yaml",
        "-i", iface,
        "-l", "logs"
    ]

    print("[+] Starting Suricata with repo's config & rules...")
    print("[+] Logs will be stored in ./logs/")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[+] Suricata stopped.")

def follow_fast_log():
    """Display real-time alerts from fast.log"""
    fast_log = "logs/fast.log"
    if os.path.exists(fast_log):
        print("\n[+] Showing alerts from fast.log (Ctrl+C to stop):\n")
        try:
            subprocess.run(["tail", "-f", fast_log])
        except KeyboardInterrupt:
            print("\n[+] Stopped monitoring alerts.")
    else:
        print("[!] fast.log not found. Run Suricata first.")

if __name__ == "__main__":
    print("""
=============================
 Suricata Portable Runner
=============================
    """)
    run_suricata()
    follow_fast_log()
