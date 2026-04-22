"""
XAI-ITD-DLP — Agent Auto-Launcher
Connects to server via API login — works with both localhost and Render.
Run this ONCE on the employee's laptop after login.

Usage: python start_agent.py
"""

import os
import sys
import json
import time
import threading
import requests
import getpass

# agent/ folder → parent is project root
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = os.path.join(ROOT_DIR, "session_token.json")

# Add root to path so monitor.py can import project modules
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Server URL ────────────────────────────────────────────────────────────────
# Default to Render URL. For local dev, set env var:
#   set XAI_SERVER_URL=http://127.0.0.1:5000
SERVER_URL = os.environ.get(
    "XAI_SERVER_URL",
    "https://xai-itd-dlp.onrender.com"
).rstrip("/")


# ── helpers ───────────────────────────────────────────────────────────────────

def read_token_file():
    """Try to read session_token.json (works for local dev)."""
    try:
        with open(TOKEN_FILE, "r") as f:
            s = json.load(f)
        email = s.get("email", "").strip()
        token = s.get("token", "").strip()
        name  = s.get("name", "Employee").strip()
        if email and token:
            return email, token, name
    except Exception:
        pass
    return None


def login_via_api(email, password):
    """Call /api/auth/verify-otp flow on server. Returns (token, name) or None."""
    try:
        # Step 1: request OTP
        res = requests.post(
            f"{SERVER_URL}/api/auth/request-otp",
            json={"email": email, "password": password},
            timeout=15
        )
        if res.status_code == 200:
            print(f"[LAUNCHER] {res.json().get('message', 'OTP sent.')}")
            # Step 2: verify OTP
            otp = input("Enter OTP from your email: ").strip()
            res2 = requests.post(
                f"{SERVER_URL}/api/auth/verify-otp",
                json={"email": email, "otp": otp},
                timeout=15
            )
            if res2.status_code == 200:
                data  = res2.json()
                token = data.get("token", "")
                name  = data.get("name", "Employee")
                if token:
                    return token, name
            print(f"[LAUNCHER] OTP verification failed: {res2.text[:100]}")
        else:
            print(f"[LAUNCHER] Login failed ({res.status_code}): {res.json().get('error', res.text[:100])}")
    except requests.exceptions.ConnectionError:
        print(f"[LAUNCHER] Cannot reach server at {SERVER_URL}")
        print("[LAUNCHER] Check your internet connection or XAI_SERVER_URL env var.")
    except Exception as e:
        print(f"[LAUNCHER] Login error: {e}")
    return None


def get_mtime():
    try:
        return os.path.getmtime(TOKEN_FILE)
    except Exception:
        return 0


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  XAI-ITD-DLP Agent Launcher")
    print(f"  Server: {SERVER_URL}")
    print("=" * 55)

    import monitor
    # Pass server URL to monitor so all its API calls go to the right place
    monitor.SERVER_URL = SERVER_URL

    while True:
        email = token = name = None

        # ── Try local session_token.json first (local dev) ────────────────
        local_session = read_token_file()
        if local_session:
            email, token, name = local_session
            print(f"[LAUNCHER] Local session found: {name} ({email})")
        else:
            # ── Login via server API ───────────────────────────────────────
            print(f"\n[LAUNCHER] No local session found. Login via server.")
            while not token:
                email    = input("Employee email:  ").strip()
                password = getpass.getpass("Password:        ")
                result   = login_via_api(email, password)
                if result:
                    token, name = result
                    print(f"[LAUNCHER] Welcome {name}!")
                else:
                    print("[LAUNCHER] Try again.\n")

        print(f"[LAUNCHER] Starting monitoring agent for {name}...\n")

        monitor.RUNNING = True
        agent_thread = threading.Thread(
            target=monitor.start_agent,
            args=(email, token, name),
            daemon=True
        )
        agent_thread.start()

        # ── Watch for new login (token file change) ───────────────────────
        current_mtime = get_mtime()
        print("[LAUNCHER] Monitoring active. Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(2)
                new_mtime = get_mtime()

                # Token file changed = new login
                if new_mtime != current_mtime and new_mtime > 0:
                    new_session = read_token_file()
                    if new_session and new_session[1] != token:
                        print("\n[LAUNCHER] New login detected — restarting agent...")
                        monitor.RUNNING = False
                        time.sleep(2)
                        break

                # Agent thread died unexpectedly — restart
                if not agent_thread.is_alive():
                    print("[LAUNCHER] Agent stopped unexpectedly — restarting in 3s...")
                    time.sleep(3)
                    monitor.RUNNING = True
                    agent_thread = threading.Thread(
                        target=monitor.start_agent,
                        args=(email, token, name),
                        daemon=True
                    )
                    agent_thread.start()

        except KeyboardInterrupt:
            print("\n[LAUNCHER] Stopped by user.")
            monitor.RUNNING = False
            time.sleep(1)
            again = input("Login as different user? (y/n): ").strip().lower()
            if again == "y":
                continue
            break


if __name__ == "__main__":
    main()