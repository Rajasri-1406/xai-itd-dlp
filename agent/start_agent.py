"""
XAI-ITD-DLP — Agent Auto-Launcher
Run this ONCE at system start (before or after login — it waits).
Watches session_token.json for changes so it auto-restarts on new login
without needing to re-run this script.

Usage: python start_agent.py
"""

import os
import sys
import json
import time
import threading

# agent/ folder → parent is project root
ROOT_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = os.path.join(ROOT_DIR, "session_token.json")

# Add root to path so monitor.py can import project modules
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── helpers ──────────────────────────────────────────────────────────────────

def read_token_file():
    """Read session_token.json, return (email, token, name) or None."""
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


def wait_for_token():
    """Block until session_token.json exists and is valid."""
    print("[LAUNCHER] Waiting for employee login...")
    waited = 0
    while True:
        if os.path.exists(TOKEN_FILE):
            result = read_token_file()
            if result:
                return result
        time.sleep(1)
        waited += 1
        if waited % 10 == 0:
            print(f"[LAUNCHER] Still waiting for login... ({waited}s)")


def get_mtime():
    try:
        return os.path.getmtime(TOKEN_FILE)
    except Exception:
        return 0


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  XAI-ITD-DLP Agent Launcher")
    print("  Run once — auto-restarts on each new login")
    print("=" * 55)

    import monitor

    current_mtime = 0

    while True:
        # Wait for a valid session token file
        email, token, name = wait_for_token()
        current_mtime = get_mtime()

        print(f"[LAUNCHER] Session found for: {name} ({email})")
        print("[LAUNCHER] Starting monitoring agent...\n")

        # Start agent in a background thread so we can watch for token changes
        monitor.RUNNING = True
        agent_thread = threading.Thread(
            target=monitor.start_agent,
            args=(email, token, name),
            daemon=True
        )
        agent_thread.start()

        # Watch for token file change = new login
        print("[LAUNCHER] Watching for new login session...")
        while True:
            time.sleep(2)
            new_mtime = get_mtime()

            # Token file changed = employee logged in again (new token)
            if new_mtime != current_mtime and new_mtime > 0:
                new_session = read_token_file()
                if new_session and new_session[1] != token:
                    print("\n[LAUNCHER] New login detected — restarting agent...")
                    # Stop old agent
                    monitor.RUNNING = False
                    time.sleep(2)   # give threads time to stop
                    break           # restart outer loop with new token

            # Agent thread died unexpectedly — restart it
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

if __name__ == "__main__":
    main()