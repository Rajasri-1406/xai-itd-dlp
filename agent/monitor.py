"""
XAI-ITD-DLP — Background Monitoring Agent v2
Blocks: PrintScreen, Screenshots, USB
Monitors: File access, Active window, Heartbeat, Camera processes
NOTE: Ctrl+C / Ctrl+X / Ctrl+V are NOT blocked (copy/paste allowed)
"""

import time
import threading
import os
import sys
import subprocess
import requests
import psutil
import ctypes
from datetime import datetime

# ── Windows imports ───────────────────────────────────────────────────────────
try:
    import win32gui
    import win32con
    import win32clipboard
    WINDOWS = True
except ImportError:
    WINDOWS = False
    print("[AGENT] WARNING: pywin32 not installed. Run: pip install pywin32")

try:
    from pynput import keyboard
    PYNPUT = True
except ImportError:
    PYNPUT = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG = True
except ImportError:
    WATCHDOG = False

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_URL = "http://127.0.0.1:5000"
HEARTBEAT_INTERVAL       = 5
CLIPBOARD_CLEAR_INTERVAL = 2
SENSITIVE_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".csv", ".txt", ".pptx",
                        ".py", ".db", ".json", ".xml"}
MONITORED_PATHS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# Camera/phone-photography related processes to block
CAMERA_PROCESSES = [
    "WindowsCamera.exe",
    "camera.exe",
    "Camera.exe",
    "iriun.exe",
    "DroidCam.exe",
    "EpocCam.exe",
    "iVCam.exe",
    "NDIWebcam.exe",
    "ManyCam.exe",
    "XSplit.exe",
    "OBS.exe",
    "obs64.exe",
    "Bandicam.exe",
    "Fraps.exe",
    "ShareX.exe",
    "Greenshot.exe",
    "LightShot.exe",
]

SESSION_TOKEN = None
USER_EMAIL    = None
USER_NAME     = None
RUNNING       = True


def set_session(email, token, name="Employee"):
    global SESSION_TOKEN, USER_EMAIL, USER_NAME
    USER_EMAIL    = email
    SESSION_TOKEN = token
    USER_NAME     = name


def report(event_type, detail, risk="LOW", blocked=False):
    if not SESSION_TOKEN:
        return
    try:
        requests.post(
            f"{SERVER_URL}/api/agent/event",
            json={
                "email":      USER_EMAIL,
                "event_type": event_type,
                "detail":     detail,
                "risk_level": risk,
                "blocked":    blocked,
                "token":      SESSION_TOKEN
            },
            timeout=3
        )
    except Exception:
        pass


# ── POPUP ALERT ───────────────────────────────────────────────────────────────
def show_alert_popup(title, message):
    if WINDOWS:
        try:
            ctypes.windll.user32.MessageBoxW(
                0, message, title,
                0x00000010 | 0x00001000
            )
        except Exception:
            pass
    else:
        print(f"[ALERT] {title}: {message}")


def show_alert_nonblocking(title, message):
    threading.Thread(
        target=show_alert_popup,
        args=(title, message),
        daemon=True
    ).start()


# ── CLIPBOARD ─────────────────────────────────────────────────────────────────
def clear_clipboard():
    if not WINDOWS:
        return
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.CloseClipboard()
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass
    try:
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        ctypes.windll.user32.CloseClipboard()
    except Exception:
        pass


def clipboard_watcher_loop():
    """Clears only screenshot bitmaps from clipboard. Text copy/paste is fully allowed."""
    while RUNNING:
        time.sleep(CLIPBOARD_CLEAR_INTERVAL)
        if not WINDOWS:
            continue
        try:
            win32clipboard.OpenClipboard()
            has_bitmap = win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB)
            win32clipboard.CloseClipboard()

            if has_bitmap:
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.CloseClipboard()
                report("SCREENSHOT_BLOCKED",
                       "Screenshot bitmap in clipboard — cleared.",
                       risk="HIGH", blocked=True)
                print("[AGENT] ⊘ SCREENSHOT BLOCKED — clipboard cleared")

        except Exception:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass


# ── KEYBOARD BLOCKER — PrintScreen ONLY ──────────────────────────────────────
# Ctrl+C, Ctrl+V, Ctrl+X are intentionally NOT in BLOCK_COMBOS
pressed_keys = set()

BLOCK_KEYS   = {keyboard.Key.print_screen} if PYNPUT else set()
BLOCK_COMBOS = []   # Empty — no key combos blocked


def get_normalized(key):
    try:
        if hasattr(key, 'char') and key.char:
            return keyboard.KeyCode.from_char(key.char.lower())
    except Exception:
        pass
    return key


def on_press(key):
    norm = get_normalized(key)
    pressed_keys.add(norm)

    # Only block PrintScreen
    if key == keyboard.Key.print_screen:
        clear_clipboard()
        report("SCREENSHOT_BLOCKED", "PrintScreen BLOCKED.", risk="HIGH", blocked=True)
        print("[AGENT] ⊘ PrintScreen BLOCKED")
        show_alert_nonblocking(
            "XAI-ITD-DLP Security",
            "⊘ SCREENSHOT BLOCKED\n\nTaking screenshots is prohibited under company security policy.\nThis attempt has been logged and reported."
        )
        return False
    # Ctrl+C, Ctrl+V, Ctrl+X — fully allowed, no action taken


def on_release(key):
    pressed_keys.discard(get_normalized(key))


def start_keyboard_blocker():
    if not PYNPUT:
        return None
    listener = keyboard.Listener(
        on_press=on_press,
        on_release=on_release,
        suppress=False
    )
    listener.start()
    print("[AGENT] ✅ Keyboard monitor active — PrintScreen BLOCKED | Ctrl+C/V/X ALLOWED")
    return listener


# ── SNIPPING TOOL BLOCKER ─────────────────────────────────────────────────────
def win_snip_blocker_loop():
    SNIP_PROCS = ["SnippingTool.exe", "ScreenSketch.exe", "SnipAndSketch.exe"]
    while RUNNING:
        time.sleep(2)
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] in SNIP_PROCS:
                    proc.kill()
                    report("SCREENSHOT_BLOCKED",
                           f"Snipping Tool blocked: {proc.info['name']}",
                           risk="HIGH", blocked=True)
                    print(f"[AGENT] ⊘ {proc.info['name']} KILLED")
                    show_alert_nonblocking(
                        "XAI-ITD-DLP Security",
                        f"⊘ SCREEN CAPTURE BLOCKED\n\n{proc.info['name']} has been terminated.\nScreen capture tools are prohibited under company policy."
                    )
            except Exception:
                pass


# ── CAMERA APP BLOCKER ────────────────────────────────────────────────────────
_camera_warned_procs = set()

def camera_blocker_loop():
    global _camera_warned_procs
    print("[AGENT] ✅ Camera/Recording app blocker active")
    while RUNNING:
        time.sleep(2)
        for proc in psutil.process_iter(['name', 'pid', 'exe']):
            try:
                pname = proc.info['name'] or ""
                if pname in CAMERA_PROCESSES:
                    pid = proc.info['pid']
                    if pid not in _camera_warned_procs:
                        _camera_warned_procs.add(pid)
                        proc.kill()
                        report("CAMERA_BLOCKED",
                               f"Camera/recording app blocked: {pname}",
                               risk="HIGH", blocked=True)
                        print(f"[AGENT] ⊘ CAMERA BLOCKED: {pname}")
                        show_alert_nonblocking(
                            "XAI-ITD-DLP Security — Camera Blocked",
                            f"⊘ CAMERA ACCESS BLOCKED\n\n{pname} has been terminated.\n\n"
                            "Using cameras or recording software while viewing\n"
                            "company documents is prohibited.\n\n"
                            "This incident has been logged and reported to your manager."
                        )
            except Exception:
                pass
        _camera_warned_procs = {p for p in _camera_warned_procs
                                 if psutil.pid_exists(p)}


# ── PHONE DETECTION via OpenCV webcam ────────────────────────────────────────
import cv2

_face_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
)
_upper_body_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + 'haarcascade_upperbody.xml'
)

_phone_cooldown = 0
_face_history   = []
_HISTORY_SIZE   = 6


def detect_phone_in_frame(frame):
    global _face_history

    gray  = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = _face_cascade.detectMultiScale(
        gray, scaleFactor=1.1, minNeighbors=3, minSize=(40, 40)
    )
    f = len(faces)

    _face_history.append(f)
    if len(_face_history) > _HISTORY_SIZE:
        _face_history.pop(0)

    if len(_face_history) < _HISTORY_SIZE:
        return False, ""

    recent   = _face_history[-_HISTORY_SIZE:]
    avg_prev = sum(recent[:-2]) / max(len(recent[:-2]), 1)

    if f >= 2:
        return True, f"Multiple persons detected near screen ({f} faces)"

    if avg_prev >= 0.7 and f == 0:
        return True, "Employee face disappeared suddenly — possible phone recording"

    return False, ""


def _is_file_open():
    try:
        r = requests.get(
            f"{SERVER_URL}/api/agent/file-viewing-status",
            params={"token": SESSION_TOKEN, "email": USER_EMAIL},
            timeout=2
        )
        if r.status_code == 200:
            data = r.json()
            print(f"[AGENT] File status: {data}")
            return data.get("active", False)
    except Exception:
        pass
    return False


def _write_phone_flag():
    try:
        safe_email = (USER_EMAIL or "unknown").replace("@", "_").replace(".", "_")
        flag_path  = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            f"phone_detected_{safe_email}.flag"
        )
        with open(flag_path, "w") as f:
            f.write(datetime.utcnow().isoformat())
        print(f"[AGENT] Flag written: {flag_path}")
    except Exception as e:
        print(f"[AGENT] Flag write error: {e}")


_push_counter = 0

def _push_frame(frame):
    global _push_counter
    _push_counter += 1
    if _push_counter % 3 != 0:
        return
    if not SESSION_TOKEN:
        return
    try:
        ok, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 55])
        if not ok:
            return
        requests.post(
            f"{SERVER_URL}/api/agent/push-frame",
            data=buf.tobytes(),
            headers={"X-Auth-Token": SESSION_TOKEN, "Content-Type": "image/jpeg"},
            timeout=1
        )
        print("[AGENT] 📸 Frame pushed to browser")
    except Exception as e:
        print(f"[AGENT] Push frame error: {e}")


def phone_detection_loop():
    global _phone_cooldown

    print("[AGENT] ✅ Phone detection active — webcam starts when file is opened")

    cap           = None
    cam_open      = False
    was_file_open = False

    while RUNNING:
        time.sleep(0.5)
        file_open = _is_file_open()

        if file_open and not cam_open:
            try:
                cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                if cap.isOpened():
                    cam_open = True
                    print("[AGENT] 📷 Webcam ON — monitoring for phone recording")
                    report("WEBCAM_STARTED", "Webcam monitoring started — employee opened a file.", risk="LOW")
                else:
                    print("[AGENT] ⚠ Could not open webcam (index 0)")
                    cap = None
            except Exception as e:
                print(f"[AGENT] Webcam open error: {e}")

        if not file_open and cam_open:
            try:
                if cap:
                    cap.release()
                    cap = None
                cam_open = False
                print("[AGENT] 📷 Webcam OFF — file closed")
                report("WEBCAM_STOPPED", "Webcam monitoring stopped — file closed.", risk="LOW")
            except Exception:
                pass

        if cam_open and cap:
            try:
                ret, frame = cap.read()
                if not ret or frame is None:
                    continue

                _push_frame(frame)
                phone_detected, reason = detect_phone_in_frame(frame)

                if phone_detected:
                    now = time.time()
                    if now - _phone_cooldown > 10:
                        _phone_cooldown = now
                        print(f"[AGENT] ⊘ PHONE DETECTED: {reason}")
                        report("PHONE_DETECTED",
                               f"Phone recording attempt: {reason}. File auto-closed.",
                               risk="HIGH", blocked=True)
                        _write_phone_flag()
                        show_alert_nonblocking(
                            "XAI-ITD-DLP Security — Recording Detected",
                            f"⊘ PHONE RECORDING DETECTED\n\n{reason}\n\n"
                            "Someone is attempting to photograph or record\n"
                            "the screen using an external device.\n\n"
                            "The file has been closed automatically.\n"
                            "This incident has been logged and reported to your manager."
                        )
            except Exception as e:
                print(f"[AGENT] Detection error: {e}")

        was_file_open = file_open

    if cap:
        cap.release()


# ── USB MONITOR ───────────────────────────────────────────────────────────────
known_drives = set()


def get_removable_drives():
    drives = set()
    for p in psutil.disk_partitions(all=False):
        if 'removable' in p.opts.lower():
            drives.add(p.device)
    return drives


def eject_drive(drive):
    if not WINDOWS:
        return
    try:
        letter = drive.replace("\\", "").replace("/", "").rstrip(":")
        subprocess.run(["mountvol", letter + ":\\", "/p"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def usb_monitor_loop():
    global known_drives
    known_drives = get_removable_drives()
    print("[AGENT] ✅ USB monitor active — USB ports BLOCKED")
    while RUNNING:
        time.sleep(3)
        try:
            current = get_removable_drives()
            for drive in current - known_drives:
                show_alert_nonblocking(
                    "XAI-ITD-DLP Security — USB BLOCKED",
                    f"⊘ USB PORT IS BLOCKED\n\nDrive: {drive}\n\n"
                    "USB storage devices are prohibited under company security policy.\n"
                    "The device is being ejected automatically.\n\n"
                    "This incident has been logged and reported to your manager."
                )
                report("USB_INSERTED",
                       f"USB inserted: {drive} — auto-ejected per policy.",
                       risk="HIGH", blocked=True)
                print(f"[AGENT] ⊘ USB BLOCKED + EJECTING: {drive}")
                eject_drive(drive)

            for drive in known_drives - current:
                report("USB_REMOVED", f"USB removed: {drive}", risk="LOW")
                print(f"[AGENT] USB removed: {drive}")

            known_drives = current
        except Exception:
            pass


# ── FILE MONITOR ──────────────────────────────────────────────────────────────
if WATCHDOG:
    class SensitiveFileHandler(FileSystemEventHandler):
        def _is_sensitive(self, path):
            return os.path.splitext(path)[1].lower() in SENSITIVE_EXTENSIONS

        def on_modified(self, event):
            if not event.is_directory and self._is_sensitive(event.src_path):
                report("FILE_MODIFIED", f"Modified: {os.path.basename(event.src_path)}", risk="MEDIUM")
                print(f"[AGENT] FILE_MODIFIED: {os.path.basename(event.src_path)}")

        def on_moved(self, event):
            report("FILE_MOVED",
                   f"Moved: {os.path.basename(event.src_path)} → {os.path.basename(event.dest_path)}",
                   risk="HIGH")
            print(f"[AGENT] FILE_MOVED: {os.path.basename(event.src_path)}")

        def on_deleted(self, event):
            if not event.is_directory and self._is_sensitive(event.src_path):
                report("FILE_DELETED", f"Deleted: {os.path.basename(event.src_path)}", risk="HIGH")
                print(f"[AGENT] FILE_DELETED: {os.path.basename(event.src_path)}")

        def on_created(self, event):
            if not event.is_directory and self._is_sensitive(event.src_path):
                report("FILE_CREATED", f"Created: {os.path.basename(event.src_path)}", risk="MEDIUM")
                print(f"[AGENT] FILE_CREATED: {os.path.basename(event.src_path)}")


def start_file_monitor():
    if not WATCHDOG:
        return None
    observer = Observer()
    handler  = SensitiveFileHandler()
    for path in MONITORED_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
    observer.start()
    print("[AGENT] ✅ File monitor active on Documents, Desktop, Downloads")
    return observer


# ── ACTIVE WINDOW ─────────────────────────────────────────────────────────────
last_window = ""

def active_window_loop():
    global last_window
    print("[AGENT] ✅ Active window monitor active")
    while RUNNING:
        time.sleep(5)
        if not WINDOWS:
            continue
        try:
            hwnd  = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(hwnd)
            if title and title != last_window:
                last_window = title
                report("ACTIVE_WINDOW", f"Window: {title}", risk="LOW")
                print(f"[AGENT] Window: {title}")
        except Exception:
            pass


# ── HEARTBEAT ─────────────────────────────────────────────────────────────────
def heartbeat_loop():
    print("[AGENT] ✅ Heartbeat active")
    while RUNNING:
        report("HEARTBEAT", f"Agent active — {USER_NAME}", risk="LOW")
        print("[AGENT] ♥ Heartbeat")
        time.sleep(HEARTBEAT_INTERVAL)


# ── MAIN ──────────────────────────────────────────────────────────────────────
def start_agent(email, token, name="Employee"):
    global RUNNING
    RUNNING = True
    set_session(email, token, name)

    print("=" * 60)
    print(f"  XAI-ITD-DLP Monitoring Agent — {name}")
    print("=" * 60)
    print("  ALLOWED  : Ctrl+C, Ctrl+V, Ctrl+X  ← copy/paste enabled")
    print("  BLOCKED  : PrintScreen, Snipping Tool, Screenshots")
    print("  BLOCKED  : USB ports")
    print("  BLOCKED  : Camera apps, Phone-as-webcam, OBS, ShareX etc.")
    print("  DETECTED : Phone near screen (OpenCV)")
    print("  MONITORED: Files, Active window, Clipboard bitmaps, Heartbeat")
    print("=" * 60 + "\n")

    report("AGENT_STARTED", f"Monitoring agent started for {name}.", risk="LOW")

    threads = [
        threading.Thread(target=usb_monitor_loop,       daemon=True),
        threading.Thread(target=clipboard_watcher_loop,  daemon=True),
        threading.Thread(target=active_window_loop,      daemon=True),
        threading.Thread(target=heartbeat_loop,          daemon=True),
        threading.Thread(target=win_snip_blocker_loop,   daemon=True),
        threading.Thread(target=camera_blocker_loop,     daemon=True),
        threading.Thread(target=phone_detection_loop,    daemon=True),
    ]
    for t in threads:
        t.start()

    kb_listener = start_keyboard_blocker()
    observer    = start_file_monitor()

    try:
        while RUNNING:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        RUNNING = False
        if observer:
            try: observer.stop(); observer.join(timeout=3)
            except Exception: pass
        if kb_listener:
            try: kb_listener.stop()
            except Exception: pass
        report("AGENT_STOPPED", "Agent stopped.", risk="LOW")
        print("\n[AGENT] Stopped.")


# ── STANDALONE ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    TOKEN_FILE = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "session_token.json"
    )
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            s = json.load(f)
        email = s["email"]
        token = s["token"]
        name  = s.get("name", "Employee")
        print(f"Auto-loaded: {name} ({email})")
    else:
        email = input("Employee email: ").strip()
        token = input("Session token:  ").strip()
        name  = input("Your name:      ").strip() or "Employee"

    start_agent(email, token, name)