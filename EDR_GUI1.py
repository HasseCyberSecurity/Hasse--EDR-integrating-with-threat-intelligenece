import os
import psutil
import hashlib
import requests
import json
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import time
import threading
import subprocess

# ---------------- CONFIG -----------------
OTX_API_KEY = "YOUR_OTX_API_KEY"
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}
USERNAME = "admin"
PASSWORD = "hasse"
SUSPICIOUS_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/opt"]
LOGO_PATH = "hasse_logo.png"
# -----------------------------------------

def get_sha256(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def fetch_threat_feed():
    try:
        response = requests.get(OTX_URL, headers=HEADERS)
        data = response.json()
        names, hashes = set(), set()
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                if indicator["type"] == "FileHash-SHA256":
                    hashes.add(indicator["indicator"].lower())
                elif indicator["type"] in ["FilePath", "FileHash-MD5"]:
                    names.add(indicator["indicator"].lower())
        return list(names), list(hashes)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch threat feed:\n{e}")
        return [], []

def scan_processes(name_feed, hash_feed):
    results = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            info = proc.info
            exe = info.get('exe')
            name = info['name']
            pid = info['pid']
            user = info['username']
            if not exe or not os.path.exists(exe):
                continue
            hash_val = get_sha256(exe)
            suspicious = False
            reasons = []

            if any(exe.startswith(d) for d in SUSPICIOUS_DIRS):
                suspicious = True
                reasons.append("Suspicious directory")

            if name.lower() in name_feed:
                suspicious = True
                reasons.append("Name match in threat feed")

            if hash_val and hash_val.lower() in hash_feed:
                suspicious = True
                reasons.append("Hash match in threat feed")

            results.append({
                "pid": pid,
                "name": name,
                "exe": exe,
                "user": user,
                "sha256": hash_val,
                "suspicious": suspicious,
                "reasons": ", ".join(reasons)
            })
        except:
            continue
    return results

def detect_usb_devices():
    usb_mounts = []
    with open('/proc/mounts', 'r') as f:
        for line in f:
            parts = line.split()
            device, mount_point = parts[0], parts[1]
            if "/media" in mount_point or "/run/media" in mount_point:
                usb_mounts.append(mount_point)
    return usb_mounts

def scan_usb_for_malware(mount_path, hash_feed):
    findings = []
    for root, dirs, files in os.walk(mount_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                hash_val = get_sha256(full_path)
                if hash_val and hash_val.lower() in hash_feed:
                    findings.append({
                        "path": full_path,
                        "sha256": hash_val,
                        "reason": "USB file hash matched threat feed"
                    })
            except:
                continue
    return findings

def kill_process(pid):
    try:
        os.kill(pid, 9)
        return True
    except:
        return False

def isolate_network():
    try:
        os.system("nmcli networking off")
        return True
    except:
        return False

def unmount_usb(mount_point):
    try:
        subprocess.run(["umount", mount_point], check=True)
        return True
    except:
        return False

class ModernStyle:
    @staticmethod
    def apply():
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background="#2e2e2e",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#2e2e2e",
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                        background="#444",
                        foreground="white",
                        font=("Segoe UI", 11, "bold"))
        style.configure("TButton",
                        padding=6,
                        font=("Segoe UI", 10))
        style.map("TButton",
                  background=[("active", "#5e5e5e")],
                  foreground=[("active", "white")])
        style.configure("TLabel",
                        background="#1e1e1e",
                        foreground="white",
                        font=("Segoe UI", 11))

class StatusHeader(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f4f4f4", height=120)
        self.pack(fill="x")

        self.icon = tk.Label(self, text="✅", font=("Segoe UI", 20), bg="#f4f4f4", fg="green")
        self.icon.grid(row=0, column=0, padx=20, pady=10)

        self.status_text = tk.Label(self, text="Your device is protected", font=("Segoe UI", 16, "bold"), bg="#f4f4f4", fg="#2d2d2d")
        self.status_text.grid(row=0, column=1, sticky="w")

        self.substatus_1 = tk.Label(self, text="No malware or PUAs found", font=("Segoe UI", 12), bg="#f4f4f4", fg="#555")
        self.substatus_1.grid(row=1, column=1, sticky="w")

        self.scan_button = ttk.Button(self, text="Scan", command=parent.run_scan)
        self.scan_button.grid(row=1, column=2, padx=20)

        self.substatus_2 = tk.Label(self, text="Data protection is on", font=("Segoe UI", 12), bg="#f4f4f4", fg="#555")
        self.substatus_2.grid(row=2, column=1, sticky="w")

        self.grid_columnconfigure(1, weight=1)

class ThreatGUI(tk.Frame):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.root.title("Threat Response Console")
        self.root.geometry("1100x700")
        self.root.configure(bg="#ffffff")
        ModernStyle.apply()

        self.status = StatusHeader(self)
        self.status.pack()

        ttk.Label(root, text="Threat Detection Results", font=("Segoe UI", 14, "bold")).pack(pady=(10, 0))

        self.tree = ttk.Treeview(root, columns=("Source", "PID/File", "User", "Name", "Path", "Suspicious", "Reason"), show="headings")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Isolate System \U0001f512", command=self.do_isolate).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Kill Selected ☠️", command=self.do_kill_selected).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Block USB \U0001f6d1", command=self.do_block_usb).pack(side="left", padx=5)

        self.log = tk.Text(root, height=8, bg="#2e2e2e", fg="white", font=("Consolas", 10))
        self.log.pack(fill="both", expand=False, padx=10, pady=5)

        self.last_devices = set()
        threading.Thread(target=self.monitor_usb_loop, daemon=True).start()

    def log_event(self, text):
        self.log.insert("end", f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {text}\n")
        self.log.see("end")

    def run_scan(self):
        self.tree.delete(*self.tree.get_children())
        name_feed, hash_feed = fetch_threat_feed()
        results = scan_processes(name_feed, hash_feed)
        for r in results:
            if r['suspicious']:
                self.tree.insert("", "end", values=("Process", r['pid'], r['user'], r['name'], r['exe'], "Yes", r['reasons']))
                self.log_event(f"Suspicious process detected: {r['name']} - {r['reasons']}")

        for mount in detect_usb_devices():
            findings = scan_usb_for_malware(mount, hash_feed)
            for f in findings:
                self.tree.insert("", "end", values=("USB", "-", "-", os.path.basename(f['path']), f['path'], "Yes", f['reason']))
                self.log_event(f"Threat found on USB: {f['path']} - {f['reason']}")

    def do_kill_selected(self):
        selected = self.tree.selection()
        for item in selected:
            values = self.tree.item(item, "values")
            if values[0] == "Process":
                pid = int(values[1])
                if kill_process(pid):
                    self.log_event(f"Killed process PID {pid}")
                else:
                    self.log_event(f"Failed to kill process PID {pid}")

    def do_isolate(self):
        if isolate_network():
            self.log_event("System network isolated")
        else:
            self.log_event("Failed to isolate network")

    def do_block_usb(self):
        for mount in detect_usb_devices():
            if unmount_usb(mount):
                self.log_event(f"Unmounted USB: {mount}")
            else:
                self.log_event(f"Failed to unmount USB: {mount}")

    def monitor_usb_loop(self):
        while True:
            current_devices = set(detect_usb_devices())
            new_devices = current_devices - self.last_devices
            for device in new_devices:
                self.log_event(f"New USB device detected: {device}")
            self.last_devices = current_devices
            time.sleep(5)

class LoginForm:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("300x200")
        self.root.configure(bg="#f4f4f4")

        tk.Label(root, text="Username", bg="#f4f4f4").pack(pady=(20, 5))
        self.username_entry = tk.Entry(root)
        self.username_entry.pack()

        tk.Label(root, text="Password", bg="#f4f4f4").pack(pady=(10, 5))
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        tk.Button(root, text="Login", command=self.check_login).pack(pady=20)

    def check_login(self):
        if self.username_entry.get() == USERNAME and self.password_entry.get() == PASSWORD:
            self.root.destroy()
            main_root = tk.Tk()
            app = ThreatGUI(main_root)
            app.pack(fill="both", expand=True)
            main_root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

if __name__ == "__main__":
    login_root = tk.Tk()
    LoginForm(login_root)
    login_root.mainloop()
