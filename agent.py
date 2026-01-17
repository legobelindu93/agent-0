import os
import time
import psutil
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WEBHOOK_URL = "TON_WEBHOOK_DISCORD"

SUSPICIOUS_DIRS = [
    os.getenv("APPDATA"),
    os.getenv("TEMP"),
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
]

SUSPICIOUS_EXT = [".exe", ".dll", ".bat", ".ps1"]

def send_alert(msg):
    requests.post(WEBHOOK_URL, json={"content": msg})

def is_suspicious_file(path):
    path = path.lower()
    return any(path.startswith(d.lower()) for d in SUSPICIOUS_DIRS if d) and \
           any(path.endswith(ext) for ext in SUSPICIOUS_EXT)

class FileWatcher(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if is_suspicious_file(event.src_path):
            send_alert(
                f"🚨 **FICHIER SUSPECT CRÉÉ**\n"
                f"`{event.src_path}`"
            )

def suspicious_process(proc):
    try:
        exe = proc.exe().lower()
        return is_suspicious_file(exe)
    except:
        return False

def monitor_processes():
    known = set()
    while True:
        time.sleep(3)
        for p in psutil.process_iter(['pid', 'name']):
            if p.pid not in known:
                known.add(p.pid)
                if suspicious_process(p):
                    send_alert(
                        f"🚨 **PROCESSUS SUSPECT**\n"
                        f"Nom : `{p.name()}`\n"
                        f"Chemin : `{p.exe()}`"
                    )

if __name__ == "__main__":
    send_alert("🛡️ **Agent sécurité démarré (Mode Intelligent)**")

    observer = Observer()
    watcher = FileWatcher()

    for d in SUSPICIOUS_DIRS:
        if d and os.path.exists(d):
            observer.schedule(watcher, d, recursive=True)

    observer.start()

    try:
        monitor_processes()
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
