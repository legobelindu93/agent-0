import os

# Configuration Discord
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1455362179212509184/8UvtJ4Zf_3MyZzCOuMtZ5C-2MXFwxo7ScHo8XAHe-OJNK5u5u3u8fgjZw5ptRfdSzZU5"

# Configuration des Logs
LOG_DIR = os.path.join(os.getcwd(), "logs")
LOG_FILE = "security_events.json"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 5

# Configuration des alertes
ALERT_LEVELS = {
    "INFO": 0x3498db,
    "WARNING": 0xf1c40f,
    "CRITICAL": 0xe74c3c,
    "SUCCESS": 0x2ecc71
}

# Système de Score de Menace (Threat Score)
# Seuil pour déclencher une alerte Discord (sinon juste Log)
ALERT_THRESHOLD = 50

THREAT_SCORES = {
    "FILE_CREATED_APPDATA": 30,
    "FILE_CREATED_STARTUP": 70,
    "FILE_CREATED_SYSTEM": 60,
    "PROCESS_SUSPICIOUS_LOCATION": 50,
    "PROCESS_SUSPICIOUS_NAME": 40,
    "NETWORK_SUSPICIOUS": 30,
    "REGISTRY_PERSISTENCE_NEW": 80,
    "REGISTRY_PERSISTENCE_MODIFIED": 60,
    "SYSTEM_WAKEUP": 10,
    "AGENT_STARTUP": 0
}

# Surveillance Fichiers
MONITORED_PATHS = [
    os.path.expandvars(r"%APPDATA%"),
    os.path.expandvars(r"%LOCALAPPDATA%"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%SystemRoot%\System32\Tasks"), # Tâches planifiées
]

SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".scr", ".cmd", ".psm1"]

# Whitelist Intelligente
# Chemins ou Processus à ignorer
WHITELIST_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Windows\System32\svchost.exe",
    os.path.expandvars(r"%APPDATA%\Discord\Update.exe"),
]

WHITELIST_HASHES = [
    # Ajoutez ici des SHA256 connus sûrs si besoin
]

# Surveillance Processus
SUSPICIOUS_PROCESS_NAMES = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "net.exe", "whoami.exe", "bitsadmin.exe", "certutil.exe"]
SUSPICIOUS_PROCESS_PATHS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%APPDATA%"),
    os.path.expandvars(r"%PUBLIC%"),
]

# Surveillance Registre (Ajout Services)
MONITORED_REGISTRY_KEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU", "VALUES"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU", "VALUES"),
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM", "VALUES"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM", "VALUES"),
    (r"SYSTEM\CurrentControlSet\Services", "HKLM", "KEYS"), # Mode KEYS pour détecter les nouveaux services
]

# Paramètres généraux
CHECK_INTERVAL = 2
