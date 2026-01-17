import psutil
import time
import os
from config import SUSPICIOUS_PROCESS_NAMES, SUSPICIOUS_PROCESS_PATHS
from engine.alert_engine import alert_system

class ProcessMonitor:
    def __init__(self):
        self.running_pids = set()
        self.first_run = True

    def update_processes(self):
        current_pids = set(psutil.pids())
        
        if self.first_run:
            self.running_pids = current_pids
            self.first_run = False
            return

        new_pids = current_pids - self.running_pids
        
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                self.check_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.running_pids = current_pids

    def check_process(self, proc):
        try:
            proc_name = proc.name().lower()
            proc_path = proc.exe()
            
            event_type = None
            title = ""
            description = ""
            fields = {
                "PID": proc.pid,
                "Nom": proc.name(),
                "Chemin": proc_path,
                "Ligne de commande": " ".join(proc.cmdline())
            }

            # Anti-Evasion: Check Parent
            try:
                parent = proc.parent()
                if parent:
                    fields["Parent PID"] = parent.pid
                    fields["Parent Nom"] = parent.name()
                    
                    # Détection Parent Suspect (ex: Word lançant PowerShell)
                    if parent.name().lower() in ["winword.exe", "excel.exe", "outlook.exe"] and proc_name in ["cmd.exe", "powershell.exe"]:
                        event_type = "PROCESS_SUSPICIOUS_PARENT"
                        title = "🚨 Exécution Suspecte (Parent)"
                        description = f"Le processus {proc_name} a été lancé par une application Office ({parent.name()})."
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Check 1: Nom suspect
            if not event_type and proc_name in SUSPICIOUS_PROCESS_NAMES:
                event_type = "PROCESS_SUSPICIOUS_NAME"
                title = "⚠️ Processus Sensible Détecté"
                description = f"Le processus '{proc_name}' a été lancé."

            # Check 2: Chemin suspect
            if not event_type and proc_path:
                for susp_path in SUSPICIOUS_PROCESS_PATHS:
                    if os.path.normpath(susp_path).lower() in os.path.normpath(proc_path).lower():
                        event_type = "PROCESS_SUSPICIOUS_LOCATION"
                        title = "🚨 Exécution depuis un dossier suspect"
                        description = f"Un processus a été lancé depuis un emplacement potentiellement dangereux."
                        break

            if event_type:
                alert_system.process_event(
                    event_type=event_type,
                    title=title,
                    description=description,
                    level="WARNING" if event_type != "PROCESS_SUSPICIOUS_LOCATION" else "CRITICAL",
                    fields=fields,
                    file_path=proc_path
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def run_check(self):
        self.update_processes()
