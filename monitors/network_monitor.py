import psutil
import socket
from config import SUSPICIOUS_PROCESS_NAMES, SUSPICIOUS_PROCESS_PATHS
from engine.alert_engine import alert_system
import os

class NetworkMonitor:
    def __init__(self):
        self.known_connections = set() # (pid, laddr, raddr)

    def run_check(self):
        try:
            # On récupère les connexions INET (ipv4/ipv6), TCP/UDP
            connections = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return

        for conn in connections:
            if conn.status == 'ESTABLISHED' or conn.status == 'SYN_SENT':
                self.check_connection(conn)

    def check_connection(self, conn):
        pid = conn.pid
        if not pid:
            return

        # Clé unique pour éviter de spammer pour la même connexion
        # (pid, laddr_ip, laddr_port, raddr_ip, raddr_port)
        conn_key = (
            pid, 
            conn.laddr.ip, conn.laddr.port, 
            conn.raddr.ip if conn.raddr else None, 
            conn.raddr.port if conn.raddr else None
        )

        if conn_key in self.known_connections:
            return

        self.known_connections.add(conn_key)
        
        # Limiter la taille du cache
        if len(self.known_connections) > 5000:
            self.known_connections.clear()

        # Analyser le processus
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            proc_path = proc.exe()

            is_suspicious = False
            reason = ""
            event_type = ""

            # Check 1: Nom
            if proc_name in SUSPICIOUS_PROCESS_NAMES:
                is_suspicious = True
                reason = "Processus sensible (Nom)"
                event_type = "NETWORK_SUSPICIOUS"

            # Check 2: Path
            if proc_path:
                for susp_path in SUSPICIOUS_PROCESS_PATHS:
                    if os.path.normpath(susp_path).lower() in os.path.normpath(proc_path).lower():
                        is_suspicious = True
                        reason = "Processus dans dossier suspect (AppData/Temp)"
                        event_type = "NETWORK_SUSPICIOUS"
                        break

            if is_suspicious:
                 alert_system.process_event(
                    event_type=event_type,
                    title="🌐 Connexion Réseau Suspecte",
                    description=f"Un processus suspect a initié une connexion réseau.",
                    level="WARNING",
                    fields={
                        "Processus": f"{proc_name} (PID: {pid})",
                        "Raison": reason,
                        "Destination": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        "Status": conn.status
                    },
                    file_path=proc_path
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
