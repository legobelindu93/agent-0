import time
import datetime
from engine.alert_engine import alert_system

class PowerMonitor:
    def __init__(self):
        self.last_tick = time.time()
        # Seuil de détection de mise en veille (si le temps saute de plus de 10s alors qu'on sleep 2s)
        self.suspension_threshold = 10 

    def run_check(self):
        current_time = time.time()
        delta = current_time - self.last_tick

        # Si le delta est significativement plus grand que l'intervalle de check (ex: > 5-10 sec)
        # C'est qu'on sort probablement de veille
        if delta > self.suspension_threshold:
            duration = datetime.timedelta(seconds=int(delta))
            alert_system.process_event(
                event_type="SYSTEM_WAKEUP",
                title="⚡ Changement d'État Système",
                description=f"Le système semble sortir de veille.",
                level="INFO",
                fields={
                    "Temps écoulé (approx veille)": str(duration),
                    "Heure reprise": datetime.datetime.now().strftime("%H:%M:%S")
                }
            )

        self.last_tick = current_time

    def log_startup(self):
         alert_system.process_event(
            event_type="AGENT_STARTUP",
            title="🟢 Démarrage de l'Agent",
            description="L'agent de surveillance est actif.",
            level="SUCCESS"
        )

    def log_shutdown(self):
        alert_system.process_event(
            event_type="AGENT_SHUTDOWN",
            title="🔴 Arrêt de l'Agent",
            description="L'agent de surveillance s'arrête.",
            level="WARNING"
        )
