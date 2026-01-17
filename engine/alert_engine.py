import requests
import datetime
import socket
import platform
from config import DISCORD_WEBHOOK_URL, ALERT_LEVELS
from engine.logger import agent_logger
from engine.threat_engine import threat_engine

class AlertEngine:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"

    def process_event(self, event_type, title, description, level="INFO", fields=None, file_path=None, file_hash=None):
        """
        Traite un événement : Loggue, calcule le score, et alerte si nécessaire.
        """
        if fields is None:
            fields = {}

        # 1. Check Whitelist
        if threat_engine.is_whitelisted(file_path, file_hash):
            agent_logger.log_event("INFO", f"Événement whitelisté : {title}", alert_type=event_type, score=0, details=fields)
            return

        # 2. Score
        is_alertable, event_score, total_score = threat_engine.evaluate_incident(event_type, fields)
        fields["Event Score"] = event_score
        fields["Total Threat Score"] = total_score

        # 3. Log
        agent_logger.log_event(level, title, alert_type=event_type, score=event_score, details=fields)

        # 4. Alert Discord
        if is_alertable or level == "CRITICAL":
            self._send_discord_alert(title, description, level, fields, event_score, total_score)

    def _send_discord_alert(self, title, description, level, fields, event_score, total_score):
        if not DISCORD_WEBHOOK_URL or "VOTRE_WEBHOOK" in DISCORD_WEBHOOK_URL:
            # print(f"[LOCAL ALERT] {title} (Score: {event_score}/{total_score})")
            return

        color = ALERT_LEVELS.get(level, ALERT_LEVELS["INFO"])
        
        # Ajout du score dans le titre
        title = f"{title} [Score: {total_score}]"

        embed = {
            "title": f"🛡️ {title}",
            "description": description,
            "color": color,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "footer": {
                "text": f"Agent: {self.hostname} | OS: {self.os_info}"
            },
            "fields": []
        }

        if fields:
            for key, value in fields.items():
                embed["fields"].append({
                    "name": key,
                    "value": str(value)[:1024], # Limite Discord
                    "inline": False 
                })

        payload = {
            "username": "Security Agent",
            "embeds": [embed]
        }

        try:
            requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            print(f"Erreur envoi Discord: {e}")

# Instance globale
alert_system = AlertEngine()
