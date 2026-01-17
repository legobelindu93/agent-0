import os
import time
from config import THREAT_SCORES, ALERT_THRESHOLD, WHITELIST_PATHS, WHITELIST_HASHES

class ThreatEngine:
    def __init__(self):
        self.whitelist_paths = [os.path.normpath(p).lower() for p in WHITELIST_PATHS]
        self.whitelist_hashes = set(WHITELIST_HASHES)
        
        # Historique des scores: list of (timestamp, score)
        self.score_history = []
        self.history_window = 300  # 5 minutes

    def is_whitelisted(self, file_path, file_hash=None):
        if file_path:
            norm_path = os.path.normpath(file_path).lower()
            if norm_path in self.whitelist_paths:
                return True
        
        if file_hash and file_hash in self.whitelist_hashes:
            return True
        
        return False

    def calculate_score(self, event_type):
        return THREAT_SCORES.get(event_type, 0)

    def _update_history(self, score):
        now = time.time()
        # Ajouter le nouveau score
        if score > 0:
            self.score_history.append((now, score))
        
        # Nettoyer les vieux scores (> window)
        self.score_history = [(t, s) for t, s in self.score_history if now - t <= self.history_window]

    def get_total_threat_score(self):
        return sum(s for t, s in self.score_history)

    def evaluate_incident(self, event_type, details):
        """
        Retourne (is_alertable, event_score, total_score)
        """
        event_score = self.calculate_score(event_type)
        
        # Update history
        self._update_history(event_score)
        
        total_score = self.get_total_threat_score()
        
        # Alerte si le score de l'événement est critique OU si le cumul est élevé
        is_alertable = (event_score >= ALERT_THRESHOLD) or (total_score >= ALERT_THRESHOLD)
        
        return is_alertable, event_score, total_score

threat_engine = ThreatEngine()
