import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import MONITORED_PATHS, SUSPICIOUS_EXTENSIONS, ALERT_THRESHOLD
from engine.alert_engine import alert_system
from utils.hashing import calculate_sha256

class SecurityEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        self._process(event, "Fichier Créé")

    def on_modified(self, event):
        self._process(event, "Fichier Modifié")

    def _process(self, event, action):
        if event.is_directory:
            return

        filename = event.src_path
        ext = os.path.splitext(filename)[1].lower()

        if ext in SUSPICIOUS_EXTENSIONS:
            # Calcul du hash
            file_hash = calculate_sha256(filename)
            
            # Détermination du type d'événement pour le scoring
            event_type = "FILE_CREATED_GENERIC"
            path_lower = filename.lower()
            
            if "appdata" in path_lower:
                event_type = "FILE_CREATED_APPDATA"
            elif "startup" in path_lower:
                event_type = "FILE_CREATED_STARTUP"
            elif "system32" in path_lower:
                event_type = "FILE_CREATED_SYSTEM"

            alert_system.process_event(
                event_type=event_type,
                title=f"⚠️ Activité Suspecte sur Fichier ({action})",
                description=f"Un fichier avec une extension sensible ({ext}) a été détecté.",
                level="WARNING",
                fields={
                    "Fichier": filename,
                    "Action": action,
                    "Extension": ext,
                    "SHA256": file_hash if file_hash else "Erreur lecture"
                },
                file_path=filename,
                file_hash=file_hash
            )

class FileMonitor:
    def __init__(self):
        self.observer = Observer()
        self.handler = SecurityEventHandler()

    def start(self):
        print("Démarrage du moniteur de fichiers...")
        for path in MONITORED_PATHS:
            if os.path.exists(path):
                # Check préliminaire de permission pour éviter le crash de watchdog
                if not self._check_permission(path):
                    print(f" -> 🚫 Permission refusée (Ignoré) : {path} (Essayez via Admin)")
                    continue

                try:
                    self.observer.schedule(self.handler, path, recursive=True)
                    print(f" -> Surveillance activée : {path}")
                except Exception as e:
                    print(f"Erreur surveillance {path}: {e}")
            else:
                print(f" -> Chemin introuvable (ignoré) : {path}")
        
        try:
            self.observer.start()
        except PermissionError:
            print("❌ Erreur Fatale: Impossible de démarrer le moniteur de fichiers (Droits insuffisants?)")
        except Exception as e:
            print(f"❌ Erreur Fatale Watchdog: {e}")

    def _check_permission(self, path):
        """Vérifie si on peut lire le dossier pour éviter que Watchdog ne crash au start()"""
        try:
            # Test simple de listing
            os.listdir(path)
            return True
        except PermissionError:
            return False
        except Exception:
            # En cas d'autre erreur, on laisse le bénéfice du doute ou on ignore
            return True # On tente quand même si ce n'est pas une erreur de permission explicite

    def stop(self):
        self.observer.stop()
        self.observer.join()
