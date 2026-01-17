import winreg
from config import MONITORED_REGISTRY_KEYS
from engine.alert_engine import alert_system

class RegistryMonitor:
    def __init__(self):
        # Snapshot: { (key_path, hive_str): { name: data } }
        self.snapshots = {}
        self.first_run = True

    def get_registry_content(self, hive, subkey, mode="VALUES"):
        """
        Retrieves either values (name: data) or subkeys (name: "SUBKEY") based on mode.
        """
        content = {}
        reg_hive = winreg.HKEY_CURRENT_USER if hive == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        
        try:
            with winreg.OpenKey(reg_hive, subkey, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        if mode == "VALUES":
                            v_name, v_data, v_type = winreg.EnumValue(key, index)
                            content[v_name] = str(v_data)
                        elif mode == "KEYS":
                            k_name = winreg.EnumKey(key, index)
                            content[k_name] = "SUBKEY"
                        
                        index += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except PermissionError:
            pass

        return content

    def check_changes(self):
        for item in MONITORED_REGISTRY_KEYS:
            if len(item) == 3:
                subkey, hive_str, mode = item
            else:
                subkey, hive_str = item
                mode = "VALUES"

            current_content = self.get_registry_content(hive_str, subkey, mode)
            snapshot_key = (subkey, hive_str)

            if self.first_run:
                self.snapshots[snapshot_key] = current_content
                continue

            previous_content = self.snapshots.get(snapshot_key, {})
            
            # Check additions
            for name, data in current_content.items():
                if name not in previous_content:
                    if mode == "KEYS":
                        # Nouveau Service (ou autre clé)
                        alert_system.process_event(
                            event_type="REGISTRY_PERSISTENCE_NEW_SERVICE",
                            title="⚙️ Nouveau Service Détecté",
                            description=f"Un nouveau service (ou clé registre) a été créé.",
                            level="CRITICAL",
                            fields={
                                "Hive": hive_str,
                                "Chemin Parent": subkey,
                                "Nouveau Service": name
                            }
                        )
                    else:
                        # Nouvelle Valeur (Run)
                        alert_system.process_event(
                            event_type="REGISTRY_PERSISTENCE_NEW",
                            title="🗝️ Persistance Registre Détectée",
                            description="Une nouvelle entrée de démarrage automatique a été ajoutée.",
                            level="CRITICAL",
                            fields={
                                "Hive": hive_str,
                                "Clé": subkey,
                                "Nom Valeur": name,
                                "Donnée": data
                            }
                        )

                elif mode == "VALUES" and previous_content[name] != data:
                    alert_system.process_event(
                        event_type="REGISTRY_PERSISTENCE_MODIFIED",
                        title="🗝️ Persistance Registre Modifiée",
                        description="Une entrée de démarrage existante a été modifiée.",
                        level="WARNING",
                        fields={
                            "Hive": hive_str,
                            "Clé": subkey,
                            "Nom Valeur": name,
                            "Ancienne Donnée": previous_content[name],
                            "Nouvelle Donnée": data
                        }
                    )
            
            # Update snapshot
            self.snapshots[snapshot_key] = current_content
        
        if self.first_run:
            self.first_run = False

    def run_check(self):
        self.check_changes()
