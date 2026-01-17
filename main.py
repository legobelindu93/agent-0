import time
import sys
from monitors.file_monitor import FileMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.registry_monitor import RegistryMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.power_monitor import PowerMonitor
from config import CHECK_INTERVAL

def main():
    print("=== Agent de Surveillance Sécurité Intelligent ===")
    print("Initialisation des modules...")

    # Instanciation
    file_mon = FileMonitor()
    proc_mon = ProcessMonitor()
    reg_mon = RegistryMonitor()
    net_mon = NetworkMonitor()
    pwr_mon = PowerMonitor()

    # Démarrage
    pwr_mon.log_startup()
    file_mon.start()

    print(f"Agent actif. Intervalle de vérification: {CHECK_INTERVAL}s")
    print("Appuyez sur Ctrl+C pour arrêter.")

    try:
        while True:
            # Cycles de vérification ponctuels
            proc_mon.run_check()
            reg_mon.run_check()
            net_mon.run_check()
            pwr_mon.run_check()

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\nArrêt en cours...")
        pwr_mon.log_shutdown()
        file_mon.stop()
        print("Agent arrêté.")
        sys.exit(0)

if __name__ == "__main__":
    main()
