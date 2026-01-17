# 🛡️ Sentinel - Intelligent Security Agent

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

**An intelligent, local HIDS (Host-based Intrusion Detection System) for Windows.**  
_Detects anomalies, monitors persistence, and alerts via Discord without compromising privacy._

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Architecture](#-architecture)

</div>

---

## 📖 Overview

**Sentinel** is a lightweight, open-source security agent designed for Blue Teamers, students, and privacy-conscious users. Unlike commercial checking tools, Sentinel runs entirely locally on your machine. It monitors sensitive system areas (AppData, Registry, Network) and uses a **Threat Score System** to evaluate incidents before alerting you.

> **Zero Spyware Logic**: No keylogging, no screen capture, no personal data exfiltration. Only metadata about suspicious system events is analyzed.

## 🚀 Features

### 🧠 Core Intelligence

- **Threat Scoring Engine**: Every event is assigned a risk score. Alerts are triggered only when the cumulative risk threshold is breached (prevents spam).
- **Smart Whitelisting**: Ignores trusted processes (Chrome, System) and supports SHA256 hash allow-listing.
- **Local JSON Logging**: Full forensic trail stored locally (`logs/security_events.json`) for post-incident analysis.

### 👁️ Monitoring Modules

| Module             | Description                                                                                                                                                 |
| :----------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **📂 File System** | Monitors creation of executable files (`.exe`, `.dll`, `.ps1`) in sensitive folders (`AppData`, `Startup`, `Temp`). Automatically calculates SHA256 hashes. |
| **⚙️ Processes**   | Detects suspicious process spawns, execution from non-standard paths, and "Office-spawning-Shell" attacks (Anti-Evasion).                                   |
| **🗝️ Registry**    | Real-time surveillance of persistence mechanisms: `Run`, `RunOnce`, and new **Services** creation.                                                          |
| **🌐 Network**     | Identifies outbound connections initiated by suspicious or unknown processes.                                                                               |
| **🔌 Power**       | Detects "Wake-up" events, often used by malware to execute tasks when the user returns.                                                                     |

## 🛠️ Installation

### Prerequisites

- **Windows 10 / 11**
- **Python 3.8+**

### Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/username/sentinel-agent.git
   cd sentinel-agent
   ```

2. **Install dependencies**

   # 🛡️ Sentinel - Intelligent Security Agent

   <div align="center">

   ![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
   ![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?style=for-the-badge&logo=windows&logoColor=white)
   ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
   ![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

   **An intelligent, local HIDS (Host-based Intrusion Detection System) for Windows.**  
   _Detects anomalies, monitors persistence, and alerts via Discord without compromising privacy._

   [Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Architecture](#-architecture)

   </div>

   ***

   ## 📖 Overview

   **Sentinel** is a lightweight, open-source security agent designed for Blue Teamers, students, and privacy-conscious users. Unlike commercial checking tools, Sentinel runs entirely locally on your machine. It monitors sensitive system areas (AppData, Registry, Network) and uses a **Threat Score System** to evaluate incidents before alerting you.

   > **Zero Spyware Logic**: No keylogging, no screen capture, no personal data exfiltration. Only metadata about suspicious system events is analyzed.

   ## 🚀 Features

   ### 🧠 Core Intelligence
   - **Threat Scoring Engine**: Every event is assigned a risk score. Alerts are triggered only when the cumulative risk threshold is breached (prevents spam).
   - **Smart Whitelisting**: Ignores trusted processes (Chrome, System) and supports SHA256 hash allow-listing.
   - **Local JSON Logging**: Full forensic trail stored locally (`logs/security_events.json`) for post-incident analysis.

   ### 👁️ Monitoring Modules

   | Module             | Description                                                                                                                                                 |
   | :----------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | **📂 File System** | Monitors creation of executable files (`.exe`, `.dll`, `.ps1`) in sensitive folders (`AppData`, `Startup`, `Temp`). Automatically calculates SHA256 hashes. |
   | **⚙️ Processes**   | Detects suspicious process spawns, execution from non-standard paths, and "Office-spawning-Shell" attacks (Anti-Evasion).                                   |
   | **🗝️ Registry**    | Real-time surveillance of persistence mechanisms: `Run`, `RunOnce`, and new **Services** creation.                                                          |
   | **🌐 Network**     | Identifies outbound connections initiated by suspicious or unknown processes.                                                                               |
   | **🔌 Power**       | Detects "Wake-up" events, often used by malware to execute tasks when the user returns.                                                                     |

   ## 🛠️ Installation

   ### Prerequisites
   - **Windows 10 / 11**
   - **Python 3.8+**

   ### Quick Start
   1. **Clone the repository**

      ```bash
      git clone https://github.com/username/sentinel-agent.git
      cd sentinel-agent
      ```

   2. **Install dependencies**

      # 🛡️ Sentinel - Intelligent Security Agent

      <div align="center">

      ![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
      ![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?style=for-the-badge&logo=windows&logoColor=white)
      ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
      ![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

      **An intelligent, local HIDS (Host-based Intrusion Detection System) for Windows.**  
      *Detects anomalies, monitors persistence, and alerts via Discord without compromising privacy.*

      [Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Architecture](#-architecture)

      </div>

      ---

      ## 📖 Overview

      **Sentinel** is a lightweight, open-source security agent designed for Blue Teamers, students, and privacy-conscious users. Unlike commercial checking tools, Sentinel runs entirely locally on your machine. It monitors sensitive system areas (AppData, Registry, Network) and uses a **Threat Score System** to evaluate incidents before alerting you.

      > **Zero Spyware Logic**: No keylogging, no screen capture, no personal data exfiltration. Only metadata about suspicious system events is analyzed.

      ## 🚀 Features

      ### 🧠 Core Intelligence

      - **Threat Scoring Engine**: Every event is assigned a risk score. Alerts are triggered only when the cumulative risk threshold is breached (prevents spam).
      - **Smart Whitelisting**: Ignores trusted processes (Chrome, System) and supports SHA256 hash allow-listing.
      - **Local JSON Logging**: Full forensic trail stored locally (`logs/security_events.json`) for post-incident analysis.

      ### 👁️ Monitoring Modules

      | Module             | Description                                                                                                                                                 |
      | :----------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
      | **📂 File System** | Monitors creation of executable files (`.exe`, `.dll`, `.ps1`) in sensitive folders (`AppData`, `Startup`, `Temp`). Automatically calculates SHA256 hashes. |
      | **⚙️ Processes**   | Detects suspicious process spawns, execution from non-standard paths, and "Office-spawning-Shell" attacks (Anti-Evasion).                                   |
      | **🗝️ Registry**    | Real-time surveillance of persistence mechanisms: `Run`, `RunOnce`, and new **Services** creation.                                                          |
      | **🌐 Network**     | Identifies outbound connections initiated by suspicious or unknown processes.                                                                               |
      | **🔌 Power**       | Detects "Wake-up" events, often used by malware to execute tasks when the user returns.                                                                     |

      ## 🛠️ Installation

      ### Prerequisites

      - **Windows 10 / 11**
      - **Python 3.8+**

      ### Quick Start

      1. **Clone the repository**

         ```bash
         git clone https://github.com/username/sentinel-agent.git
         cd sentinel-agent
         ```

      2. **Install dependencies**

         ```bash
         pip install -r requirements.txt
         ```

      3. **Configure the Agent**
         Open `config.py` and set your Discord Webhook URL:
         ```python
         DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
         ```

      4. **Run**
         ```bash
         python main.py
         ```

      ## ⚙️ Configuration (`config.py`)

      You can fine-tune the agent's behavior to suit your needs:

      - **`ALERT_THRESHOLD`**: Adjust sensitivity (Default: `50`). Lower means more alerts.
      - **`WHITELIST_PATHS`**: Add full paths of trusted applications to ignore.
      - **`MONITORED_PATHS`**: customize which directories are watched.

      ## Architecture

      ```mermaid
      graph TD
          A[Main Loop] --> B(File Monitor)
          A --> C(Process Monitor)
          A --> D(Registry Monitor)
          A --> E(Network Monitor)
    
          B & C & D & E --> F{Threat Engine}
          F -- Check Whitelist --> G[Ignore]
          F -- Calculate Score --> H[Local Log (JSON)]
    
          H --> I{Score > Threshold?}
          I -- Yes --> J[Discord Alert 🚨]
          I -- No --> K[Silent Log]
      ```

      ## 🔐 Security & Ethics

      This tool is designed for **Defensive Security** purposes.
      - **Data Privacy**: All analysis happens locally. No data is sent to the cloud except structured alerts to your private Discord Webhook.
      - **Permissions**: Some modules (like System32 Task monitoring) require Administrator privileges to function fully.

      ## 🤝 Contributing

      Contributions are welcome! Please feel free to submit a Pull Request.

      1. Fork the project
      2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
      3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
      4. Push to the branch (`git push origin feature/AmazingFeature`)
      5. Open a Pull Request

      ## 📄 License

      Distributed under the MIT License. See `LICENSE` for more information.

      ---

      <div align="center">
        <sub>Built with ❤️ for Cyber Security Education</sub>
      </div>
