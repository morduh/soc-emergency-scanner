# 🛡️ SOC Emergency AI Scanner — "Detection on a Stick"

> **Final Project — Certified SOC Analyst Course**
> A fully offline, USB-portable incident response triage tool powered by a locally hosted AI model.

![Main Interface](docs/images/main%20page.png)

---

## What Is This?

The **SOC Emergency AI Scanner** is a Windows incident response tool designed for real-world deployment in a Security Operations Center (SOC) environment. It allows a SOC analyst to plug in a USB drive to any potentially compromised Windows machine, run a deep forensic scan, and receive an AI-generated incident report — all **without an internet connection** and **without installing anything** on the target machine.

This project was built as a final project for a Certified SOC Analyst course, demonstrating practical knowledge of malware analysis, digital forensics, threat hunting, and security automation.

### The Problem It Solves

When a machine is suspected of compromise, analysts often face a challenge: commercial EDR tools may not be installed, internet access may be blocked or untrusted, and manually reviewing thousands of files is slow and error-prone. This tool bridges that gap by combining:

- **Automated file triage** — scans high-value directories, computes SHA-256 hashes, and scores files based on known malware signatures
- **PE binary analysis** — detects unsigned executables, packed/encrypted files, and masquerading malware
- **Live system artifact collection** — active network connections, scheduled tasks, registry persistence keys, and PowerShell event logs
- **Local AI analysis** — a 7-billion parameter language model runs entirely on-device to synthesize the evidence into a human-readable incident timeline

---

## How It Works

The scanner runs through four sequential stages every time you initiate a scan:

| Stage | What Happens |
|---|---|
| **1. Artifact Collection** | Collects live system data: active network connections (`netstat`), scheduled tasks, browser shortcuts, and PowerShell script execution logs (Event IDs 4103/4104) |
| **2. File Walk & Scoring** | Traverses up to 6 configurable scan modules. Each file is SHA-256 hashed and scored: malware DB match (+100 pts), unsigned binary (+50 pts), name masquerading (+50 pts) |
| **3. AI Analysis** | The top suspicious files and artifacts are sent to the local Qwen2.5-7B AI model (running offline via llama.cpp). The model generates a structured forensic JSON — risk level, attack timeline, and recommendations |
| **4. Report Generation** | A timestamped incident report is saved to the `reports/` folder on the USB drive for evidence preservation |

---

## Features

- **Fully Offline** — Zero network calls during scanning. The AI model runs locally via llama.cpp. No data leaves the machine.
- **USB Portable** — Everything (AI engine, model, databases, scanner) fits on a USB drive. No installation required on the target machine.
- **6 Configurable Scan Modules** — Enable or disable individual modules to control scan scope and speed:
  - Downloads & Desktop
  - Temp Folders
  - Browser Cache (Chrome, Edge, Firefox)
  - Registry Persistence Keys (HKCU/HKLM Run)
  - Scheduled Tasks
  - PowerShell Event Logs
- **Dual Malware Databases** — Cross-references SHA-256 hashes against both ClamAV (~33 MB) and MalwareBazaar (~70 MB) signature databases
- **PE Binary Intelligence** — Reads PE headers to detect Authenticode signatures, calculates Shannon entropy to identify packed/encrypted payloads, and detects process name masquerading
- **Click-to-Open Forensics** — Click any result to instantly highlight the file in Windows Explorer, or navigate directly to a suspicious registry key in `regedit` — without executing anything
- **Live System Telemetry** — Actively hunts for reverse shells (via `netstat`), suspicious persistence mechanisms, and PowerShell memory injection patterns
- **AI-Generated Evidence Blocks** — The AI extracts exact raw scripts, IP addresses, and command-line parameters directly from the logs into the report proof blocks
- **Auto-Save Reports** — Every scan automatically saves a timestamped `.txt` forensic report to the USB `reports/` folder

---

## Requirements

Before running the scanner for the first time, you need:

- A Windows machine (Windows 10 or later, 64-bit)
- At least **6 GB of free disk space** for the AI model and databases
- An internet connection **only for the first-time setup** (to download the model and signature databases)
- The target machine (where you run the scan) needs **no installs, no Python, no internet**

---

## Installation & First-Time Setup

### Step 1 — Download this repository

Click **Code → Download ZIP** on GitHub and extract it to a folder, or clone it:

```
git clone https://github.com/morduh/soc-emergency-scanner.git
```

### Step 2 — Run `setup.bat`

Double-click **`setup.bat`**. This is a one-time setup that automatically downloads:

| Download | Size | Description |
|---|---|---|
| Qwen2.5-7B AI Model | ~4.4 GB | The offline language model for forensic analysis |
| ClamAV Signature DB | ~33 MB | Open-source antivirus hash database |
| MalwareBazaar Hash DB | ~70 MB | Community-curated malware hash database |

> **Important:** The AI model download is ~4.4 GB. Make sure you have a stable internet connection and do not close the window until it completes. You only need to do this once.

![Setup Process](docs/images/install%20proccess.png)

*`setup.bat` running in the terminal — downloading the AI model from HuggingFace. No Python or other tools are needed.*

### Step 3 — Launch the scanner

Once setup finishes, double-click **`SOC-Scanner.exe`**.

The application will start the local AI engine in the background. Wait for the **"AI Engine Ready"** indicator to turn green in the top-right corner before starting a scan.

---

## How to Use

### The Main Interface

When you launch the scanner, you will see the main dashboard. The two status indicators in the top-right confirm the system is ready:

- **OFFLINE / USB MODE ACTIVE** — confirms no internet calls will be made
- **AI ENGINE READY** — confirms the local Qwen2.5 model has loaded and is ready

![Main Interface — Expanded](docs/images/main%20page.png)

*The main dashboard with all 6 scan modules enabled. The custom path input at the bottom lets you scan any specific directory.*

![Main Interface — Compact](docs/images/main%20page%202.png)

*The scan module panel can be collapsed to a compact view once you have configured your modules.*

### Running a Scan

**Option A — Default Scan (recommended)**

Click **INITIATE DEFAULT SCAN** to run all enabled modules simultaneously. This covers the most critical system locations in one click.

You can customize which modules are active by checking or unchecking them in the **Configure Scan Modules** panel before starting. Use **Enable All** or **Disable All** for quick toggles.

**Option B — Custom Path Scan**

Type or drag-and-drop a folder path into the **OR SCAN A CUSTOM PATH** input field and click **SCAN PATH** to scan any specific directory of your choice.

### During the Scan

The scanner runs through two visible phases:

**Phase 1 — Scanning & Hashing Files**

The engine traverses the file system, computes SHA-256 hashes, checks them against the malware databases, and calculates suspicion scores for each file.

![Scanning Phase at 25%](docs/images/processing%20scan%201.png)

*Phase 1 at 25%: traversing the file system and computing SHA-256 hashes. The current file being processed is shown in real time.*

![Scanning Phase at 58%](docs/images/scanning%2060.png)

*Phase 1 at 58%: continuing the file walk across all enabled scan modules.*

**Phase 2 — AI Analyzing Threats**

Once file collection is complete, the top suspicious artifacts are sent to the local Qwen2.5 AI model. The model reasons over the evidence and constructs a structured forensic analysis.

![AI Analysis Phase at 68%](docs/images/processing%20scan.png)

*Phase 2 at 68%: the local AI model is processing the collected artifacts. This phase may take a few minutes depending on hardware.*

> **Note:** AI analysis runs entirely on the CPU. On standard hardware this takes 2–10 minutes. Do not close the window during this phase.

### Reading the Results

When the scan completes, the results panel is displayed with:

- **Risk Level** — HIGH / MEDIUM / LOW, determined by the AI based on all collected evidence
- **Scan Coverage Stats** — total folders traversed, total files evaluated, number of suspicious files flagged
- **Forensic Report Path** — the exact path where the report was automatically saved on the USB
- **Attack Story** — the AI's narrative summary of what it found and what it means
- **SOC Recommendations** — specific remediation steps the AI recommends for the SOC team
- **Attack Timeline** — a chronological reconstruction of the attack events, each with an exact evidence proof block

![Scan Results — HIGH RISK](docs/images/after%20scanning.png)

*A completed scan showing HIGH RISK — 583 files evaluated, 79 flagged as suspicious. The AI has generated an attack summary, SOC recommendations, and an attack timeline with 10 events.*

---

## Incident Reports

Every scan automatically saves a detailed `.txt` forensic report to the `reports/` folder on the USB drive. Reports are timestamped and preserved across sessions, giving you a full audit trail of all scans performed.

![Reports Folder](docs/images/report%20folder.png)

*The `reports/` folder on the USB after multiple scan sessions — each file is a complete forensic report named with the date and time of the scan.*

Report files are plain text and can be opened with any text editor, submitted as evidence, or attached to a ticket in your SOC case management system.

---

## Deploying to USB

After completing the first-time setup, copy the following four items to your USB drive to create a portable deployment:

```
USB Drive/
├── SOC-Scanner.exe    ← double-click to launch
├── bin\               ← AI engine (llama-server.exe) + malware databases
├── models\            ← Qwen2.5 AI model (~4.4 GB)
└── reports\           ← create this as an empty folder (reports are saved here)
```

![USB Drive Contents](docs/images/usb%20folder.png)

*The correct USB folder structure — four items total. The scanner auto-detects the USB path at launch.*

Once deployed to USB, the scanner is fully self-contained. Plug it into any Windows machine and double-click `SOC-Scanner.exe` — no installs, no internet, no configuration needed.

---

## Security & Privacy

- **Zero network calls during scanning** — all analysis is performed locally
- **No data leaves the machine** — the AI model runs on-device via llama.cpp
- **Nothing is installed on the target machine** — the exe bundles its own Python runtime
- **AI process auto-terminates** when the application window is closed
- **Safe file viewing** — the "Open" button uses Windows Explorer's `/select,` flag to highlight files without executing them

---

## For Developers — Rebuilding the EXE

If you modify `app.py` or the React frontend and need to rebuild the executable:

**Prerequisites:**
```
pip install pyinstaller pywebview requests
npm install   (run inside the frontend/ folder)
```

**Build:**
```
1. Install Python 3.8+  →  python.org/downloads
2. Install Node.js      →  nodejs.org
3. Run build_exe.bat
```

`build_exe.bat` will:
1. Build the React frontend (`npm run build`)
2. Bundle everything with PyInstaller into a single `.exe`
3. Copy the result to the project root

---

## Project Structure

```
├── SOC-Scanner.exe     ← Ready-to-run app (Python runtime bundled inside)
├── setup.bat           ← One-click first-time setup
├── build_exe.bat       ← Developer rebuild script
├── app.py              ← Python backend: triage engine, AI bridge, forensic logic
├── requirements.txt    ← Python dependencies (pywebview, requests)
├── frontend/
│   └── src/App.jsx     ← React UI (dark enterprise theme, real-time progress)
├── bin/
│   ├── llama-server.exe   ← AI inference engine (llama.cpp)
│   ├── clamav.hsb         ← Downloaded by setup.bat
│   └── bazaar.hsb         ← Downloaded by setup.bat
├── models/
│   └── *.gguf             ← Downloaded by setup.bat (~4.4 GB)
├── reports/               ← Scan reports saved here
└── docs/images/           ← README screenshots
```

---

*Built as a Final Project for a Certified SOC Analyst course — demonstrating practical incident response automation, malware triage, and AI-assisted forensics.*
