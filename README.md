# 🛡️ SOC Emergency AI Scanner — "Detection on a Stick"

> Final Project — Certified SOC Analyst Course | Security Automation Tool
> A fully offline, USB-portable incident response triage tool powered by a locally hosted AI.

---

## 🚀 How to Use (3 Steps, No Installs)

### Step 1 — Download this repository
Click **Code → Download ZIP** on GitHub, then extract it. Or clone it.

### Step 2 — Run `setup.bat`
Double-click `setup.bat`. It will automatically download:
- The Qwen2.5 AI model (~4.4 GB) — **this takes time, leave it running**
- ClamAV malware signature database (~33 MB)
- MalwareBazaar hash database (~70 MB)

No Python, no installs, no browser required. Just wait for it to finish.

### Step 3 — Launch the scanner
Double-click **`SOC-Scanner.exe`**

---

## 💾 Deploying to USB

After `setup.bat` finishes, copy these 4 items to your USB drive:

```
USB Drive/
├── SOC-Scanner.exe    ← double-click to launch
├── bin\               ← AI engine + malware databases
├── models\            ← Qwen2.5 AI model
└── reports\           ← create this as an empty folder
```

The scanner is 100% offline. No internet needed once deployed. It auto-detects the USB path.

---

## 📁 What's in This Repository

```
├── SOC-Scanner.exe     ← Ready-to-run app (Python already bundled inside)
├── setup.bat           ← One-click setup: downloads model + databases
├── bin\
│   ├── llama-server.exe   ← AI inference engine
│   ├── *.dll              ← Runtime libraries for the AI engine
│   ├── clamav.hsb         ← Downloaded by setup.bat (not in repo, ~33 MB)
│   └── bazaar.hsb         ← Downloaded by setup.bat (not in repo, ~70 MB)
├── models\
│   └── *.gguf             ← Downloaded by setup.bat (not in repo, ~4.4 GB)
├── reports\               ← Scan reports saved here at runtime
├── app.py              ← Python source (backend + triage engine)
├── frontend\src\       ← React UI source code
└── build_exe.bat       ← For developers: rebuild the exe from source
```

---

## 🔍 How the Scanner Works

| Stage | What Happens |
|---|---|
| **Live Artifact Collection** | Native Windows commands extract active Network Connections, Scheduled Tasks, Shortcuts, and PowerShell Event Logs. |
| **File Walk & Registry** | Scans 8 high-value directories (Bank Lab Preset) and audits HKCU/HKLM Run keys. |
| **Scoring** | Scores each file: SHA-256 database match (+100), unsigned binary (+50), name masquerading (+50) |
| **AI Analysis** | Local Qwen2.5 model analyzes the aggregated forensic artifacts and raw scripts — no internet, fully offline. |
| **Report Extraction** | The AI extracts exact raw evidence (scripts, IPs, etc.) and presents a structured incident timeline. |

---

## ✨ Advanced Features

- **Automated "Bank Lab" Preset**: A single-click macro that instantly traverses the 8 most critical system locations for stealthy malware.
- **Click-to-Open Forensics**: Click the "Open" button next to any suspicious file in the UI to instantly open Windows File Explorer and highlight the file without safely executing it. Registry paths will automatically open `regedit` to the exact key.
- **Evidence "Proof" Blocks**: View raw extracted forensic data (e.g., suspicious scripts, execution arguments) directly in the AI's incident timeline for verifiable reporting.
- **Intelligent Scan Optimization**: Automatically bypasses high-volume, benign directories (like browser caches) to ensure lightning-fast traversal and minimize token bloat.
- **Robust AI Parsing Pipeline**: Built-in JSON sanitization engine seamlessly handles Windows backslashes and complex escape characters to prevent AI hallucination and ensure reliable UI generation.
- **Live System Telemetry**: Instead of just scanning dormant files, the scanner actively hunts for reverse shells (`netstat`), suspicious persistence (`schtasks`), and memory injection keywords via PowerShell Event Logs (`Get-WinEvent`).
- **UI Safety Locks**: The interface is hard-locked until the offline AI engine completes its background initialization and model loading.

---

## 🔒 Security & Privacy

- **Zero network calls** — everything runs locally
- **No data leaves the machine** — fully air-gapped
- AI process auto-terminates when the window is closed

---

## 🛠️ For Developers (Rebuilding the EXE)

If you modify `app.py` or the frontend and want to rebuild the exe:

```
1. Install Python 3.8+  →  pip install pyinstaller pywebview requests
2. Install Node.js      →  nodejs.org
3. Run build_exe.bat
```
