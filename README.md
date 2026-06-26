# 🛡️ SOC Emergency AI Scanner — "Detection on a Stick"

> **Final Project — Certified SOC Analyst Course | Option 2: Security Automation Tool**
> A fully offline, USB-portable incident response triage tool powered by a locally hosted LLM.

---

## ⚡ Quick Start (Fresh Clone)

> **You only need to do this once.** After setup, just copy the 3 folders + exe to a USB and go.

### Prerequisites — Install These First

| Tool | Download | Notes |
|---|---|---|
| **Python 3.8+** | https://www.python.org/downloads/ | ✅ Check "Add Python to PATH" during install |
| **Node.js (LTS)** | https://nodejs.org/ | Required to build the React UI |

### One Command to Set Everything Up

```
1. Clone or download this repository
2. Double-click  setup.bat
3. Wait ~15-30 min (downloads the 4.4 GB AI model)
4. Done — SOC-Scanner.exe will be ready in the project folder
```

`setup.bat` handles everything automatically:
- ✅ Installs Python dependencies (`pip install -r requirements.txt`)
- ✅ Downloads the **Qwen2.5 AI model** (~4.4 GB from HuggingFace)
- ✅ Downloads **ClamAV** malware signature database (~33 MB)
- ✅ Downloads **MalwareBazaar** hash database (~70 MB)
- ✅ Runs `npm install` + `npm run build` for the React frontend
- ✅ Builds `SOC-Scanner.exe` with PyInstaller

---

## 📁 What Gets Created After Setup

```
Final Project/
├── SOC-Scanner.exe       ← The built app (run this on the target machine)
├── bin/
│   ├── llama-server.exe  ← AI engine (included in repo, no download needed)
│   ├── *.dll             ← llama.cpp runtime DLLs (included in repo)
│   ├── clamav.hsb        ← Downloaded by setup.bat
│   └── bazaar.hsb        ← Downloaded by setup.bat
├── models/
│   └── Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf  ← Downloaded by setup.bat (~4.4 GB)
└── reports/              ← Scan reports saved here at runtime
```

> **For the USB:** Copy `SOC-Scanner.exe` + `bin\` + `models\` + an empty `reports\` folder.
> The exe finds `bin\` and `models\` automatically from whatever folder it's launched from.

---

## 🚀 USB Deployment

After running `setup.bat`, copy these to your USB drive:

```
USB Drive/
├── SOC-Scanner.exe    ← double-click to launch
├── bin\               ← AI engine + signature databases
├── models\            ← Qwen2.5 AI model
└── reports\           ← empty folder (reports saved here during scans)
```

To update the USB after making code changes, run `update_usb.bat` *(requires WinPython at the hardcoded path — dev machine only)*.

---

## 🔧 Manual Build (if setup.bat fails)

```powershell
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Build the React frontend
cd frontend
npm install
npm run build
cd ..

# 3. Build the exe
python -m PyInstaller --onefile --add-data "frontend\build;frontend\build" app.py --name SOC-Scanner --noconfirm
```

The exe will be at `dist\SOC-Scanner.exe`. Copy it to the project root.

---

## 🔍 How the Triage Engine Works

| Stage | What Happens |
|---|---|
| **1. File Walk** | Recursively scans the target directory, skipping OS system folders |
| **2. Scoring** | Each file is scored by 3 rules: SHA-256 offline DB lookup (+100), unsigned PE binary (+50), system-binary name masquerading (+50) |
| **3. Top-10 Extraction** | Top 10 highest-scoring files extracted for AI analysis |
| **4. AI Prompt** | Aggregated forensic data sent to the local Qwen2.5 model via llama-server |
| **5. JSON Report** | AI returns structured report: risk level, attack summary, timeline, recommendations |

---

## 🎨 UI Features

- **OFFLINE / USB MODE ACTIVE** badge with pulsing green glow
- **AI Engine Status** polling (ready / initializing / offline)
- **Animated scan progress** with live status messages
- **Risk Badge** with neon red/orange/green glow per threat level
- **Attack Story** — narrative explanation of the incident
- **Interactive Attack Timeline** — chronological event reconstruction
- **Recommendations Box** — SOC mitigation steps
- **Suspect File Table** — files ranked by suspicion score

---

## 🔒 Security & Privacy

- **Zero network calls** — all analysis runs 100% locally
- **No data leaves the machine** — the LLM is fully offline
- `CREATE_NO_WINDOW` flag ensures no console popups on the target
- AI process auto-terminates when the GUI window is closed

---

## 📦 Repository Structure

```
Final Project/
├── app.py              ← Python backend (PyWebView + triage engine + AI integration)
├── requirements.txt    ← Python dependencies
├── setup.bat           ← One-click first-time setup (clone this → run this)
├── build_exe.bat       ← Rebuild the exe only (no downloads)
├── update_usb.bat      ← Full rebuild + deploy to USB drive J:\
├── run.bat             ← Run app.py directly (dev mode, no exe)
├── SOC-Scanner.spec    ← PyInstaller config
├── README.md           ← This file
├── bin/                ← llama.cpp runtime DLLs + llama-server.exe (in repo)
│   ├── llama-server.exe
│   ├── llama.dll, ggml.dll, ggml-cpu-*.dll ...
│   ├── clamav.hsb      ← NOT in repo — downloaded by setup.bat
│   └── bazaar.hsb      ← NOT in repo — downloaded by setup.bat
├── models/             ← NOT in repo — downloaded by setup.bat (~4.4 GB)
│   └── Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf
└── frontend/           ← React (Vite + Tailwind) source code
    ├── src/
    │   ├── App.jsx     ← Main UI component
    │   ├── index.jsx
    │   └── index.css
    ├── index.html
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    └── postcss.config.js
```

---

## ⚠️ What Is NOT in This Repository (Too Large for GitHub)

| File | Size | How to Get It |
|---|---|---|
| `models/*.gguf` | ~4.4 GB | **Automatic** — `setup.bat` downloads it |
| `bin/bazaar.hsb` | ~70 MB | **Automatic** — `setup.bat` downloads it |
| `bin/clamav.hsb` | ~33 MB | **Automatic** — `setup.bat` downloads it |
| `SOC-Scanner.exe` | ~13 MB | **Automatic** — `setup.bat` builds it |
