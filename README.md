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
| **File Walk** | Scans the target directory for suspicious files |
| **Scoring** | Scores each file: SHA-256 database match (+100), unsigned binary (+50), name masquerading (+50) |
| **Top-10** | Top 10 most suspicious files extracted for AI review |
| **AI Analysis** | Local Qwen2.5 model analyzes the files — no internet, fully offline |
| **Report** | Structured incident report: risk level, attack story, timeline, recommendations |

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
