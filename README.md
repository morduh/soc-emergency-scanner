# 🛡️ SOC Emergency AI Scanner — "Detection on a Stick"

> **Final Project — Certified SOC Analyst Course | Option 2: Security Automation Tool**
> A fully offline, USB-portable incident response triage tool powered by a locally hosted LLM.

---

## 📁 Project Structure

```
Final Project/
├── app.py                        ← Python backend (PyWebView + triage engine)
├── requirements.txt
├── README.md
├── bin/
│   └── llama-server.exe          ← LOCAL: Download separately (see below)
├── models/
│   └── Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf  ← LOCAL: Download separately
└── frontend/
    ├── package.json
    ├── tailwind.config.js
    ├── public/
    │   └── index.html
    └── src/
        ├── index.js
        ├── index.css
        └── App.js
```

---

## ⚙️ One-Time Developer Setup (on YOUR machine)

### Step 1 — Python dependencies
```powershell
pip install -r requirements.txt
```

### Step 2 — Download the AI model files

1. **llama-server.exe** — Download from the llama.cpp releases page:
   - https://github.com/ggerganov/llama.cpp/releases
   - Get the `llama-b...-bin-win-cpu-x64.zip`, extract `llama-server.exe`
   - Place in `./bin/llama-server.exe`

2. **Qwen2.5 model** — Download from HuggingFace:
   - https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF
   - File: `Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf`
   - Place in `./models/Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf`

### Step 3 — Build the React frontend
```powershell
cd frontend
npm install
npm run build
cd ..
```

This produces `frontend/build/` — the static files PyWebView loads directly.

### Step 4 — Run the application
```powershell
python app.py
```

---

## 🚀 USB Deployment

1. Copy the **entire project folder** to a USB drive.
2. Ensure Python 3.10+ is installed on the response laptop (or bundle with PyInstaller).
3. The app auto-detects its USB path via `os.path.dirname(os.path.abspath(__file__))`.
4. Run `python app.py` — the GUI opens, the AI server starts silently.

### Optional: Bundle to a single .exe (no Python needed on target)
```powershell
pip install pyinstaller
pyinstaller --onefile --noconsole --add-data "frontend/build;frontend/build" app.py
```
Copy the `dist/app.exe` plus `bin/` and `models/` folders to the USB.

---

## 🔍 How the Triage Engine Works

| Stage | What Happens |
|-------|-------------|
| **1. File Walk** | Recursively scans target directory, skipping Windows/system dirs |
| **2. Scoring** | Each file gets a suspicion score based on: extension risk (+40), suspicious path (+30), modified in last 48h (+25), obfuscation signatures in content (+20), double-extension trick (+50) |
| **3. Top-10 Extraction** | Top 10 highest-scoring files are extracted (max 4000 chars each) |
| **4. AI Prompt** | Aggregated data + system prompt sent to local Qwen2.5 model |
| **5. JSON Output** | AI returns structured Hebrew report: risk level, summary, timeline, recommendations |

---

## 🎨 UI Features

- **OFFLINE / USB MODE ACTIVE** badge with pulsing green glow
- **AI Engine Status** polling (ready / initializing / offline)
- **Animated scan progress** with Hebrew status messages
- **Risk Badge** with neon red/orange/green glow per threat level
- **Hebrew Attack Story** with RTL text rendering
- **Interactive Attack Timeline** with file/network/persistence event types
- **Recommendations Box** for SOC mitigation steps
- **Suspect File Table** with visual suspicion score bars

---

## 🔒 Security Notes

- Zero network calls — all analysis is 100% local
- No data leaves the USB drive
- `CREATE_NO_WINDOW` flag ensures no console windows on target machine
- AI process auto-terminates when the GUI window is closed
