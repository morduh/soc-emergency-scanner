"""
SOC Emergency AI Scanner — Python Backend
==========================================
Production-grade backend for the USB-based offline triage tool.
Handles: USB path detection, llama-server lifecycle, file system triage,
and AI analysis via a locally hosted LLM server.

Author : SOC Analyst Final Project
Version: 1.0.0
"""

from __future__ import annotations  # Fix Python 3.8 compatibility for set[str], list[str], str | None, etc.

import os
import sys
import json
import time
import math
import struct

# ---------------------------------------------------------------------------
# Force sys.stdout and sys.stderr to ignore Unicode charmap errors
# ---------------------------------------------------------------------------
class SafeStream:
    def __init__(self, target):
        self.target = target
    def write(self, s):
        if self.target:
            try:
                self.target.write(s)
            except UnicodeEncodeError:
                try:
                    self.target.write(s.encode('cp1252', errors='replace').decode('cp1252'))
                except Exception:
                    pass
            except Exception:
                pass
    def flush(self):
        if self.target:
            try: self.target.flush()
            except Exception: pass
    def __getattr__(self, name):
        return getattr(self.target, name)

sys.stdout = SafeStream(sys.stdout)
sys.stderr = SafeStream(sys.stderr)
# ---------------------------------------------------------------------------
import subprocess
import threading
import requests
import stat
import hashlib
import mimetypes
import re
from datetime import datetime, timedelta
from pathlib import Path
import winreg
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import webview

# ---------------------------------------------------------------------------
# USB / Execution-Directory Detection
# ---------------------------------------------------------------------------
# When packaged with PyInstaller --onefile:
#   - sys._MEIPASS  → temp extraction dir where bundled data (frontend) lives
#   - EXE_DIR       → the real directory containing the .exe file on disk
#                     (where external bin/ and models/ folders must sit)
# When running as a plain Python script, both resolve to the script's directory.

if getattr(sys, "frozen", False):
    # Running inside a PyInstaller --onefile bundle
    EXE_DIR  = os.path.dirname(sys.executable)   # next to app.exe  → bin/, models/
    BASE_DIR = sys._MEIPASS                       # temp extract dir → frontend/build
else:
    # Running as a regular Python script
    EXE_DIR  = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = EXE_DIR

BIN_DIR   = os.path.join(EXE_DIR,  "bin")
MODEL_DIR = os.path.join(EXE_DIR,  "models")

LLAMA_SERVER_PATH = os.path.join(BIN_DIR, "llama-server.exe")
MODEL_PATH        = os.path.join(MODEL_DIR, "Qwen2.5-7B-Instruct-1M-Q4_K_M.gguf")

AI_SERVER_URL = "http://127.0.0.1:8080/v1/chat/completions"
AI_SERVER_HEALTH_URL = "http://127.0.0.1:8080/health"
AI_STARTUP_TIMEOUT_SECONDS = 60  # max time to wait for the server to come online

# Global handle to the AI subprocess
ai_process: Optional[subprocess.Popen] = None

# Global handle to the PyWebView window — kept at module level to avoid
# the PyWebView recursion crash that occurs when window is stored as a
# class attribute (pywebview tries to auto-serialize it to JS).
MAIN_WINDOW = None

# ---------------------------------------------------------------------------
# High-Risk Indicators
# ---------------------------------------------------------------------------
HIGH_RISK_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1",       # PowerShell
    ".bat", ".cmd",                  # Batch
    ".vbs", ".vbe", ".wsf", ".wsc",  # VBScript / Windows Script
    ".js", ".jse",                   # JScript
    ".hta",                          # HTML Application
    ".scr",                          # Screensaver (PE)
    ".dll", ".exe",                  # Binaries
    ".lnk",                          # Shortcut
    ".reg",                          # Registry files
    ".msi", ".msp",                  # Installers
    ".inf",                          # Setup information
    ".jar", ".class",                # Java
    ".py",                           # Python scripts on target
    ".rb",                           # Ruby
    ".sh",                           # Shell scripts
}

SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\programdata\\", "\\windows\\temp\\",
    "\\users\\public\\", "\\recycle", "\\$recycle.bin",
    "\\system32\\tasks\\", "\\syswow64\\tasks\\",
    "\\windows\\system32\\drivers\\",
    "\\appdata\\roaming\\",
]

OBFUSCATION_SIGNATURES = [
    b"invoke-expression",
    b"iex(",
    b"encodedcommand",
    b"frombase64string",
    b"downloadstring",
    b"downloadfile",
    b"webclient",
    b"system.net.webclient",
    b"bitsadmin",
    b"certutil",
    b"regsvr32",
    b"mshta",
    b"wscript.shell",
    b"cmd /c",
    b"powershell -",
    b"net user",
    b"net localgroup",
    b"schtasks",
    b"reg add",
    b"reg delete",
    b"vssadmin",
    b"bcdedit",
    b"wmic",
    b"attrib +h",
    b"attrib +s",
    b"icacls",
    b"takeown",
    b"whoami",
    b"netstat",
    b"tasklist",
    b"mimikatz",
    b"sekurlsa",
    b"lsadump",
    b"pass-the-hash",
    b"shellcode",
    b"meterpreter",
    b"nc.exe",
    b"ncat",
    b"reverse shell",
]

# ---------------------------------------------------------------------------
# Smart Binary Triage — Masquerading Detection
# ---------------------------------------------------------------------------

# Well-known Windows process names that attackers commonly masquerade as.
WINDOWS_SYSTEM_BINARIES: set[str] = {
    "svchost.exe",   "lsass.exe",   "explorer.exe",  "services.exe",
    "csrss.exe",     "smss.exe",    "wininit.exe",   "winlogon.exe",
    "taskhost.exe",  "taskhostw.exe","spoolsv.exe",  "conhost.exe",
    "dllhost.exe",   "rundll32.exe","regsvr32.exe",  "msiexec.exe",
    "cmd.exe",       "powershell.exe","wscript.exe", "cscript.exe",
    "mshta.exe",     "certutil.exe","bitsadmin.exe", "wmic.exe",
    "netsh.exe",     "sc.exe",      "net.exe",       "net1.exe",
    "ntoskrnl.exe",  "hal.dll",     "ntdll.dll",     "kernel32.dll",
    "user32.dll",    "advapi32.dll","msvcrt.dll",    "wininet.dll",
}

# Path fragments that confirm a binary is in a legitimate Windows system directory.
LEGITIMATE_SYSTEM_PATHS: tuple[str, ...] = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
)

# ---------------------------------------------------------------------------
# AI System Prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a Senior SOC Analyst and Expert Incident Responder with 15 years of experience in malware analysis, threat hunting, and digital forensics. You have deep knowledge of attacker TTPs (MITRE ATT&CK), Windows internals, PowerShell obfuscation, and lateral movement techniques.

You will be provided with raw file content snippets collected from a potentially compromised Windows machine. Your job is to analyze these artifacts and construct a clear picture of what happened.

CRITICAL INSTRUCTIONS:
1. Analyze the raw data for: malware indicators, persistence mechanisms, backdoors, credential theft, lateral movement, defense evasion, and command-and-control (C2) communication.
2. You MUST return ONLY a raw JSON object. Do NOT wrap it in markdown code blocks (no ```json). Do NOT add any explanation outside the JSON.
3. LANGUAGE RULE — STRICTLY ENFORCED: You MUST write the entire JSON response and ALL descriptive text fields in clear, professional English ONLY. Do NOT use Hebrew, Russian, Arabic, or any other language. Every field value must be 100% English. Violation of this rule makes the output unusable.
4. The risk_level field must be EXACTLY one of: "HIGH", "MEDIUM", or "LOW" — in English, uppercase.
5. The timeline array should represent a logical reconstruction of the attack sequence, ordered chronologically.
6. If the data appears clean or benign, set risk_level to "LOW" and explain why in English.
7. IMPORTANT: Limit the 'timeline' array to a maximum of the top 4-5 most critical or suspicious events only. Do NOT log every file. Avoid output bloat — this is essential for performance on CPU hardware.

Return ONLY this exact JSON structure:
{
  "risk_level": "HIGH" | "MEDIUM" | "LOW",
  "summary": "Comprehensive English summary of investigation findings and the attack story",
  "timeline": [
    {"time": "HH:MM", "event": "English description of the event", "type": "file" | "network" | "persistence"}
  ],
  "recommendation": "Clear English mitigation steps and recommended actions for the SOC team"
}"""

# ---------------------------------------------------------------------------
# Utility: Launch the local AI server
# ---------------------------------------------------------------------------

def launch_ai_server() -> Optional[subprocess.Popen]:
    """
    Start the llama-server.exe process from the USB bin directory.
    Uses CREATE_NO_WINDOW so no console flashes on the target machine.
    Returns the Popen handle or None on failure.
    """
    global ai_process

    if not os.path.isfile(LLAMA_SERVER_PATH):
        print(f"[WARN] llama-server.exe not found at: {LLAMA_SERVER_PATH}")
        return None

    if not os.path.isfile(MODEL_PATH):
        print(f"[WARN] Model not found at: {MODEL_PATH}")
        return None

    cmd = [
        LLAMA_SERVER_PATH,
        "--model", MODEL_PATH,
        "--port", "8080",
        "--ctx-size", "16384",
        "--parallel", "1",
    ]

    creation_flags = 0

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=BASE_DIR,
        )
        print(f"[INFO] llama-server launched (PID: {proc.pid})")
        return proc
    except Exception as exc:
        print(f"[ERROR] Failed to launch llama-server: {exc}")
        return None


def wait_for_ai_server(timeout: int = AI_STARTUP_TIMEOUT_SECONDS) -> bool:
    """
    Poll the AI health endpoint until it responds or timeout is reached.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(AI_SERVER_HEALTH_URL, timeout=2)
            if resp.status_code == 200:
                print("[INFO] llama-server is ready.")
                return True
        except Exception:
            pass
        time.sleep(2)
    print("[WARN] llama-server did not become ready in time.")
    return False


# ---------------------------------------------------------------------------
# Cleanup Callback (registered with PyWebView)
# ---------------------------------------------------------------------------

def on_window_closed():
    """Terminate the AI server when the GUI window is closed."""
    global ai_process
    if ai_process and ai_process.poll() is None:
        print("[INFO] Terminating llama-server...")
        ai_process.terminate()
        try:
            ai_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ai_process.kill()
        print("[INFO] llama-server terminated.")


# ---------------------------------------------------------------------------
# Progress Reporter — pushes live scan status to the React frontend
# ---------------------------------------------------------------------------

# Module-level progress state — updated by _report_progress(), read by CyberAPI.get_progress().
# The frontend polls get_progress() every ~600 ms instead of relying on evaluate_js,
# which can deadlock when called from within a pywebview JS-API handler thread.
_progress_state: dict = {"phase": "INIT", "percent": 0, "file": ""}


def _report_progress(phase: str, percent: int, current_file: str = "") -> None:
    """
    Record the current scan phase/percentage so the frontend can poll it.

    Also attempts an evaluate_js push as a best-effort shortcut — this works
    when the page is served over HTTP (dev mode) but may silently fail under
    file:// in PyInstaller builds.  The polling fallback guarantees delivery.

    phase   : INIT | SCANNING | AI_THINKING | SAVING | COMPLETE
    percent : 0–100 integer
    """
    global _progress_state
    _progress_state = {"phase": phase, "percent": int(percent), "file": current_file}
    # Best-effort push — swallowed safely if it fails
    if MAIN_WINDOW is not None:
        try:
            payload = json.dumps(_progress_state)
            MAIN_WINDOW.evaluate_js(
                f"if(window.updateProgress){{window.updateProgress({payload});}}"
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CyberAPI — Methods exposed to the JavaScript frontend via PyWebView
# ---------------------------------------------------------------------------

class CyberAPI:
    """
    All public methods of this class are callable from the JavaScript frontend
    via window.pywebview.api.<method_name>().

    NOTE: Do NOT store the PyWebView window object as a class attribute here.
    PyWebView introspects all attributes of the js_api object and will try to
    serialize a window reference, causing a "maximum recursion depth exceeded"
    crash on startup. Use the module-level MAIN_WINDOW global instead.
    """

    def __init__(self) -> None:
        # Offline malware signature database: sha256_lowercase -> malware_name
        # Populated once by _load_offline_signatures() on first use.
        self.signatures: dict[str, str] = {}
        self._load_offline_signatures()

    # ------------------------------------------------------------------
    # Internal: Offline Signature Database
    # ------------------------------------------------------------------

    def _load_offline_signatures(self) -> None:
        """
        Load offline malware signatures into self.signatures from two
        independent database files inside BIN_DIR:

          bazaar.hsb  — MalwareBazaar flat SHA-256 hash export.
                        Lines are either:
                          sha256_hex
                          sha256_hex  malware_name
          clamav.hsb  — ClamAV HSB signature database.
                        Lines are colon-delimited:
                          sha256_hex:malware_name:file_size   (or more fields)
                        Space-delimited lines are also accepted as a fallback.

        Both files feed into the same self.signatures lookup dict
        (sha256_lowercase -> malware_name).  Each file is parsed
        independently so a missing file never prevents the other from
        loading.  All hash keys are lowercased for uniform lookup.
        Lines starting with '#' or empty lines are silently skipped.
        """

        # ── Shared parser ────────────────────────────────────────────────────
        def _parse_sig_file(filepath: str) -> int:
            """
            Parse one signature file and merge entries into self.signatures.
            Returns the number of valid entries loaded from this file.
            """
            count = 0
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Colon-delimited (ClamAV HSB standard)
                    if ":" in line:
                        parts = line.split(":")
                        sha_hash     = parts[0].strip().lower()
                        malware_name = parts[1].strip() if len(parts) > 1 else "Unknown"
                    # Space-delimited (MalwareBazaar export or fallback)
                    elif " " in line:
                        parts = line.split(None, 1)
                        sha_hash     = parts[0].strip().lower()
                        malware_name = parts[1].strip() if len(parts) > 1 else "Unknown"
                    # Hash-only line
                    else:
                        sha_hash     = line.lower()
                        malware_name = "Unknown"

                    # Sanity check: SHA-256 must be exactly 64 lowercase hex chars
                    if len(sha_hash) == 64 and all(c in "0123456789abcdef" for c in sha_hash):
                        self.signatures[sha_hash] = malware_name
                        count += 1

            return count
        # ─────────────────────────────────────────────────────────────────────

        bazaar_path = os.path.join(BIN_DIR, "bazaar.hsb")
        clamav_path = os.path.join(BIN_DIR, "clamav.hsb")

        bazaar_count = 0
        clamav_count = 0

        # ── MalwareBazaar (bazaar.hsb) ───────────────────────────────────────
        if os.path.isfile(bazaar_path):
            try:
                bazaar_count = _parse_sig_file(bazaar_path)
                print(f"[INFO] Loaded {bazaar_count} signatures from MalwareBazaar (bazaar.hsb).")
            except (OSError, PermissionError) as exc:
                print(f"[WARN] Could not read MalwareBazaar database: {exc}")
        else:
            print(f"[WARN] MalwareBazaar database file missing (bazaar.hsb), "
                  f"continuing with ClamAV only.")

        # ── ClamAV (clamav.hsb) ─────────────────────────────────────────────
        if os.path.isfile(clamav_path):
            try:
                clamav_count = _parse_sig_file(clamav_path)
                print(f"[INFO] Loaded {clamav_count} signatures from ClamAV (clamav.hsb).")
            except (OSError, PermissionError) as exc:
                print(f"[WARN] Could not read ClamAV database: {exc}")
        else:
            print(f"[WARN] ClamAV database file missing (clamav.hsb), "
                  f"continuing with MalwareBazaar only.")

        # ── Summary ──────────────────────────────────────────────────────────
        total = len(self.signatures)  # len() is authoritative — dedup is free
        print(f"[INFO] Total armed offline signatures in memory: {total}.")


    # ------------------------------------------------------------------
    # Internal: Advanced Static Analysis Helpers
    # ------------------------------------------------------------------

    def _calculate_entropy(self, file_path: str) -> float:
        """
        Compute the Shannon Entropy of a file's byte distribution.

        Returns a float in the range [0.0, 8.0].
        - Values > 7.5 strongly indicate packing, encryption, or obfuscation
          (classic signs of a packed malware dropper).
        - Legitimate uncompressed binaries typically score between 5.0 and 6.5.
        - Values near 0.0 indicate highly uniform / trivially simple content.
        """
        byte_counts = [0] * 256
        total_bytes = 0
        try:
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    for byte in chunk:
                        byte_counts[byte] += 1
        except (OSError, PermissionError):
            return 0.0

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def _check_pe_signature(self, file_path: str) -> bool:
        """
        Inspect the PE (Portable Executable) header to determine whether
        the binary contains a valid Authenticode digital signature.

        Strategy:
          1. Read the DOS header to locate the PE header offset (e_lfanew at
             bytes 0x3C–0x3F).
          2. Seek to the PE Optional Header's Data Directory array.
          3. Entry index 4 is the Security Directory (Certificate Table).
             Each entry is 8 bytes: 4-byte VirtualAddress + 4-byte Size.
          4. If both VirtualAddress and Size are > 0, a certificate table
             exists — the binary is (at minimum structure-level) signed.

        Returns:
          True  — Certificate Table entry is populated (Signed).
          False — Certificate Table is absent or file is not a valid PE.
        """
        try:
            with open(file_path, "rb") as fh:
                # -- DOS header magic check (MZ) --
                magic = fh.read(2)
                if magic != b"MZ":
                    return False

                # -- Read e_lfanew (PE header offset) at 0x3C --
                fh.seek(0x3C)
                pe_offset_bytes = fh.read(4)
                if len(pe_offset_bytes) < 4:
                    return False
                pe_offset = struct.unpack_from("<I", pe_offset_bytes)[0]

                # -- Verify PE signature "PE\0\0" --
                fh.seek(pe_offset)
                pe_sig = fh.read(4)
                if pe_sig != b"PE\x00\x00":
                    return False

                # -- Read COFF header (20 bytes) to get SizeOfOptionalHeader --
                # Skip machine (2), num_sections (2), timestamp (4),
                # sym_table_ptr (4), num_symbols (4) = 16 bytes
                fh.read(16)
                size_of_optional_header_bytes = fh.read(2)
                if len(size_of_optional_header_bytes) < 2:
                    return False
                size_of_opt_header = struct.unpack_from("<H", size_of_optional_header_bytes)[0]

                # -- Skip Characteristics (2 bytes) --
                fh.read(2)

                # -- Read Optional Header magic to determine PE32 vs PE32+ --
                opt_magic_bytes = fh.read(2)
                if len(opt_magic_bytes) < 2:
                    return False
                opt_magic = struct.unpack_from("<H", opt_magic_bytes)[0]

                # PE32  = 0x10b → Data Directories start at offset 96 from Optional Header
                # PE32+ = 0x20b → Data Directories start at offset 112 from Optional Header
                if opt_magic == 0x10b:    # PE32
                    data_dirs_rel_offset = 96
                elif opt_magic == 0x20b:  # PE32+
                    data_dirs_rel_offset = 112
                else:
                    return False

                # -- Seek to the Security Directory entry (index 4 in Data Dirs) --
                # Each Data Directory entry = 8 bytes (VirtualAddress + Size)
                # The Optional Header starts at pe_offset + 24 (4 sig + 20 COFF)
                opt_header_start = pe_offset + 24
                security_dir_offset = opt_header_start + data_dirs_rel_offset + (4 * 8)
                fh.seek(security_dir_offset)
                security_dir_bytes = fh.read(8)
                if len(security_dir_bytes) < 8:
                    return False

                virtual_address, size = struct.unpack_from("<II", security_dir_bytes)
                return virtual_address > 0 and size > 0

        except (OSError, PermissionError, struct.error):
            return False

    def _score_file(self, file_path: str) -> tuple[int, list[str]]:
        """
        Return a (suspicion_score, justifications) tuple for a given file path.
        Every file starts at score 0. Points are awarded ONLY by the three
        deterministic rules below — no extension penalties, no entropy checks,
        no path-fragment bonuses, no recency scoring.

        Rule A  SHA-256 offline database lookup   applies to ALL files   +100
        Rule B  Authenticode signature check       .exe / .dll only       +50
        Rule C  Filename masquerading detection    4 sensitive names       +50

        Files that finish at score 0 are NOT suspicious and are excluded from
        the triage report by the caller (start_emergency_scan).
        """
        score = 0
        justifications: list[str] = []

        path_lower = file_path.lower()
        basename   = os.path.basename(path_lower)   # e.g. "svchost.exe"
        ext        = os.path.splitext(file_path)[1].lower()
        IS_PE      = ext in (".exe", ".dll")

        # ── Rule A: Universal SHA-256 Offline Database Lookup ───────────────
        # Computes the SHA-256 hash of the file and checks it against the
        # merged self.signatures dict (bazaar.hsb + clamav.hsb).
        # This runs on EVERY file regardless of extension.
        sha256_val: str | None = None
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            sha256_val = h.hexdigest().lower()
        except (OSError, PermissionError):
            sha256_val = None

        if sha256_val and sha256_val in self.signatures:
            score += 100
            justifications.append(
                "Definitive malware match found in offline database (+100 points)"
            )

        # ── Rule B: PE Authenticode Signature Check (.exe / .dll only) ──────
        # Inspects the PE Security Directory (Certificate Table entry).
        # Unsigned PE binaries are a strong malware indicator.
        if IS_PE:
            is_signed = self._check_pe_signature(file_path)
            if not is_signed:
                score += 50
                justifications.append(
                    "Unsigned binary — lacks a valid Authenticode digital signature (+50 points)"
                )

        # ── Rule C: Filename Masquerading Detection ──────────────────────────
        # Attackers commonly drop malware using the exact names of critical
        # Windows system processes to blend in with legitimate traffic.
        # We flag any file whose name matches the sensitive list but whose
        # path does NOT confirm a legitimate system directory.
        SENSITIVE_SYSTEM_NAMES = {
            "svchost.exe",
            "lsass.exe",
            "cmd.exe",
            "powershell.exe",
        }
        LEGITIMATE_DIRS = ("system32", "windowspowershell")

        if basename in SENSITIVE_SYSTEM_NAMES:
            in_legit_dir = any(d in path_lower for d in LEGITIMATE_DIRS)
            if not in_legit_dir:
                score += 50
                justifications.append(
                    "Filename masquerading detected — critical Windows system binary name "
                    "found running from an unauthorized directory (+50 points)"
                )

        return score, justifications

    def _triage_binary(self, file_path: str) -> str:
        """
        Smart Binary Triage for .exe and .dll files.

        Produces a structured forensic summary for the local LLM:
          - File size
          - SHA-256 hash (for VirusTotal cross-referencing)
          - Digital Signature status (Authenticode Certificate Table check)
          - Shannon Entropy (packing / obfuscation indicator)
          - Masquerading check: is a system-binary name used outside a
            legitimate Windows system directory?

        Returns a clean text block ready for the AI prompt.
        """
        lines: list[str] = ["[BINARY TRIAGE REPORT]"]


        # --- Size ---
        try:
            size_bytes = os.path.getsize(file_path)
            lines.append(f"File Size : {size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)")
        except OSError:
            lines.append("File Size : [UNREADABLE]")
            size_bytes = 0

        # --- SHA-256 Hash ---
        sha256_val = "[HASH ERROR]"
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            sha256_val = h.hexdigest()
        except (OSError, PermissionError) as exc:
            sha256_val = f"[HASH ERROR: {exc}]"
        lines.append(f"SHA-256   : {sha256_val}")

        # --- Offline Malware Signature Database Match ---
        sig_hash = sha256_val.lower() if not sha256_val.startswith("[") else ""
        matched_malware = self.signatures.get(sig_hash, None) if sig_hash else None
        if matched_malware is not None:
            match_line = f"[CRITICAL MALWARE MATCH]: YES - Flagged by offline signature database as: {matched_malware}"
        else:
            match_line = "[CRITICAL MALWARE MATCH]: NO"
        lines.append(match_line)

        # --- Digital Signature Check (PE Certificate Table) ---
        is_signed = self._check_pe_signature(file_path)
        sig_label = "YES (Authenticode Certificate Table detected)" if is_signed else "NO  (Unsigned binary — elevated suspicion)"
        lines.append(f"Digital Signature Detected: {sig_label}")

        # --- Shannon Entropy ---
        entropy = self._calculate_entropy(file_path)
        entropy_note = ""
        if entropy > 7.5:
            entropy_note = " ← HIGH ENTROPY: binary is likely packed, encrypted, or obfuscated"
        elif entropy > 6.5:
            entropy_note = " ← MODERATE: may contain compressed resources"
        else:
            entropy_note = " ← NORMAL range for uncompressed PE binaries"
        lines.append(f"File Entropy      : {entropy:.2f} / 8.00{entropy_note}")

        # --- Masquerading Check ---
        basename_lower  = os.path.basename(file_path).lower()
        path_lower      = file_path.lower()
        is_system_name  = basename_lower in WINDOWS_SYSTEM_BINARIES
        in_legit_path   = any(frag in path_lower for frag in LEGITIMATE_SYSTEM_PATHS)

        if is_system_name and not in_legit_path:
            masquerade_flag = "YES — CRITICAL MASQUERADING ALERT (Windows system binary name found outside legitimate system directory)"
        elif is_system_name and in_legit_path:
            masquerade_flag = "NO (Legitimate system path confirmed)"
        else:
            masquerade_flag = "N/A (Not a common Windows system binary name)"

        lines.append(f"System Name Masquerading: {masquerade_flag}")
        lines.append(f"Binary Location : {file_path}")

        return "\n".join(lines)

    def _extract_text(self, file_path: str, max_chars: int = 800) -> str:
        """
        Safely extract content from a file for the AI prompt.

        - .exe / .dll  → forwarded to _triage_binary() for structured metadata
                          (avoids raw-byte context overflow)
        - Text files   → read up to max_chars characters
        - Other binary → small hex snippet as last resort
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".exe", ".dll"):
            # Route PE binaries through smart triage — never read raw bytes
            # into the LLM context (causes HTTP 400 context-size overflows).
            return self._triage_binary(file_path)

        try:
            # Try UTF-8 first, then Latin-1 as fallback
            for encoding in ("utf-8", "latin-1", "cp1252"):
                try:
                    with open(file_path, "r", encoding=encoding, errors="ignore") as fh:
                        return fh.read(max_chars)
                except (UnicodeDecodeError, ValueError):
                    continue

            # Binary fallback: return hex snippet
            with open(file_path, "rb") as fh:
                raw = fh.read(2048)
            return f"[BINARY FILE — HEX SNIPPET]\n{raw.hex()}"
        except (OSError, PermissionError) as exc:
            return f"[READ ERROR: {exc}]"

    # ------------------------------------------------------------------
    # Public: Start Emergency Scan
    # ------------------------------------------------------------------

    def _scan_registry_persistence(self) -> list[tuple[int, list[str], str]]:
        """
        Scan HKCU and HKLM Run/RunOnce keys for lab indicators.
        """
        registry_hits = []
        lab_indicators = ["budget", "myflag#", "nc.exe"]
        keys_to_check = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hkey, subkey in keys_to_check:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            i += 1
                            data_lower = str(value_data).lower()
                            if any(ind in data_lower for ind in lab_indicators):
                                prefix = "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM"
                                virtual_path = f"{prefix}\\{subkey}\\{value_name} -> {value_data}"
                                justifications = ["Suspicious persistence entry found in Registry Run keys matching lab indicators (+100 points)"]
                                registry_hits.append((100, justifications, virtual_path))
                        except OSError:
                            break
            except OSError:
                pass

        return registry_hits

    def run_bank_lab_preset(self) -> str:
        """
        Kicks off the preset scan in a background thread so it doesn't block the PyWebView JS bridge.
        """
        def worker():
            try:
                res = self._do_run_bank_lab_preset()
                _progress_state["result"] = res
                _progress_state["percent"] = 100
                _progress_state["phase"] = "COMPLETE"
            except Exception as e:
                _progress_state["result"] = json.dumps({"error": str(e)}, ensure_ascii=False)
                _progress_state["percent"] = 100
                _progress_state["phase"] = "ERROR"

        threading.Thread(target=worker, daemon=True).start()
        return json.dumps({"status": "started"}, ensure_ascii=False)

    def _do_run_bank_lab_preset(self) -> str:
        """
        Execute a comprehensive recursive directory traversal across 8 high-value forensic lab locations
        and run registry persistence auditing.
        """
        targets = [
            os.path.expandvars(r"%USERPROFILE%\Downloads"),
            os.path.expandvars(r"%USERPROFILE%\Desktop"),
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache"),
            r"C:\Windows\System32\Tasks",
            r"C:\Windows\System32\Winevt\Logs",
            os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp"),
            r"C:\Windows\Temp",
            os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]

        scored_files: list[tuple[int, list[str], str]] = []
        skipped = 0
        total_files_found   = 0
        total_folders_found = 0
        files_processed     = 0  # for live progress reporting

        _report_progress("SCANNING", 5, "Starting scan of 8 high-value locations...")

        for folder_path in targets:
            if not os.path.exists(folder_path):
                continue
            try:
                for root, dirs, files in os.walk(folder_path, followlinks=False):
                    total_folders_found += 1
                    # ── Directory exclusion list ─────────────────────────────────
                    # Skip _MEI* dirs: these are PyInstaller's own temp extraction
                    # folders — scanning them floods the prompt with thousands of
                    # bundled .pyd/.dll files that are not forensic artifacts.
                    dirs[:] = [
                        d for d in dirs
                        if d.lower() not in {
                            "windows", "program files", "program files (x86)",
                            ".git", "node_modules", "__pycache__",
                            "cache", "caches", "logs", "log",
                            "crashreports", "crashpad",
                            "ebwebview",   # PyWebView's WebView2 temp data dir
                            "shadercache", "pkimetadata", "subresource filter",
                        }
                        and not d.startswith("_MEI")   # PyInstaller temp bundles
                    ]
                    # ── Safety-net path filter ────────────────────────────────────────────
                    # Catches _MEI* (PyInstaller) and EBWebView (PyWebView) temp dirs that
                    # slipped through the dirs[:] pruning above.
                    _root_parts = root.replace("\\", "/").split("/")
                    if any(part.startswith("_MEI") or part.lower() == "ebwebview"
                           for part in _root_parts):
                        skipped += len(files)
                        continue

                    for filename in files:
                        total_files_found += 1
                        files_processed += 1
                        full_path = os.path.join(root, filename)
                        try:
                            if os.path.islink(full_path):
                                continue
                            if os.path.getsize(full_path) > 50 * 1024 * 1024:
                                skipped += 1
                                continue

                            print(f"[SCANNING PRESET] {full_path}")

                            # Report progress every 5 files: 5% → 60%
                            if files_processed % 5 == 0:
                                progress_pct = min(60, 5 + files_processed // 5)
                                _report_progress("SCANNING", progress_pct, full_path)

                            score, justifications = self._score_file(full_path)
                            if score > 0:
                                scored_files.append((score, justifications, full_path))
                        except OSError:
                            skipped += 1
                            continue
            except PermissionError:
                pass

        registry_hits = self._scan_registry_persistence()
        scored_files.extend(registry_hits)

        if not scored_files:
            return json.dumps({
                "risk_level": "LOW",
                "summary": "Bank Lab Scan complete. No suspicious files or persistence mechanisms found.",
                "timeline": [],
                "recommendation": "No immediate action required.",
                "total_files_scanned": total_files_found,
                "total_folders_scanned": total_folders_found,
            }, ensure_ascii=False)

        scored_files.sort(key=lambda x: x[0], reverse=True)
        top_suspects = scored_files[:5]   # Capped at 5 to keep AI prompt lean on slow machines

        aggregate_lines: list[str] = []
        aggregate_lines.append(f"=== BANK LAB TRIAGE REPORT — {datetime.now().isoformat()} ===")
        aggregate_lines.append(f"Target directories: 8 High-Value Lab Locations + Live Registry")
        aggregate_lines.append(f"Total files scanned: {len(scored_files) + skipped}")
        aggregate_lines.append(f"Suspicious artifacts found: {len(scored_files)}")
        aggregate_lines.append(f"Presenting top {len(top_suspects)} suspects:\n")

        file_meta_list = []
        for rank, (score, justifications, fpath) in enumerate(top_suspects, start=1):
            if fpath.startswith("HKCU") or fpath.startswith("HKLM"):
                ext = "[REGISTRY]"
                size = 0
                mtime_str = "Live Registry"
                sha256_val = "N/A"
                content = f"Virtual Registry Entry: {fpath}"
            else:
                ext   = os.path.splitext(fpath)[1].lower()
                size  = 0
                mtime_str = "unknown"
                sha256_val = ""
                try:
                    stat_info = os.stat(fpath)
                    size = stat_info.st_size
                    mtime_str = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    
                    h = hashlib.sha256()
                    with open(fpath, "rb") as fh:
                        for chunk in iter(lambda: fh.read(65536), b""):
                            h.update(chunk)
                    sha256_val = h.hexdigest().lower()
                except OSError:
                    pass
                content = self._extract_text(fpath)

            justification_text = "  " + "\n  ".join(
                f"[{j+1}] {reason}" for j, reason in enumerate(justifications)
            ) if justifications else "  [No specific rule triggered]"

            block = (
                f"--- FILE #{rank} (Suspicion Score: {score}) ---\n"
                f"Path      : {fpath}\n"
                f"Extension : {ext}\n"
                f"Size      : {size} bytes\n"
                f"Modified  : {mtime_str}\n"
                f"SHA-256   : {sha256_val}\n"
                f"Scoring Justification:\n{justification_text}\n"
                f"Content Preview:\n{content}\n"
            )
            aggregate_lines.append(block)

            if fpath.startswith("HKCU") or fpath.startswith("HKLM"):
                name = fpath.split(" -> ")[0].split("\\")[-1]
                path = fpath.split(" -> ")[1] if " -> " in fpath else fpath
                file_meta_list.append({
                    "name": name,
                    "path": fpath,
                    "extension": "[REGISTRY]",
                    "size": 0,
                    "modified": "Live Registry",
                    "score": score,
                    "sha256": "N/A",
                    "justifications": justifications,
                    "rank": rank,
                    "justification": justifications
                })
            else:
                file_meta_list.append({
                    "rank": rank,
                    "score": score,
                    "path": fpath,
                    "extension": ext,
                    "size": size,
                    "modified": mtime_str,
                    "justification": justifications,
                    "sha256": sha256_val,
                })

        raw_data = "\n".join(aggregate_lines)
        _report_progress("AI_THINKING", 65, "")
        ai_result = self._analyze_with_local_ai(raw_data)
        _report_progress("SAVING", 92, "")

        try:
            result_obj = json.loads(ai_result)
        except (json.JSONDecodeError, TypeError):
            return json.dumps({
                "error": "The AI response was not valid JSON. The model may still be warming up — please retry.",
                "raw_response": ai_result,
            }, ensure_ascii=False)

        if "error" in result_obj:
            print(f"[WARN] AI analysis returned an error: {result_obj['error']}")
            return json.dumps(result_obj, ensure_ascii=False)

        result_obj["scanned_files"]         = file_meta_list
        result_obj["total_suspicious"]      = len(scored_files)
        result_obj["total_files_scanned"]   = total_files_found
        result_obj["total_folders_scanned"] = total_folders_found
        scan_ts = datetime.now()
        result_obj["scan_timestamp"] = scan_ts.isoformat()

        report_path = self._save_report(result_obj, file_meta_list, scan_ts)
        if report_path:
            result_obj["report_file_path"] = report_path

        _report_progress("COMPLETE", 100, "")
        return json.dumps(result_obj, ensure_ascii=False)

    def start_emergency_scan(self, folder_path: str) -> str:
        """
        Kicks off the emergency scan in a background thread so it doesn't block the PyWebView JS bridge.
        """
        if not folder_path or not os.path.isdir(folder_path):
            return json.dumps({"error": "Target path not found. Please verify the path exists and try again."}, ensure_ascii=False)

        def worker():
            try:
                res = self._do_start_emergency_scan(folder_path)
                _progress_state["result"] = res
                _progress_state["percent"] = 100
                _progress_state["phase"] = "COMPLETE"
            except Exception as e:
                _progress_state["result"] = json.dumps({"error": str(e)}, ensure_ascii=False)
                _progress_state["percent"] = 100
                _progress_state["phase"] = "ERROR"

        threading.Thread(target=worker, daemon=True).start()
        return json.dumps({"status": "started"}, ensure_ascii=False)

    def _do_start_emergency_scan(self, folder_path: str) -> str:
        """
        Stage 1: Triage the target folder.
        Stage 2: Send top suspects to local AI for analysis.
        Returns a JSON string to the frontend.
        """
        # --- Validate path ---
        if not folder_path or not os.path.isdir(folder_path):
            return json.dumps({"error": "Target path not found. Please verify the path exists and try again."}, ensure_ascii=False)

        # --- Stage 1: Recursive file enumeration & scoring ---
        scored_files: list[tuple[int, str]] = []
        skipped = 0
        total_files_found   = 0  # every file seen, before any filtering
        total_folders_found = 0  # every directory visited by os.walk
        files_processed     = 0  # for live progress reporting

        _report_progress("SCANNING", 5, f"Starting scan: {folder_path}")

        try:
            for root, dirs, files in os.walk(folder_path, followlinks=False):
                total_folders_found += 1
                # Skip clearly irrelevant system dirs to speed up scan
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in {
                        "windows", "program files", "program files (x86)",
                        ".git", "node_modules", "__pycache__",
                    }
                ]

                for filename in files:
                    total_files_found += 1   # count every file, no exceptions
                    files_processed += 1
                    full_path = os.path.join(root, filename)
                    try:
                        # Skip symlinks and very large files (> 50 MB)
                        if os.path.islink(full_path):
                            continue
                        if os.path.getsize(full_path) > 50 * 1024 * 1024:
                            skipped += 1
                            continue

                        # Always print every file to CMD console for full audit trail
                        print(f"[SCANNING] {full_path}")

                        # Report progress every 5 files: 5% → 60%
                        if files_processed % 5 == 0:
                            progress_pct = min(60, 5 + files_processed // 5)
                            _report_progress("SCANNING", progress_pct, full_path)

                        result = self._score_file(full_path)
                        score, justifications = result
                        if score > 0:
                            scored_files.append((score, justifications, full_path))
                    except OSError:
                        skipped += 1
                        continue
        except PermissionError as exc:
            return json.dumps({"error": f"Access denied: {exc}"}, ensure_ascii=False)

        if not scored_files:
            return json.dumps({
                "risk_level": "LOW",
                "summary": "Scan complete. No suspicious files were found in the selected directory.",
                "timeline": [],
                "recommendation": "No immediate action required. Continue routine monitoring of the system.",
                "total_files_scanned": total_files_found,
                "total_folders_scanned": total_folders_found,
            }, ensure_ascii=False)

        # Sort descending by score, take top 10
        scored_files.sort(key=lambda x: x[0], reverse=True)
        top_suspects = scored_files[:10]

        # --- Stage 2: Aggregate suspect data ---
        aggregate_lines: list[str] = []
        aggregate_lines.append(f"=== TRIAGE REPORT — {datetime.now().isoformat()} ===")
        aggregate_lines.append(f"Target directory: {folder_path}")
        aggregate_lines.append(f"Total files scanned: {len(scored_files) + skipped}")
        aggregate_lines.append(f"Suspicious files found: {len(scored_files)}")
        aggregate_lines.append(f"Presenting top {len(top_suspects)} suspects:\n")

        file_meta_list = []

        for rank, (score, justifications, fpath) in enumerate(top_suspects, start=1):
            ext   = os.path.splitext(fpath)[1].lower()
            size  = 0
            mtime_str = "unknown"
            sha256_val = ""
            try:
                stat_info = os.stat(fpath)
                size = stat_info.st_size
                mtime_str = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                
                h = hashlib.sha256()
                with open(fpath, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                sha256_val = h.hexdigest().lower()
            except OSError:
                pass

            content = self._extract_text(fpath)

            # Build the justification summary for the LLM triage block
            justification_text = "  " + "\n  ".join(
                f"[{j+1}] {reason}" for j, reason in enumerate(justifications)
            ) if justifications else "  [No specific rule triggered — score accumulated from multiple minor factors]"

            block = (
                f"--- FILE #{rank} (Suspicion Score: {score}) ---\n"
                f"Path      : {fpath}\n"
                f"Extension : {ext}\n"
                f"Size      : {size} bytes\n"
                f"Modified  : {mtime_str}\n"
                f"SHA-256   : {sha256_val}\n"
                f"Scoring Justification:\n{justification_text}\n"
                f"Content Preview:\n{content}\n"
            )
            aggregate_lines.append(block)

            file_meta_list.append({
                "rank": rank,
                "score": score,
                "path": fpath,
                "extension": ext,
                "size": size,
                "modified": mtime_str,
                "justification": justifications,
                "sha256": sha256_val,
            })

        raw_data = "\n".join(aggregate_lines)

        # --- Stage 3: AI Analysis ---
        _report_progress("AI_THINKING", 65, "")
        ai_result = self._analyze_with_local_ai(raw_data)
        _report_progress("SAVING", 92, "")

        # Decode the AI result
        try:
            result_obj = json.loads(ai_result)
        except (json.JSONDecodeError, TypeError):
            return json.dumps({
                "error": "The AI response was not valid JSON. The model may still be warming up — please retry.",
                "raw_response": ai_result,
            }, ensure_ascii=False)

        # --- Guard: if the AI layer returned an error, surface it immediately ---
        # Do NOT attempt to build or save a forensic report on a failed response.
        if "error" in result_obj:
            print(f"[WARN] AI analysis returned an error: {result_obj['error']}")
            return json.dumps(result_obj, ensure_ascii=False)

        # Merge scan metadata into result for the UI
        result_obj["scanned_files"]         = file_meta_list
        result_obj["total_suspicious"]      = len(scored_files)
        result_obj["total_files_scanned"]   = total_files_found
        result_obj["total_folders_scanned"] = total_folders_found
        scan_ts = datetime.now()
        result_obj["scan_timestamp"] = scan_ts.isoformat()

        # --- Save physical forensic report to USB ---
        report_path = self._save_report(result_obj, file_meta_list, scan_ts)
        if report_path:
            result_obj["report_file_path"] = report_path

        _report_progress("COMPLETE", 100, "")
        return json.dumps(result_obj, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Internal: Save Physical Forensic Report to USB
    # ------------------------------------------------------------------

    def _save_report(
        self,
        result_obj: dict,
        file_meta_list: list,
        scan_ts: datetime,
    ) -> Optional[str]:
        """
        Write a professional SOC forensic incident report as a plain-text file
        inside EXE_DIR/reports/ on the USB drive.
        Returns the absolute file path on success, or None on failure.

        NOTE: We use EXE_DIR here (the real directory containing the .exe) rather
        than BASE_DIR, because when frozen BASE_DIR == sys._MEIPASS which is a
        temporary read-only extraction directory that is wiped on exit.
        """
        try:
            reports_dir = os.path.join(EXE_DIR, "reports")
            os.makedirs(reports_dir, exist_ok=True)

            filename = f"incident_report_{scan_ts.strftime('%Y%m%d_%H%M%S')}.txt"
            report_path = os.path.join(reports_dir, filename)

            risk_level    = result_obj.get("risk_level", "UNKNOWN")
            summary       = result_obj.get("summary", "")
            recommendation = result_obj.get("recommendation", "")
            timeline      = result_obj.get("timeline", [])
            total_suspicious = result_obj.get("total_suspicious", len(file_meta_list))

            separator = "=" * 72

            lines: list[str] = [
                separator,
                "       SOC EMERGENCY AI SCANNER — INCIDENT FORENSIC REPORT",
                separator,
                f"  Scan Timestamp  : {scan_ts.strftime('%Y-%m-%d %H:%M:%S')}",
                f"  Risk Level      : {risk_level}",
                f"  Suspicious Files: {total_suspicious}",
                f"  Report File     : {report_path}",
                separator,
                "",
                "[ סיכום המתקפה / ATTACK SUMMARY ]",
                "-" * 72,
                summary,
                "",
                "[ ציר זמן / ATTACK TIMELINE ]",
                "-" * 72,
            ]

            for i, event in enumerate(timeline, start=1):
                t    = event.get("time", "??:??")
                evt  = event.get("event", "")
                etype = event.get("type", "file").upper()
                lines.append(f"  [{i:02d}] {t}  [{etype}]  {evt}")

            lines += [
                "",
                "[ המלצות לצוות ה-SOC / RECOMMENDATIONS ]",
                "-" * 72,
                recommendation,
                "",
                "[ קבצים חשודים / SUSPECT FILE LIST ]",
                "-" * 72,
            ]

            critical_files = [f for f in file_meta_list if f["score"] >= 100]
            warning_files = [f for f in file_meta_list if f["score"] < 100]

            def _append_files(group_files):
                for f in group_files:
                    bar_pct  = min(100, f["score"])
                    bar_fill = int(bar_pct / 5)
                    bar      = "█" * bar_fill + "░" * (20 - bar_fill)
                    lines.append(
                        f"  #{f['rank']:02d}  Score: {f['score']:3d}  [{bar}]  {f['path']}"
                    )
                    lines.append(
                        f"       Ext: {f['extension']}  |  "
                        f"Size: {f['size'] / 1024:.1f} KB  |  "
                        f"Modified: {f['modified']}"
                    )
                    reasons = f.get("justification", [])
                    if reasons:
                        for reason in reasons:
                            lines.append(f"       👉 Flagged Reason: {reason}")
                    else:
                        lines.append("       👉 Flagged Reason: Score accumulated from multiple minor indicators")
                    lines.append("")

            if not file_meta_list:
                lines.append("  None detected.\n")
            else:
                if critical_files:
                    lines += [
                        "========================================================================",
                        "🔴 [ CATEGORY 01 ]  CRITICAL THREATS (CONFIRMED MALWARE & SPOOFING)",
                        "========================================================================"
                    ]
                    _append_files(critical_files)
                
                # If both groups exist, _append_files left one trailing blank line.
                # Adding one more creates the requested double line break buffer.
                if critical_files and warning_files:
                    lines.append("")

                if warning_files:
                    lines += [
                        "========================================================================",
                        "🟡 [ CATEGORY 02 ]  WARNINGS (UNSIGNED BINARIES FOR ANALYST TRIAGE)",
                        "========================================================================"
                    ]
                    _append_files(warning_files)

            lines += [
                separator,
                "  Generated by SOC Emergency AI Scanner v1.0 — Offline USB Mode",
                "  All AI analysis performed locally. No data left the device.",
                separator,
            ]

            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))

            print(f"[INFO] Forensic report saved: {report_path}")
            return report_path

        except Exception as exc:
            print(f"[WARN] Could not save report: {exc}")
            return None

    # ------------------------------------------------------------------
    # Internal: Local AI Analysis
    # ------------------------------------------------------------------

    def _analyze_with_local_ai(self, raw_data: str) -> str:
        """
        POST the aggregated file data to the locally running llama-server
        via the OpenAI-compatible /v1/chat/completions endpoint.

        Using /v1/chat/completions instead of /completion ensures the
        Qwen2.5 <|im_start|> chat template is applied automatically by
        llama-server, so the model receives correctly formatted instructions
        and produces structured JSON output instead of echoing the input.
        """
        payload = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": f"Analyze the following data and return ONLY the JSON object:\n\n{raw_data}"},
            ],
            "max_tokens": 512,   # Trimmed for slow CPU machines (~8 tok/s VMs)
            "temperature": 0.2,
            "stop": ["```", "\n\n\n"],
        }

        try:
            response = requests.post(
                AI_SERVER_URL,
                json=payload,
                timeout=600,  # 10 min — handles slow VM inference (~8 tok/s)
            )
            response.raise_for_status()
            data = response.json()

            # /v1/chat/completions returns text under choices[0].message.content
            raw_text = (
                data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                    .strip()
            )

            # ── DEBUG: print raw AI response to terminal for auditing ──────────
            print("\n=================== RAW AI RESPONSE ===================")
            print(raw_text)
            print("=======================================================\n")
            # ──────────────────────────────────────────────────────────────────

            # ── Extract JSON block (brace-depth tracker) ──────────────────────
            start_idx = raw_text.find('{')
            if start_idx != -1:
                depth = 0
                end_idx = start_idx
                for idx in range(start_idx, len(raw_text)):
                    if raw_text[idx] == '{':
                        depth += 1
                    elif raw_text[idx] == '}':
                        depth -= 1
                        if depth == 0:
                            end_idx = idx
                            break
                json_candidate = raw_text[start_idx:end_idx + 1]
            else:
                json_candidate = raw_text
            # ──────────────────────────────────────────────────────────────────

            # ── Parse attempt 1: direct (chat API already returns valid JSON) ─
            try:
                json.loads(json_candidate)
                return json_candidate
            except json.JSONDecodeError:
                pass
            # ──────────────────────────────────────────────────────────────────

            # ── Parse attempt 2: backslash sanitizer (fallback for raw paths) ─
            fixed_text = ""
            in_string = False
            i = 0
            while i < len(json_candidate):
                char = json_candidate[i]
                if char == '"' and (i == 0 or json_candidate[i-1] != '\\'):
                    in_string = not in_string
                if in_string and char == '\\':
                    if i + 1 < len(json_candidate):
                        next_char = json_candidate[i+1]
                        if next_char in ['"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u']:
                            fixed_text += char
                        else:
                            fixed_text += '\\\\'
                    else:
                        fixed_text += '\\\\'
                else:
                    fixed_text += char
                i += 1

            try:
                json.loads(fixed_text)
                return fixed_text
            except json.JSONDecodeError as parse_err:
                print(f"[WARN] JSON parse failed after sanitizer: {parse_err}")
                print(f"[WARN] Candidate text was: {json_candidate[:300]}")
            # ──────────────────────────────────────────────────────────────────

            raise json.JSONDecodeError("Could not parse AI response", json_candidate, 0)

        except requests.exceptions.ConnectionError:
            return json.dumps({
                "error": "AI server is not responding. It may still be initializing — please wait a few seconds and retry."
            }, ensure_ascii=False)
        except requests.exceptions.Timeout:
            return json.dumps({
                "error": "AI server timed out. The scan payload may be too large or the model is overloaded — please retry."
            }, ensure_ascii=False)
        except requests.exceptions.HTTPError as exc:
            return json.dumps({
                "error": f"HTTP error from AI server: {exc}"
            }, ensure_ascii=False)
        except json.JSONDecodeError:
            return json.dumps({
                "error": "The AI returned a malformed response that could not be parsed as JSON. The model may still be warming up — please retry."
            }, ensure_ascii=False)
        except Exception as exc:
            return json.dumps({
                "error": f"Unexpected error during AI analysis: {str(exc)}"
            }, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Public: Health Check (callable from JS to check if AI is ready)
    # ------------------------------------------------------------------

    def get_progress(self) -> str:
        """
        Return the current scan progress as a JSON string.
        Polled by the React frontend every ~600 ms while a scan is running.
        This is the reliable fallback for when evaluate_js cannot push progress
        from inside a pywebview JS-API handler thread.
        """
        return json.dumps(_progress_state)

    def check_ai_status(self) -> str:
        """Check if the local AI server is healthy and ready."""
        try:
            resp = requests.get(AI_SERVER_HEALTH_URL, timeout=3)
            if resp.status_code == 200:
                return json.dumps({"status": "ready"})
            return json.dumps({"status": "initializing"})
        except Exception:
            return json.dumps({"status": "offline"})

    # ------------------------------------------------------------------
    # Public: Get base directory info (for display in the UI)
    # ------------------------------------------------------------------

    def get_system_info(self) -> str:
        """Return info about the USB base directory and model status."""
        return json.dumps({
            "base_dir": BASE_DIR,
            "llama_server_found": os.path.isfile(LLAMA_SERVER_PATH),
            "model_found": os.path.isfile(MODEL_PATH),
            "platform": sys.platform,
        })


# ---------------------------------------------------------------------------
# Lightweight HTTP Server for POST Automation
# ---------------------------------------------------------------------------
GLOBAL_API = None

class PresetAPIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            payload = json.loads(post_data.decode('utf-8'))
            
            if payload.get("preset") == "bank-lab" and GLOBAL_API:
                # Trigger the preset synchronously to hold the connection
                # and return the final JSON payload directly back to React fetch()
                result_json = GLOBAL_API.run_bank_lab_preset()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(result_json.encode('utf-8'))
                return
                
        self.send_response(404)
        self.end_headers()
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
    def log_message(self, format, *args):
        pass  # Suppress default HTTP logs

def start_http_server():
    server = HTTPServer(('127.0.0.1', 5000), PresetAPIHandler)
    server.serve_forever()

# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

def main():
    global ai_process, MAIN_WINDOW, GLOBAL_API

    # Step 1: Launch the local AI server in the background
    print(f"[INFO] USB Base Directory: {BASE_DIR}")
    print(f"[INFO] Launching llama-server from: {LLAMA_SERVER_PATH}")
    ai_process = launch_ai_server()

    # Step 2: Create the API bridge and start HTTP Server
    api = CyberAPI()
    GLOBAL_API = api
    threading.Thread(target=start_http_server, daemon=True).start()
    print("[INFO] Local Automation API listening on port 5000")

    # Step 3: Determine path to the React build.
    # BASE_DIR == sys._MEIPASS when frozen (PyInstaller extracts the bundled
    # frontend/build folder there at startup), or the script directory otherwise.
    frontend_build_dir = os.path.join(BASE_DIR, "frontend", "build")
    index_html         = os.path.join(frontend_build_dir, "index.html")

    # Step 4: Create the PyWebView window
    print(f"[DIAG] Frontend build path : {index_html}")
    print(f"[DIAG] Frontend build exists: {os.path.isfile(index_html)}")
    resolved_url = index_html if os.path.isfile(index_html) else "http://localhost:3000"
    print(f"[DIAG] PyWebView will load  : {resolved_url}")
    print(f"[DIAG] PyWebView version    : {getattr(webview, '__version__', 'unknown')}")

    try:
        window = webview.create_window(
            title      = "SOC Emergency AI Scanner — Offline USB Mode",
            url        = resolved_url,
            js_api     = api,
            width      = 1400,
            height     = 900,
            min_size   = (1024, 700),
            background_color = "#020817",  # Matches slate-950
            text_select = True,
        )
        print("[DIAG] webview.create_window() succeeded.")
    except Exception as exc:
        print(f"[ERROR] webview.create_window() FAILED: {exc}")
        raise

    # Store window in the module-level global ONLY — never inside CyberAPI.
    # Storing it as a class attribute causes PyWebView to try to serialize it
    # into JavaScript, triggering a "maximum recursion depth exceeded" crash.
    MAIN_WINDOW = window

    # Register the close handler via the events API (fixed lifecycle)
    window.events.closed += on_window_closed

    # Step 5: Start PyWebView
    print("[DIAG] Calling webview.start() — if the app hangs here, WebView2 Runtime is missing on this machine.")
    print("[DIAG] Download WebView2 from: https://developer.microsoft.com/en-us/microsoft-edge/webview2/")
    try:
        webview.start(debug=False)
        print("[DIAG] webview.start() returned normally (window was closed).")
    except Exception as exc:
        print(f"[ERROR] webview.start() FAILED: {exc}")


if __name__ == "__main__":
    main()
