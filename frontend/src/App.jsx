import React, { useState, useEffect, useRef, useCallback } from 'react';

// ── Icons (inline SVG components to avoid npm deps) ──────────────────────────
const Icon = ({ d, size = 16, className = '' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth={2} strokeLinecap="round"
    strokeLinejoin="round" className={className}>
    <path d={d} />
  </svg>
);

const Icons = {
  Shield:    () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  Usb:       () => <Icon d="M10 2h4v6l2 2-2 2v4l-4 2-4-2v-4L4 10l2-2V2h4zM8 2v2m8-2v2M9 14v4m6-4v4" />,
  Folder:    () => <Icon d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />,
  Scan:      () => <Icon d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2M7 12h10M12 7v10" />,
  Alert:     () => <Icon d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" />,
  Check:     () => <Icon d="M20 6L9 17l-5-5" />,
  Clock:     () => <Icon d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 6v6l4 2" />,
  File:      () => <Icon d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-7-7zM13 2v7h7" />,
  Network:   () => <Icon d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2v-4M9 21H5a2 2 0 0 0-2-2v-4m0 0h18" />,
  Persist:   () => <Icon d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />,
  Cpu:       () => <Icon d="M18 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zM9 9h6v6H9z" />,
  Info:      () => <Icon d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 16v-4M12 8h.01" />,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const callPython = async (method, ...args) => {
  // Wait for pywebview bridge to be injected
  let attempts = 0;
  while ((!window.pywebview || !window.pywebview.api) && attempts < 40) {
    await sleep(150);
    attempts++;
  }
  if (!window.pywebview?.api) throw new Error('PyWebView bridge unavailable');
  return window.pywebview.api[method](...args);
};

// ── Risk config ───────────────────────────────────────────────────────────────
const RISK = {
  HIGH:   { label: 'HIGH RISK', bg: 'bg-red-950/60',    border: 'border-red-500',    text: 'text-red-400',    glow: 'border-glow-red',    pulse: 'animate-danger-pulse' },
  MEDIUM: { label: 'MEDIUM RISK', bg: 'bg-orange-950/60', border: 'border-orange-500', text: 'text-orange-400', glow: 'border-glow-orange',  pulse: '' },
  LOW:    { label: 'LOW RISK',  bg: 'bg-green-950/60',  border: 'border-green-500',  text: 'text-green-400',  glow: 'border-glow-green',   pulse: '' },
};

const TYPE_ICON = { file: Icons.File, network: Icons.Network, persistence: Icons.Persist };
const TYPE_COLOR = { file: 'text-blue-400 bg-blue-950/50 border-blue-700', network: 'text-orange-400 bg-orange-950/50 border-orange-700', persistence: 'text-red-400 bg-red-950/50 border-red-700' };

// ── Sub-components ────────────────────────────────────────────────────────────

function Header({ aiStatus }) {
  const statusCfg = {
    ready:        { dot: 'bg-green-400 animate-pulse-glow', label: 'AI ENGINE READY',        color: 'text-green-400' },
    initializing: { dot: 'bg-yellow-400 animate-pulse',     label: 'AI INITIALIZING...',     color: 'text-yellow-400' },
    offline:      { dot: 'bg-red-500 animate-pulse',        label: 'AI ENGINE OFFLINE',      color: 'text-red-400' },
    unknown:      { dot: 'bg-slate-500',                    label: 'CHECKING AI...',         color: 'text-slate-400' },
  };
  const s = statusCfg[aiStatus] || statusCfg.unknown;

  return (
    <header className="relative border-b border-slate-800 bg-slate-950/90 backdrop-blur-sm">
      {/* Top accent line */}
      <div className="h-0.5 w-full bg-gradient-to-r from-red-500 via-blue-500 to-green-500" />
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-red-600 to-red-900 flex items-center justify-center border border-red-700 shadow-lg shadow-red-900/50">
              <span className="text-2xl">🛡️</span>
            </div>
          </div>
          <div>
            <h1 className="text-xl font-black tracking-widest text-white text-glow-red uppercase">
              SOC Emergency AI Scanner
            </h1>
            <p className="text-xs text-slate-500 font-mono tracking-wider">
              INCIDENT RESPONSE • OFFLINE FORENSICS • BLUE TEAM OPERATIONS
            </p>
          </div>
        </div>

        {/* Badges */}
        <div className="flex items-center gap-3">
          {/* USB Mode badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-950/60 border border-green-600 animate-pulse-glow">
            <div className="w-2 h-2 rounded-full bg-green-400" />
            <span className="text-xs font-bold text-green-300 tracking-widest">OFFLINE / USB MODE ACTIVE</span>
          </div>
          {/* AI status badge */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-700`}>
            <div className={`w-2 h-2 rounded-full ${s.dot}`} />
            <span className={`text-xs font-bold tracking-widest ${s.color}`}>{s.label}</span>
          </div>
        </div>
      </div>
    </header>
  );
}

function ScanControl({ folderPath, setFolderPath, onScan, onUnifiedScan, loading, aiStatus }) {
  const [scanConfig, setScanConfig] = useState({
    downloads_desktop: true,
    temp_folders: true,
    browser_cache: true,
    registry: true,
    scheduled_tasks: true,
    event_logs: true
  });
  const [configOpen, setConfigOpen] = useState(false);

  const configOptions = [
    { key: 'downloads_desktop', label: 'Downloads & Desktop',                    icon: '📁' },
    { key: 'temp_folders',      label: 'Temp Folders',                           icon: '🗂️' },
    { key: 'browser_cache',     label: 'Browser Cache (Chrome, Edge, Firefox…)', icon: '🌐' },
    { key: 'registry',          label: 'Registry — Persistence Keys',            icon: '🔑' },
    { key: 'scheduled_tasks',   label: 'Scheduled Tasks',                        icon: '⏱️' },
    { key: 'event_logs',        label: 'Event Logs (PowerShell)',                 icon: '📋' },
  ];

  const enabledCount = Object.values(scanConfig).filter(Boolean).length;

  return (
    <div className="glass-card rounded-2xl border border-slate-800/80 overflow-hidden">

      <div className="p-6">
        <button
          id="default-scan-btn"
          onClick={() => onUnifiedScan(scanConfig)}
          disabled={loading || aiStatus !== 'ready'}
          className="w-full relative flex items-center justify-center gap-3 px-8 py-5 rounded-xl font-black text-base tracking-[0.15em] uppercase text-white
            bg-gradient-to-r from-slate-700 to-slate-600
            border border-slate-500
            hover:from-slate-600 hover:to-slate-500 hover:border-slate-400
            focus:outline-none focus:ring-2 focus:ring-slate-400 focus:ring-offset-2 focus:ring-offset-slate-950
            disabled:opacity-30 disabled:cursor-not-allowed
            transition-all duration-200
            shadow-[0_4px_24px_rgba(0,0,0,0.5)]
            hover:shadow-[0_4px_32px_rgba(148,163,184,0.12)]
            active:scale-[0.99] group overflow-hidden"
        >
          <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="relative z-10 text-slate-300 flex-shrink-0">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><path d="M11 8v6M8 11h6"/>
          </svg>
          <span className="relative z-10">
            {loading ? 'SCAN IN PROGRESS…' : 'INITIATE DEFAULT SCAN'}
          </span>
          {!loading && (
            <span className="relative z-10 ml-1 px-2 py-0.5 rounded text-xs font-bold bg-slate-900/60 text-slate-400 border border-slate-700 tracking-normal normal-case">
              {enabledCount}/6 modules
            </span>
          )}
        </button>

        {aiStatus !== 'ready' && (
          <p className="mt-2 text-center text-xs text-amber-500/80 font-mono tracking-wide">
            Waiting for AI engine to come online…
          </p>
        )}
      </div>

      <div className="border-t border-slate-800/80">
        <button
          onClick={() => setConfigOpen(o => !o)}
          className="w-full flex items-center justify-between px-6 py-3 text-xs font-semibold tracking-widest uppercase text-slate-500
            hover:text-slate-300 hover:bg-slate-800/30 transition-all duration-150"
        >
          <span className="flex items-center gap-2">
            <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
            </svg>
            Advanced Scan Configuration
          </span>
          <span className="flex items-center gap-2">
            <span className="text-slate-700 font-mono normal-case tracking-normal">
              {enabledCount} of 6 active
            </span>
            <svg
              width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}
              strokeLinecap="round" strokeLinejoin="round"
              className={`transition-transform duration-200 ${configOpen ? 'rotate-180' : ''}`}
            >
              <path d="m6 9 6 6 6-6"/>
            </svg>
          </span>
        </button>

        <div className={`overflow-hidden transition-all duration-300 ease-in-out ${configOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'}`}>
          <div className="px-6 pb-4 pt-1 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {configOptions.map(({ key, label, icon }) => {
              const active = scanConfig[key];
              return (
                <label
                  key={key}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer select-none transition-all duration-150 group/item ${
                    active
                      ? 'bg-slate-800/60 border-slate-600 text-slate-200'
                      : 'bg-slate-900/40 border-slate-800 text-slate-500 hover:border-slate-700'
                  }`}
                >
                  <input
                    type="checkbox"
                    className="hidden"
                    checked={active}
                    onChange={() => setScanConfig(prev => ({ ...prev, [key]: !prev[key] }))}
                  />
                  <div className={`flex-shrink-0 w-4 h-4 rounded flex items-center justify-center border transition-all ${
                    active ? 'bg-cyan-500 border-cyan-500' : 'bg-transparent border-slate-600 group-hover/item:border-slate-500'
                  }`}>
                    {active && (
                      <svg width={10} height={10} viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth={3.5} strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 6 9 17l-5-5"/>
                      </svg>
                    )}
                  </div>
                  <span className="text-xs font-medium tracking-wide leading-tight">
                    <span className="mr-1">{icon}</span>{label}
                  </span>
                </label>
              );
            })}
          </div>
          <div className="flex items-center gap-3 px-6 pb-4">
            <button
              onClick={() => setScanConfig(Object.fromEntries(configOptions.map(o => [o.key, true])))}
              className="text-xs text-cyan-600 hover:text-cyan-400 transition-colors font-mono tracking-wide"
            >
              Enable All
            </button>
            <span className="text-slate-700">·</span>
            <button
              onClick={() => setScanConfig(Object.fromEntries(configOptions.map(o => [o.key, false])))}
              className="text-xs text-slate-600 hover:text-slate-400 transition-colors font-mono tracking-wide"
            >
              Disable All
            </button>
          </div>
        </div>
      </div>

      <div className="border-t border-slate-800/80 px-6 py-3">
        <span className="text-xs font-bold tracking-widest text-slate-700 uppercase">Or scan a custom path</span>
      </div>

      <div className="px-6 pb-6">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600">
              <Icons.Folder />
            </div>
            <input
              id="folder-path-input"
              type="text"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              placeholder="C:\Users\Suspect\AppData  — or drag & drop a path here"
              disabled={loading}
              className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-800 rounded-xl text-sm text-slate-200 placeholder-slate-700 font-mono
                focus:outline-none focus:ring-1 focus:ring-slate-500 focus:border-slate-600
                transition-all disabled:opacity-40"
            />
          </div>
          <button
            id="start-scan-btn"
            onClick={onScan}
            disabled={loading || !folderPath.trim() || aiStatus !== 'ready'}
            className="relative px-5 py-3 rounded-xl font-bold text-sm tracking-widest uppercase text-white
              bg-red-700 border border-red-600
              hover:bg-red-600 hover:border-red-500
              focus:outline-none focus:ring-2 focus:ring-red-500
              disabled:opacity-30 disabled:cursor-not-allowed
              transition-all duration-200 shadow-lg shadow-red-950/50
              active:scale-95 flex items-center gap-2"
          >
            <Icons.Scan />
            {loading ? 'SCANNING…' : 'SCAN PATH'}
          </button>
        </div>
      </div>
    </div>
  );
}

function LoadingState({ phase, percent, currentFile }) {
  const PHASES = {
    INIT:        { icon: '⚡', label: 'Initializing Scanner',         color: 'text-yellow-400',  bar: 'from-yellow-600 to-yellow-400'  },
    SCANNING:    { icon: '🔍', label: 'Scanning & Hashing Files',     color: 'text-blue-400',    bar: 'from-blue-700 to-cyan-400'      },
    AI_THINKING: { icon: '🤖', label: 'AI Analyzing Threats',         color: 'text-purple-400',  bar: 'from-purple-700 to-pink-400'    },
    SAVING:      { icon: '💾', label: 'Generating Forensic Report',   color: 'text-green-400',   bar: 'from-green-700 to-emerald-400'  },
    COMPLETE:    { icon: '✅', label: 'Complete',                     color: 'text-green-300',   bar: 'from-green-500 to-green-300'    },
  };

  const cfg = PHASES[phase] || PHASES.INIT;

  // During AI inference we don’t know the duration, so auto-increment toward 90%
  const [displayPct, setDisplayPct] = useState(percent || 0);
  useEffect(() => {
    setDisplayPct(percent || 0);
    if (phase === 'AI_THINKING') {
      const iv = setInterval(() => {
        setDisplayPct(p => (p < 90 ? Math.min(90, p + 0.15) : p));
      }, 400);
      return () => clearInterval(iv);
    }
  }, [phase, percent]);

  const subtitle = {
    INIT:        'Setting up the scan engine...',
    SCANNING:    `Traversing file system — computing SHA-256 hashes and suspicion scores`,
    AI_THINKING: 'Local CPU inference in progress — this may take a few minutes on first run',
    SAVING:      'Writing the incident report to disk...',
    COMPLETE:    'Scan complete.',
  }[phase] || 'Please wait...';

  // Step strip config
  const steps = [
    { key: 'SCANNING',    label: 'Scan' },
    { key: 'AI_THINKING', label: 'AI'   },
    { key: 'SAVING',      label: 'Report'},
    { key: 'COMPLETE',    label: 'Done'  },
  ];
  const phaseOrder = ['INIT','SCANNING','AI_THINKING','SAVING','COMPLETE'];
  const currentIdx = phaseOrder.indexOf(phase);

  return (
    <div className="glass-card rounded-2xl border border-slate-700 p-10 flex flex-col items-center gap-7 animate-fade-in-up">

      {/* Animated icon ring */}
      <div className="relative w-24 h-24 flex items-center justify-center">
        <div className="absolute inset-0 rounded-full border-2 border-purple-500/20 animate-ping" style={{ animationDuration: '2.5s' }} />
        <div className="absolute inset-2 rounded-full border-2 border-purple-500/40 animate-spin-slow" />
        <div className="absolute inset-4 rounded-full border border-purple-600/60" />
        <span className="text-3xl relative z-10">{cfg.icon}</span>
      </div>

      {/* Phase label + subtitle */}
      <div className="text-center space-y-1.5">
        <p className={`text-xl font-black tracking-widest ${cfg.color}`}>{cfg.label}</p>
        <p className="text-xs text-slate-500 font-mono tracking-wide max-w-md leading-relaxed">{subtitle}</p>
      </div>

      {/* Progress bar */}
      <div className="w-full max-w-md space-y-2">
        <div className="flex justify-between items-center">
          <span className="text-xs font-mono text-slate-500">Progress</span>
          <span className={`text-2xl font-black tabular-nums ${cfg.color}`}>
            {Math.round(displayPct)}%
          </span>
        </div>
        <div className="w-full h-3 bg-slate-800/80 rounded-full overflow-hidden border border-slate-700">
          <div
            className={`h-full rounded-full bg-gradient-to-r ${cfg.bar} transition-all duration-500 ease-out shadow-lg`}
            style={{ width: `${Math.max(2, displayPct)}%` }}
          />
        </div>
        {/* Step strip */}
        <div className="flex justify-between mt-1">
          {steps.map((s) => {
            const sIdx = phaseOrder.indexOf(s.key);
            const done    = sIdx < currentIdx;
            const active  = s.key === phase;
            return (
              <span key={s.key} className={`text-xs font-mono font-bold transition-colors ${
                active ? cfg.color
                : done  ? 'text-slate-400'
                :         'text-slate-700'
              }`}>
                {done ? '✓ ' : ''}{s.label}
              </span>
            );
          })}
        </div>
      </div>

      {/* Current file */}
      {currentFile && (
        <div className="w-full max-w-md flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-800">
          <span className="flex-shrink-0 text-green-500" style={{ fontSize: 10 }}>►</span>
          <p className="text-xs font-mono text-green-400/80 truncate leading-none tracking-tight" title={currentFile}>
            {currentFile}
          </p>
        </div>
      )}

      {/* Ticker dots */}
      <div className="flex gap-2">
        {[0,1,2,3,4].map(i => (
          <div key={i} className="w-1.5 h-1.5 rounded-full bg-green-400 animate-data-ticker"
            style={{ animationDelay: `${i * 0.2}s` }} />
        ))}
      </div>
    </div>
  );
}

function RiskBadge({ level }) {
  const cfg = RISK[level] || RISK.LOW;
  const icon = level === 'HIGH' ? '🚨' : level === 'MEDIUM' ? '⚠️' : '✅';
  return (
    <div className={`inline-flex items-center gap-3 px-6 py-3 rounded-2xl border-2 ${cfg.border} ${cfg.bg} ${cfg.glow} ${cfg.pulse}`}>
      <span className="text-2xl">{icon}</span>
      <div>
        <p className={`text-xl font-black tracking-widest ${cfg.text}`}>{cfg.label}</p>
        <p className="text-xs text-slate-400 font-mono tracking-wider">THREAT ASSESSMENT COMPLETE</p>
      </div>
    </div>
  );
}

function SummaryCard({ summary, riskLevel }) {
  const cfg = RISK[riskLevel] || RISK.LOW;
  return (
    <div className={`glass-card rounded-2xl border ${cfg.border} p-6 space-y-3 animate-fade-in-up`}>
      <div className="flex items-center gap-2">
        <Icons.Info />
        <h3 className="text-sm font-bold tracking-widest text-slate-300 uppercase">Attack Story — AI Analysis</h3>
      </div>
      <p className={`text-base leading-relaxed ${cfg.text}`}>{summary}</p>
    </div>
  );
}

function TimelineItem({ item, index }) {
  const TypeIcon = TYPE_ICON[item.type] || Icons.File;
  const typeColor = TYPE_COLOR[item.type] || TYPE_COLOR.file;
  const typeLabel = item.type === 'file' ? 'FILE' : item.type === 'network' ? 'NETWORK' : 'PERSISTENCE';

  return (
    <div
      className="relative flex gap-4 animate-fade-in-up"
      style={{ animationDelay: `${index * 0.1}s` }}
    >
      {/* Connector line */}
      <div className="flex flex-col items-center gap-0">
        <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center z-10 animate-node-pulse bg-slate-900 ${typeColor.split(' ')[2]} ${typeColor.split(' ')[0]}`}
          style={{ animationDelay: `${index * 0.3}s` }}>
          <TypeIcon />
        </div>
        <div className="w-0.5 flex-1 bg-gradient-to-b from-slate-600 to-transparent min-h-8" />
      </div>

      {/* Content */}
      <div className="flex-1 pb-6">
        <div className="glass-card rounded-xl border border-slate-800 p-4 space-y-2 hover:border-slate-600 transition-colors">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1">
                <Icons.Clock />
                <span className="text-xs font-mono font-bold text-slate-400">{item.time}</span>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded-full border font-bold tracking-wider ${typeColor}`}>
                {typeLabel}
              </span>
            </div>
            {item.path && (
              <button
                onClick={() => callPython('open_file_location', item.path)}
                title="Open location"
                className="flex-shrink-0 px-2 py-1 rounded border border-slate-700 bg-slate-800/50 hover:bg-slate-700 text-slate-300 hover:text-white transition-all text-xs"
              >
                📁 Open
              </button>
            )}
          </div>
          <p className="text-sm text-slate-200 leading-relaxed">{item.event}</p>
          {item.proof && (
            <pre className="text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-slate-400 whitespace-pre-wrap overflow-x-auto mt-2">
              {item.proof}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

function Timeline({ items }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-6 animate-fade-in-up delay-200">
      <div className="flex items-center gap-2 mb-6">
        <Icons.Clock />
        <h3 className="text-sm font-bold tracking-widest text-slate-300 uppercase">Attack Timeline</h3>
        <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
          {items.length} events
        </span>
      </div>
      <div>
        {items.map((item, i) => (
          <TimelineItem key={i} item={item} index={i} />
        ))}
      </div>
    </div>
  );
}

function RecommendationCard({ text }) {
  return (
    <div className="glass-card rounded-2xl border border-yellow-700/50 bg-yellow-950/20 p-6 animate-fade-in-up delay-300">
      <div className="flex items-start gap-3">
        <div className="w-8 h-8 rounded-lg bg-yellow-500/20 border border-yellow-600/50 flex items-center justify-center flex-shrink-0 mt-0.5">
          <Icons.Alert />
        </div>
        <div className="space-y-2 flex-1">
          <h3 className="text-sm font-bold tracking-widest text-yellow-400 uppercase">SOC Recommendations</h3>
          <p className="text-sm text-slate-200 leading-relaxed">{text}</p>
        </div>
      </div>
    </div>
  );
}

// ── Forensic justification badge strip ───────────────────────────────────────
function JustificationBadges({ reasons }) {
  if (!reasons || reasons.length === 0) return null;
  return (
    <div className="mt-1.5 flex flex-col gap-1">
      {reasons.map((reason, idx) => {
        const low = reason.toLowerCase();
        const isDefinitive = low.includes('definitive') || low.includes('signature database');
        const isStructural  = low.includes('unsigned') || low.includes('entropy') || low.includes('masquerad') || low.includes('double-extension');
        const cls = isDefinitive
          ? 'bg-red-950/70 border-red-700/60 text-red-300'
          : isStructural
          ? 'bg-orange-950/70 border-orange-700/60 text-orange-300'
          : 'bg-amber-950/50 border-amber-800/50 text-amber-300';
        const icon = isDefinitive ? '🚨' : isStructural ? '⚠️' : '📌';
        return (
          <div key={idx} className={`flex items-start gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-mono leading-snug ${cls}`}>
            <span className="flex-shrink-0 mt-px">{icon}</span>
            <span>{reason}</span>
          </div>
        );
      })}
    </div>
  );
}

function FileTable({ files }) {
  if (!files || files.length === 0) return null;
  const maxScore = files[0]?.score || 1;
  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-6 animate-fade-in-up delay-400">
      <div className="flex items-center gap-2 mb-4">
        <Icons.File />
        <h3 className="text-sm font-bold tracking-widest text-slate-300 uppercase">Suspect Files Scanned</h3>
        <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
          {files.length} files
        </span>
      </div>
      <div className="space-y-3">
        {files.map((f, i) => {
          const pct      = Math.round((f.score / maxScore) * 100);
          const barColor = pct > 70 ? 'bg-red-500' : pct > 40 ? 'bg-orange-500' : 'bg-yellow-500';
          const cardCls  = pct > 70
            ? 'border-red-900/50 bg-red-950/10'
            : pct > 40
            ? 'border-orange-900/50 bg-orange-950/10'
            : 'border-slate-800/60';
          return (
            <div key={i} className={`rounded-xl border p-3 space-y-2 transition-colors ${cardCls}`}>
              {/* Top row: rank + filename + score bar */}
              <div className="flex items-start gap-3">
                <span className="text-xs font-mono font-bold text-slate-500 w-6 flex-shrink-0 mt-0.5">#{f.rank}</span>
                <div className="flex-1 min-w-0">
                  {/* Bold extracted filename — always fully visible */}
                  <p className="text-sm font-bold text-slate-100 leading-snug mb-0.5">
                    👉 {f.path.replace(/\\/g, '\\').split('\\').filter(Boolean).pop() || f.path}
                  </p>
                  {/* Full absolute path — wraps naturally, never truncated */}
                  <div className="flex items-start gap-2 mb-1">
                    <p className="text-xs text-slate-400 break-all whitespace-pre-wrap leading-relaxed flex-1">
                      {f.path}
                    </p>
                    <button
                      onClick={() => callPython('open_file_location', f.path)}
                      title="Open location"
                      className="flex-shrink-0 px-2 py-1 rounded border border-slate-700 bg-slate-800/50 hover:bg-slate-700 text-slate-300 hover:text-white transition-all text-xs"
                    >
                      📁 Open
                    </button>
                  </div>
                  <p className="text-xs text-slate-600">
                    {f.extension}&nbsp;&bull;&nbsp;{(f.size / 1024).toFixed(1)} KB&nbsp;&bull;&nbsp;{f.modified}
                  </p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 mt-0.5">

                  <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${barColor}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className={`text-xs font-bold font-mono w-8 text-right ${
                    pct > 70 ? 'text-red-400' : pct > 40 ? 'text-orange-400' : 'text-yellow-400'
                  }`}>
                    {f.score}
                  </span>
                </div>
              </div>

              {/* Forensic justification badges — "Why was this flagged?" */}
              {f.justification && f.justification.length > 0 && (
                <div>
                  <p className="text-xs font-bold tracking-wider text-slate-500 uppercase flex items-center gap-1 mb-1">
                    <span>🔍</span> Why flagged:
                  </p>
                  <JustificationBadges reasons={f.justification} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ErrorCard({ message }) {
  return (
    <div className="glass-card rounded-2xl border border-red-800/60 bg-red-950/20 p-6 flex items-start gap-3 animate-fade-in-up">
      <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-600/50 flex items-center justify-center flex-shrink-0">
        <Icons.Alert />
      </div>
      <div>
        <h3 className="text-sm font-bold text-red-400 mb-1">Error</h3>
        <p className="text-sm text-slate-300">{message}</p>
      </div>
    </div>
  );
}

function ScanStatsCard({ totalFiles, totalFolders, totalSuspicious }) {
  const stats = [
    { icon: '📂', label: 'Total Folders Traversed', value: totalFolders?.toLocaleString() ?? '—', color: 'text-blue-400' },
    { icon: '📄', label: 'Total Files Evaluated',   value: totalFiles?.toLocaleString()   ?? '—', color: 'text-slate-300' },
    { icon: '🚨', label: 'Suspicious Files',  value: totalSuspicious?.toLocaleString() ?? '—', color: 'text-red-400'  },
  ];
  return (
    <div className="glass-card rounded-2xl border border-slate-700 p-4 animate-fade-in-up">
      <p className="text-xs font-bold tracking-widest text-slate-400 uppercase mb-3">Scan Coverage — Full Directory Traversal Verified</p>
      <div className="grid grid-cols-3 gap-3">
        {stats.map((s) => (
          <div key={s.label} className="flex flex-col items-center gap-1 bg-slate-900/50 rounded-xl p-3 border border-slate-800">
            <span className="text-xl">{s.icon}</span>
            <span className={`text-lg font-black font-mono ${s.color}`}>{s.value}</span>
            <span className="text-xs text-slate-500 text-center leading-tight">{s.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportSavedCard({ filePath }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(filePath).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  return (
    <div className="glass-card rounded-2xl border border-cyan-700/50 bg-cyan-950/20 p-4 animate-fade-in-up">
      <div className="flex items-start gap-3">
        <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-600/50 flex items-center justify-center flex-shrink-0 mt-0.5">
          <span className="text-base">💾</span>
        </div>
        <div className="flex-1 min-w-0 space-y-1.5">
          <p className="text-xs font-bold tracking-widest text-cyan-400 uppercase">
            Forensic Report Saved to USB Successfully
          </p>
          <div className="flex items-center gap-2">
            <p
              className="text-xs font-mono text-cyan-300 truncate flex-1 bg-slate-900/60 px-2 py-1 rounded border border-slate-800"
              title={filePath}
            >
              {filePath}
            </p>
            <button
              onClick={handleCopy}
              title="Copy path"
              className="flex-shrink-0 px-2 py-1 rounded text-xs font-bold border transition-all duration-150
                         border-cyan-700 text-cyan-400 bg-cyan-950/40 hover:bg-cyan-800/40 hover:border-cyan-500
                         active:scale-95"
            >
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <p className="text-xs text-slate-500 font-mono">
            📁 {filePath}
          </p>
        </div>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [folderPath, setFolderPath]   = useState('');
  const [scanResult, setScanResult]   = useState(null);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState(null);
  const [aiStatus, setAiStatus]       = useState('unknown');
  const [currentFile, setCurrentFile] = useState('');
  const [progress, setProgress]       = useState({ phase: 'INIT', percent: 0, file: '' });
  const pollRef                       = useRef(null);

  // Register global bridge callbacks so Python's evaluate_js can push live updates
  useEffect(() => {
    window.updateScanningFile = (path) => setCurrentFile(path);
    window.updateProgress = ({ phase, percent, file }) => {
      setProgress({ phase, percent: Math.round(percent), file: file || '' });
      if (file) setCurrentFile(file);
    };
    return () => {
      delete window.updateScanningFile;
      delete window.updateProgress;
    };
  }, []);

  // Poll AI status every 5 seconds
  const pollAiStatus = useCallback(async () => {
    try {
      const raw = await callPython('check_ai_status');
      const obj = typeof raw === 'string' ? JSON.parse(raw) : raw;
      setAiStatus(obj.status || 'offline');
    } catch {
      setAiStatus('offline');
    }
  }, []);

  useEffect(() => {
    // Initial poll after pywebview is ready
    const init = async () => {
      await pollAiStatus();
      pollRef.current = setInterval(pollAiStatus, 5000);
    };

    // Use pywebviewready event if available, else fallback
    if (window.pywebview) {
      init();
    } else {
      window.addEventListener('pywebviewready', init, { once: true });
      // Fallback timeout
      const t = setTimeout(init, 2000);
      return () => {
        clearTimeout(t);
        window.removeEventListener('pywebviewready', init);
        if (pollRef.current) clearInterval(pollRef.current);
      };
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [pollAiStatus]);

  const handleScan = async () => {
    if (!folderPath.trim()) return;
    setLoading(true);
    setError(null);
    setScanResult(null);
    setCurrentFile('');
    setProgress({ phase: 'INIT', percent: 0, file: '' });

    try {
      const raw = await callPython('start_emergency_scan', folderPath.trim());
      const obj = typeof raw === 'string' ? JSON.parse(raw) : raw;

      if (obj.error) {
        setLoading(false);
        setError(obj.error);
        return;
      }
      
      // If started successfully, begin polling
      const pollId = setInterval(async () => {
        try {
          const pRaw = await callPython('get_progress');
          const prog = typeof pRaw === 'string' ? JSON.parse(pRaw) : pRaw;
          if (prog && prog.phase) {
            setProgress({ phase: prog.phase, percent: Math.round(prog.percent || 0), file: prog.file || '' });
            if (prog.file) setCurrentFile(prog.file);

            if (prog.phase === 'COMPLETE' || prog.phase === 'ERROR') {
              clearInterval(pollId);
              setLoading(false);
              
              let resultObj = null;
              if (prog.result) {
                try { resultObj = typeof prog.result === 'string' ? JSON.parse(prog.result) : prog.result; } catch (e) {}
              }
              
              if (prog.phase === 'ERROR' || (resultObj && resultObj.error)) {
                setError(resultObj ? resultObj.error : "Unknown error occurred.");
              } else if (resultObj) {
                setScanResult(resultObj);
              }
            }
          }
        } catch (_) {}
      }, 600);

    } catch (err) {
      setError(`System error: ${err.message}`);
      setLoading(false);
    }
  };

  const handleUnifiedScan = async (config) => {
    setLoading(true);
    setError(null);
    setScanResult(null);
    setCurrentFile('');
    setProgress({ phase: 'INIT', percent: 0, file: '' });

    try {
      const raw = await callPython('run_unified_scan', JSON.stringify(config));
      const obj = typeof raw === 'string' ? JSON.parse(raw) : raw;

      if (obj.error) {
        setLoading(false);
        setError(obj.error);
        return;
      }

      const pollId = setInterval(async () => {
        try {
          const pRaw = await callPython('get_progress');
          const prog = typeof pRaw === 'string' ? JSON.parse(pRaw) : pRaw;
          if (prog && prog.phase) {
            setProgress({ phase: prog.phase, percent: Math.round(prog.percent || 0), file: prog.file || '' });
            if (prog.file) setCurrentFile(prog.file);

            if (prog.phase === 'COMPLETE' || prog.phase === 'ERROR') {
              clearInterval(pollId);
              setLoading(false);
              
              let resultObj = null;
              if (prog.result) {
                try { resultObj = typeof prog.result === 'string' ? JSON.parse(prog.result) : prog.result; } catch (e) {}
              }
              
              if (prog.phase === 'ERROR' || (resultObj && resultObj.error)) {
                setError(resultObj ? resultObj.error : "Unknown error occurred.");
              } else if (resultObj) {
                setScanResult(resultObj);
              }
            }
          }
        } catch (_) {}
      }, 600);

    } catch (err) {
      setError(`Unified scan error: ${err.message}`);
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleScan();
  };

  const hasResult = scanResult && !scanResult.error;
  const risk = hasResult ? (RISK[scanResult.risk_level] || RISK.LOW) : null;

  return (
    <div className="min-h-screen bg-slate-950 cyber-grid flex flex-col">
      <Header aiStatus={aiStatus} />

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8 space-y-6">
        {/* Scan Control */}
        <div onKeyDown={handleKeyDown}>
          <ScanControl
            folderPath={folderPath}
            setFolderPath={setFolderPath}
            onScan={handleScan}
            onUnifiedScan={handleUnifiedScan}
            loading={loading}
            aiStatus={aiStatus}
          />
        </div>

        {/* Loading */}
        {loading && <LoadingState phase={progress.phase} percent={progress.percent} currentFile={progress.file || currentFile} />}

        {/* Error */}
        {error && !loading && <ErrorCard message={error} />}

        {/* Results */}
        {hasResult && !loading && (
          <div className="space-y-6">
            {/* Risk Badge row */}
            <div className="flex items-center justify-between flex-wrap gap-4 animate-fade-in-up">
              <RiskBadge level={scanResult.risk_level} />
              <div className="flex items-center gap-4 text-xs font-mono text-slate-500">
                <span>🕐 {new Date(scanResult.scan_timestamp).toLocaleString('en-US')}</span>
              </div>
            </div>

            {/* Scan coverage stats */}
            <ScanStatsCard
              totalFiles={scanResult.total_files_scanned}
              totalFolders={scanResult.total_folders_scanned}
              totalSuspicious={scanResult.total_suspicious}
            />

            {/* USB Report saved path */}
            {scanResult.report_file_path && (
              <ReportSavedCard filePath={scanResult.report_file_path} />
            )}

            {/* Two-column grid on wide screens */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
              <div className="xl:col-span-2 space-y-6">
                <SummaryCard summary={scanResult.summary} riskLevel={scanResult.risk_level} />
                <Timeline items={scanResult.timeline} />
              </div>
              <div className="space-y-6">
                <RecommendationCard text={scanResult.recommendation} />
                <FileTable files={scanResult.scanned_files} />
              </div>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && !hasResult && (
          <div className="flex flex-col items-center justify-center py-20 text-center space-y-4 animate-fade-in-up">
            <div className="w-20 h-20 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center">
              <span className="text-4xl">🛡️</span>
            </div>
            <h2 className="text-lg font-bold text-slate-400">Ready to Scan</h2>
            <p className="text-sm text-slate-600 max-w-md">
              Enter the path to a suspect directory and click "Start Emergency Scan" to activate the local triage engine.
            </p>
            <div className="flex items-center gap-6 pt-4 text-xs text-slate-700 font-mono">
              <span>✦ No Internet Required</span>
              <span>✦ Local AI Only</span>
              <span>✦ English Output</span>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-4 px-6 flex items-center justify-between text-xs text-slate-700 font-mono">
        <span>SOC Emergency AI Scanner v1.0 — Final Project | Certified SOC Analyst Course</span>
        <span>OFFLINE MODE • {new Date().getFullYear()}</span>
      </footer>
    </div>
  );
}
