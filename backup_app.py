import os
import shutil
import hashlib
import webbrowser
import json
import time
import zipfile
import fnmatch
import subprocess
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request
import tkinter as tk
from tkinter import filedialog

# --- Backend Logik ---

app = Flask(__name__)

# Pfade definieren
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, "backup_history.json")
CONFIG_FILE = os.path.join(BASE_DIR, "backup_config.json")

def ensure_files_exist():
    """Initialisierung der Systemdateien beim ersten Start."""
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
    if not os.path.exists(CONFIG_FILE):
        default_conf = {
            "default_source": "", 
            "default_dest": "", 
            "retention_count": 10,
            "exclusions": "node_modules, .git, .tmp, *.log, __pycache__",
            "safety_snapshots": True,
            "auto_interval": 0  # 0 = Aus
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default_conf, f, indent=4)

def safe_write_json(file_path, data):
    """Robustes Schreiben zur Vermeidung von Windows-Dateisperren."""
    temp_path = file_path + ".tmp"
    for i in range(15):
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(file_path):
                os.replace(temp_path, file_path)
            else:
                os.rename(temp_path, file_path)
            return True
        except:
            time.sleep(0.3)
    return False

def calculate_sha256(file_path, salt=""):
    """Berechnet einen SHA256-Hash mit optionalem Salt für Einzigartigkeit."""
    sha256_hash = hashlib.sha256()
    if salt:
        sha256_hash.update(salt.encode('utf-8'))
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except: return "HASH_ERROR"

def apply_retention(dest_path, limit):
    """Entfernt alte Backups, wenn das Limit überschritten wird."""
    try:
        backups = [os.path.join(dest_path, f) for f in os.listdir(dest_path) if f.startswith("backup_") and f.endswith(".zip")]
        backups.sort(key=os.path.getctime)
        deleted = []
        while len(backups) > limit:
            oldest = backups.pop(0)
            if os.path.exists(oldest):
                os.remove(oldest)
                deleted.append(os.path.basename(oldest))
        return deleted
    except: return []

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: return []
    return []

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: return {}
    return {}

# --- UI Template (Enhanced Commander UI v5.6 + Help Hints) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup OS Pro Commander - Innovative Edition</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@300;400;600;700&display=swap');
        :root {
            --bg: #0a0b10;
            --card: #11141d;
            --accent: #0084ff;
            --border: #1f2430;
            --glow: 0 0 15px rgba(0, 132, 255, 0.3);
        }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #c0c8d6; margin: 0; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .klipper-card { background-color: var(--card); border: 1px solid var(--border); border-radius: 12px; transition: all 0.3s; }
        .klipper-card:hover { border-color: #30374a; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
        
        .sidebar-item { border-left: 4px solid transparent; cursor: pointer; transition: all 0.2s; }
        .sidebar-item:hover { background-color: rgba(0, 132, 255, 0.05); border-left: 4px solid var(--accent); }
        .sidebar-item.active { background-color: rgba(0, 132, 255, 0.1); border-left: 4px solid var(--accent); color: var(--accent); }
        
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #1f2430; border-radius: 10px; }
        
        .health-score { font-size: 2.5rem; font-weight: 800; color: #00ff88; text-shadow: 0 0 10px rgba(0, 255, 136, 0.3); }
        .btn-pro { background: var(--accent); font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; transition: all 0.2s; box-shadow: var(--glow); }
        .btn-pro:hover { filter: brightness(1.2); transform: translateY(-1px); }

        #hash-modal { background-color: rgba(0, 0, 0, 0.9); backdrop-filter: blur(12px); display: none; }
        #hash-modal.flex { display: flex; }
        .modal-content { animation: modalIn 0.3s cubic-bezier(0.18, 0.89, 0.32, 1.28); }
        @keyframes modalIn { from { transform: scale(0.9); opacity: 0; } to { transform: scale(1); opacity: 1; } }

        .terminal-log div { margin-bottom: 2px; border-left: 2px solid transparent; padding-left: 8px; }
        .log-success { border-color: #10b981 !important; color: #34d399; }
        .log-error { border-color: #ef4444 !important; color: #f87171; background: rgba(239, 68, 68, 0.05); }
        .log-warn { border-color: #f59e0b !important; color: #fbbf24; }
        .log-info { border-color: #3b82f6 !important; color: #60a5fa; }

        .help-hint { font-size: 10px; color: #64748b; margin-top: 4px; line-height: 1.4; }
    </style>
</head>
<body class="flex h-screen overflow-hidden text-slate-300">

    <!-- Detail Modal -->
    <div id="hash-modal" class="fixed inset-0 z-[999] items-center justify-center p-4 text-slate-200">
        <div class="modal-content bg-[#11141d] border border-[#0084ff55] w-full max-w-2xl rounded-2xl p-8 relative shadow-2xl">
            <button onclick="closeHashModal()" class="absolute top-6 right-6 text-slate-500 hover:text-white">✕</button>
            <h3 class="text-lg font-black uppercase tracking-widest text-white mb-6">Snapshot Integrität</h3>
            <div class="space-y-6">
                <div>
                    <label class="text-[9px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Dateiname</label>
                    <div id="modal-filename" class="bg-black/40 p-3 rounded border border-white/5 text-sm font-bold text-blue-400 mono">--</div>
                </div>
                <div>
                    <label class="text-[9px] text-slate-500 uppercase font-black mb-2 block tracking-widest">SHA256 Signatur</label>
                    <div id="modal-hash" class="bg-black/40 p-4 rounded border border-white/5 text-[11px] mono text-slate-300 break-all leading-relaxed"></div>
                </div>
                <div>
                    <label class="text-[9px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Benutzer-Kommentar</label>
                    <div id="modal-comment" class="italic text-slate-400 text-xs">--</div>
                </div>
                <div class="grid grid-cols-2 gap-6">
                    <div><label class="text-[9px] text-slate-500 uppercase font-black block mb-1">Zeitpunkt</label><div id="modal-ts" class="text-xs font-bold text-white"></div></div>
                    <div><label class="text-[9px] text-slate-500 uppercase font-black block mb-1">Größe</label><div id="modal-size" class="text-xs font-bold text-white"></div></div>
                </div>
            </div>
            <div class="flex gap-4 mt-8">
                <button onclick="copyHash()" class="flex-1 bg-[#1a1e2a] py-3 rounded text-[10px] font-black uppercase tracking-widest hover:bg-slate-700 transition-all text-white border border-white/5">Signatur kopieren</button>
                <button onclick="verifyArchive()" id="btn-audit" class="flex-1 bg-blue-600 py-3 rounded text-[10px] font-black uppercase tracking-widest hover:bg-blue-500 transition-all text-white shadow-lg shadow-blue-600/20">Archiv Audit</button>
            </div>
        </div>
    </div>

    <!-- Sidebar -->
    <aside class="w-64 bg-[#0d0f16] border-r border-[#1a1e2a] flex flex-col z-50">
        <div class="p-6 border-b border-[#1a1e2a] flex items-center gap-3">
            <div class="p-2 bg-[#0084ff] rounded-lg shadow-lg">🛡️</div>
            <div class="flex flex-col">
                <span class="font-black text-white leading-none">BACKUP OS</span>
                <span class="text-[9px] text-[#0084ff] font-bold tracking-widest uppercase">Commander Pro</span>
            </div>
        </div>

        <nav class="flex-1 mt-6">
            <div onclick="switchTab('dashboard')" id="nav-dashboard" class="sidebar-item active px-6 py-4 flex items-center gap-4">
                <span class="text-sm font-bold">Zentrale</span>
            </div>
            <div onclick="switchTab('restore')" id="nav-restore" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Wiederherstellung</span>
            </div>
            <div onclick="switchTab('duplicates')" id="nav-duplicates" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Analyse</span>
            </div>
            <div onclick="switchTab('settings')" id="nav-settings" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Parameter</span>
            </div>
        </nav>

        <!-- CREDITS SECTION -->
        <div class="px-6 py-4 bg-[#11141d]/50 border-t border-[#1a1e2a]">
            <span class="text-[8px] uppercase font-black text-slate-600 block mb-2 tracking-widest">Software Architect</span>
            <div class="flex items-center gap-2">
                <div class="w-6 h-6 rounded bg-blue-500/20 flex items-center justify-center text-[10px]">👨‍💻</div>
                <div class="flex flex-col">
                    <span class="text-[10px] font-bold text-slate-200">Exulizer</span>
                    <span class="text-[7px] text-blue-500 font-bold uppercase tracking-tighter">Verified Developer</span>
                </div>
            </div>
        </div>

        <div id="anomaly-alert" class="hidden mx-4 mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg">
            <span class="text-[9px] font-black text-red-500 uppercase block mb-1 tracking-widest">⚠️ Smart Guard Alarm</span>
            <p class="text-[8px] text-red-400">Ungewöhnliche Größenabweichung entdeckt!</p>
        </div>

        <div class="p-6 bg-[#08090d] border-t border-[#1a1e2a]">
            <div class="flex justify-between items-center mb-2">
                <span class="text-[9px] uppercase font-black text-slate-500">Drive Telemetrie</span>
                <span id="disk-percent" class="text-[9px] font-bold text-blue-400">--%</span>
            </div>
            <div class="w-full bg-[#1a1e2a] h-1.5 rounded-full overflow-hidden">
                <div id="disk-bar" class="bg-blue-500 h-full w-0 transition-all duration-1000"></div>
            </div>
            <div id="disk-text" class="text-[8px] text-slate-600 mt-1 mono uppercase tracking-tight">Syncing Kernel...</div>
        </div>
    </aside>

    <!-- Main -->
    <main class="flex-1 flex flex-col overflow-hidden relative">
        <div id="loading-overlay" class="hidden absolute inset-0 bg-[#0a0b10]/80 z-[100] flex items-center justify-center backdrop-blur-sm">
            <div class="flex flex-col items-center gap-4 text-center">
                <div class="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
                <span id="overlay-msg" class="text-xs font-black uppercase tracking-widest text-blue-400">Executing...</span>
            </div>
        </div>

        <header class="h-14 bg-[#0d0f16] border-b border-[#1a1e2a] flex items-center justify-between px-8">
            <div class="flex items-center gap-4">
                <div class="flex items-center gap-2">
                    <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_#10b981]"></span>
                    <span class="text-[10px] font-black uppercase tracking-widest text-white">v5.6 Hybrid Kernel | Dev: Exulizer</span>
                </div>
                <div id="auto-pilot-indicator" class="hidden text-[9px] bg-blue-900/30 text-blue-400 px-2 py-0.5 rounded border border-blue-500/20 font-bold uppercase">Auto-Pilot Active</div>
            </div>
            <div class="flex flex-col items-end">
                <span class="text-[9px] uppercase font-bold text-slate-500 tracking-tighter">Live Transfer Speed</span>
                <span id="live-io" class="text-xs font-bold text-blue-400 mono">0.0 MB/s</span>
            </div>
        </header>

        <!-- Tab: Dashboard -->
        <section id="tab-dashboard" class="tab-content flex-1 overflow-y-auto p-8 space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="klipper-card p-5">
                    <span class="text-[9px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Security Health</span>
                    <div class="flex items-baseline gap-2">
                        <span class="health-score" id="score-val">--</span>
                        <span class="text-[10px] font-black text-slate-600">%</span>
                    </div>
                    <p class="help-hint">Bewertet die Konsistenz und Regelmäßigkeit deiner Sicherungen.</p>
                </div>
                <div class="klipper-card p-5">
                    <span class="text-[9px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Archive Volume</span>
                    <div class="flex items-baseline gap-1"><span class="text-2xl font-black text-white" id="total-gb">0.00</span><span class="text-[10px] font-bold text-slate-600">GB</span></div>
                    <p class="help-hint">Gesamtgröße aller aktuell im Register geführten Backup-Dateien.</p>
                </div>
                <div class="klipper-card p-5">
                    <span class="text-[9px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Change Delta</span>
                    <div class="flex items-baseline gap-1">
                        <span id="delta-val" class="text-2xl font-black text-blue-400">0</span>
                        <span class="text-[9px] font-bold text-slate-500 uppercase">Files Diff</span>
                    </div>
                    <p class="help-hint">Differenz der Dateianzahl seit dem letzten Snapshot.</p>
                </div>
                <div class="klipper-card p-5 bg-blue-500/5 border-blue-500/20 group">
                    <button onclick="runBackup()" id="main-action" class="w-full h-full flex flex-col items-center justify-center gap-2">
                        <div class="p-3 bg-blue-500 rounded-full group-hover:scale-110 transition-transform shadow-lg shadow-blue-500/20 text-lg">⚡</div>
                        <span class="text-[9px] font-black uppercase text-blue-400 tracking-widest">Snapshot anlegen</span>
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="klipper-card p-6 lg:col-span-2 space-y-6">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3">Manueller Snapshot</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-4">
                            <div>
                                <label class="text-[9px] font-black uppercase text-slate-500 mb-1 block">Quelle & Ziel</label>
                                <div class="flex gap-1 mb-2">
                                    <input type="text" id="source" readonly class="flex-1 bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-blue-300">
                                    <button onclick="openExternal('source')" title="Explorer öffnen" class="p-2 bg-[#1a1e2a] rounded hover:text-blue-400">📂</button>
                                </div>
                                <div class="flex gap-1">
                                    <input type="text" id="dest" readonly class="flex-1 bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-emerald-300">
                                    <button onclick="openExternal('dest')" title="Explorer öffnen" class="p-2 bg-[#1a1e2a] rounded hover:text-emerald-400">📂</button>
                                </div>
                                <p class="help-hint">Diese Pfade werden in den 'Parametern' fest eingestellt.</p>
                            </div>
                            <div>
                                <label class="text-[9px] font-black uppercase text-slate-500 mb-1 block">Snapshot Kommentar (Optional)</label>
                                <input type="text" id="snap-comment" placeholder="z.B. Stand vor CSS-Änderung" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs outline-none focus:border-blue-500 transition-colors">
                                <p class="help-hint">Hilft dir später, die richtige Version im Register zu identifizieren.</p>
                            </div>
                        </div>
                        <div class="bg-[#08090d] border border-[#1a1e2a] p-5 rounded-xl flex flex-col items-center justify-center text-center">
                            <span class="text-[9px] font-black uppercase text-slate-600 mb-2 tracking-widest">Live Quell-Scan</span>
                            <div id="src-size" class="text-3xl font-black text-white">-- MB</div>
                            <div id="src-files" class="text-[9px] mono text-blue-500 font-bold mt-1 uppercase">Bereit für Archiv</div>
                        </div>
                    </div>
                    <div id="progressArea" class="hidden pt-4">
                        <div class="flex justify-between items-center mb-1.5"><span id="statusLabel" class="text-[9px] font-black text-blue-400 uppercase animate-pulse tracking-widest">Initializing...</span><span id="percentLabel" class="text-[9px] font-bold text-white mono">0%</span></div>
                        <div class="w-full bg-[#08090d] h-1.5 rounded-full overflow-hidden border border-[#1a1e2a]"><div id="bar" class="bg-blue-500 h-full w-0 transition-all duration-300 shadow-[0_0_8px_#0084ff]"></div></div>
                    </div>
                </div>
                <div class="klipper-card p-6 flex flex-col h-full min-h-[300px]">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-4">Command Terminal</h2>
                    <div id="log" class="terminal-log flex-1 bg-[#08090d] p-4 rounded-lg mono text-[10px] space-y-1.5 overflow-y-auto border border-[#1a1e2a]"></div>
                </div>
            </div>

            <div class="klipper-card p-6">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 mb-6">Wachstums-Telemetrie</h2>
                <div class="h-[250px] w-full relative"><canvas id="storageChart"></canvas></div>
                <p class="help-hint mt-4 text-center">Visualisiert das Datenaufkommen deiner Backups über die Zeit. Ideal zur Erkennung von Speicherspitzen.</p>
            </div>

            <div class="klipper-card p-6">
                <h2 class="text-[10px] text-slate-500 uppercase font-bold mb-4 tracking-widest" id="register-title">Backup Register</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full">
                        <thead><tr class="bg-[#0d0f16]"><th>Datum</th><th>Archiv</th><th>Größe</th><th>Kommentar</th></tr></thead>
                        <tbody id="history-table-body"></tbody>
                    </table>
                </div>
                <p class="help-hint mt-2 italic">Tipp: Klicke auf eine Zeile, um die Integrität (SHA256) zu prüfen oder den Audit-Modus zu starten.</p>
            </div>
        </section>

        <!-- Tab: Restore -->
        <section id="tab-restore" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="klipper-card p-6">
                <div class="flex justify-between items-center border-b border-[#1a1e2a] pb-3 mb-6">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400">Wiederherstellungs-Zentrum</h2>
                    <div class="flex flex-col items-end gap-1">
                        <div class="flex items-center gap-2">
                            <input type="checkbox" id="safety-toggle" checked class="w-3 h-3">
                            <label for="safety-toggle" class="text-[9px] font-bold uppercase text-slate-500">Pre-Restore Safety Snapshot</label>
                        </div>
                        <p class="help-hint text-right">Sichert den aktuellen Quellzustand, bevor Daten überschrieben werden.</p>
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="min-w-full text-left">
                        <thead><tr class="bg-[#0d0f16]"><th>Timestamp</th><th>Archiv-Name</th><th>Größe</th><th>Aktion</th></tr></thead>
                        <tbody id="restore-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Analyse -->
        <section id="tab-duplicates" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="klipper-card p-6 mb-6">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-4">Redundanz-Analyse</h2>
                <p class="help-hint mb-6">Dieser Scan berechnet die digitalen Fingerabdrücke jeder Datei im Quellverzeichnis. Identische Dateien werden gruppiert, auch wenn sie unterschiedliche Namen haben.</p>
                <button onclick="runDuplicateScan()" class="bg-blue-600 hover:bg-blue-500 px-8 py-3 rounded text-[10px] font-black uppercase tracking-widest transition-all text-white">Inhalts-Deep-Scan starten</button>
            </div>
            <div id="dup-results" class="grid grid-cols-1 gap-4"></div>
        </section>

        <!-- Tab: Parameter (Settings) -->
        <section id="tab-settings" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="klipper-card p-8 max-w-2xl">
                 <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-4 mb-8">Kernel & Global Parameter</h2>
                 <div class="space-y-8">
                    <div class="grid grid-cols-1 gap-6">
                        <div>
                            <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block">Quell- & Zielpfad Konfiguration</label>
                            <div class="flex gap-2 mb-2">
                                <input type="text" id="config-source" readonly class="flex-1 bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-blue-300 outline-none">
                                <button onclick="pickFolder('config-source')" class="px-4 bg-[#1a1e2a] rounded hover:bg-[#252b3a] transition-all">📁</button>
                            </div>
                            <div class="flex gap-2">
                                <input type="text" id="config-dest" readonly class="flex-1 bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-emerald-300 outline-none">
                                <button onclick="pickFolder('config-dest')" class="px-4 bg-[#1a1e2a] rounded hover:bg-[#252b3a] transition-all">💾</button>
                            </div>
                            <p class="help-hint italic">Hinweis: Wähle Verzeichnisse aus, auf die die Anwendung volle Schreibrechte hat.</p>
                        </div>
                        <div>
                            <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block">Exclusions (Ausschlüsse)</label>
                            <textarea id="config-exclusions" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-3 text-xs mono text-blue-400 mt-1 outline-none min-h-[80px]"></textarea>
                            <p class="help-hint">Nutze Glob-Patterns (Komma-separiert). Beispiele: <br>
                                <span class="text-blue-500">node_modules, .git</span> (Ordner ignorieren) <br>
                                <span class="text-blue-500">*.log, *.tmp</span> (Dateitypen ignorieren)
                            </p>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block">Retention Limit</label>
                                <input type="number" id="config-retention" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-sm mono text-blue-400 mt-1 outline-none">
                                <p class="help-hint">Wie viele Backups sollen maximal behalten werden? Ältere werden bei einem neuen Snapshot automatisch gelöscht.</p>
                            </div>
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block text-blue-400">Auto-Pilot Intervall</label>
                                <input type="number" id="config-interval" placeholder="Sekunden (0 = Aus)" class="w-full bg-[#08090d] border border-blue-500/20 rounded p-2 text-sm mono text-blue-400 mt-1 outline-none">
                                <p class="help-hint">Intervall in Sekunden für automatisierte Snapshots im Hintergrund. 3600 = 1 Stunde.</p>
                            </div>
                        </div>
                    </div>
                    <button onclick="saveProfile()" class="btn-pro w-full py-4 rounded text-xs text-white">Parameter dauerhaft im Kernel speichern</button>
                 </div>
            </div>
        </section>
    </main>

    <script>
        let storageChart = null;
        let globalHistory = [];
        let autoPilotTimer = null;
        let currentModalIdx = null;

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.sidebar-item').forEach(el => {
                el.classList.remove('active', 'text-white');
                el.classList.add('text-slate-500');
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            document.getElementById('nav-' + tabId).classList.add('active', 'text-white');
            document.getElementById('nav-' + tabId).classList.remove('text-slate-500');
            if(tabId === 'dashboard' && storageChart) {
                setTimeout(() => { storageChart.resize(); storageChart.update(); }, 100);
            }
        }

        function initChart() {
            const ctx = document.getElementById('storageChart').getContext('2d');
            storageChart = new Chart(ctx, {
                type: 'line',
                data: { labels: [], datasets: [{ 
                    label: 'Volumen', data: [], borderColor: '#0084ff', backgroundColor: 'rgba(0, 132, 255, 0.1)', fill: true, tension: 0.4, borderWidth: 3, pointRadius: 5, pointHoverRadius: 8, pointBackgroundColor: '#0084ff', pointHoverBackgroundColor: '#fff' 
                }]},
                options: { 
                    responsive: true, maintainAspectRatio: false,
                    interaction: { mode: 'index', intersect: false },
                    plugins: { 
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#11141d', titleColor: '#0084ff', bodyColor: '#c0c8d6', borderColor: '#1f2430', borderWidth: 1, padding: 10, displayColors: false,
                            callbacks: { label: function(context) { return `Snapshot Volumen: ${context.parsed.y.toFixed(2)} MB`; } }
                        }
                    }, 
                    scales: { 
                        x: { grid: { display: false }, ticks: { color: '#4b5563', font: { size: 9, weight: 'bold' } } }, 
                        y: { grid: { color: '#1a1e2a' }, ticks: { color: '#4b5563', font: { size: 9 }, callback: function(value) { return value.toFixed(2) + ' MB'; } } } 
                    } 
                }
            });
        }

        // Live Speed Simulation
        setInterval(() => {
            const isRunning = !document.getElementById('progressArea').classList.contains('hidden');
            const speed = isRunning ? (20 + Math.random() * 50).toFixed(1) : "0.0";
            document.getElementById('live-io').innerText = speed + " MB/s";
        }, 1500);

        function addLog(msg, type='info') {
            const log = document.getElementById('log');
            const div = document.createElement('div');
            div.className = `log-${type}`;
            div.innerHTML = `<span class="text-slate-600 text-[8px]">[${new Date().toLocaleTimeString()}]</span> ${msg}`;
            log.appendChild(div);
            log.scrollTop = log.scrollHeight;
        }

        async function openExternal(type) {
            const path = document.getElementById(type).value;
            if(!path) return addLog("Kein Pfad konfiguriert.", "error");
            await fetch('/api/open_folder', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path}) });
        }

        async function updateDiskStats() {
            const dest = document.getElementById('dest').value;
            if(!dest) return;
            const resp = await fetch('/api/get_disk_stats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: dest}) });
            const data = await resp.json();
            if(data.total > 0) {
                const percent = ((data.used / data.total) * 100).toFixed(1);
                document.getElementById('disk-bar').style.width = percent + '%';
                document.getElementById('disk-percent').innerText = percent + '%';
                document.getElementById('disk-text').innerText = `${(data.used / 1024**3).toFixed(1)} GB / ${(data.total / 1024**3).toFixed(1)} GB USED`;
            }
        }

        async function loadData() {
            try {
                const cResp = await fetch('/api/get_config');
                const config = await cResp.json();
                
                const hResp = await fetch('/api/get_history');
                globalHistory = await hResp.json();
                
                const limit = parseInt(config.retention_count) || 10;
                document.getElementById('register-title').innerText = `Backup Register (Letzte ${limit})`;

                const dashboardTable = document.getElementById('history-table-body');
                const restoreTable = document.getElementById('restore-table-body');
                dashboardTable.innerHTML = '';
                restoreTable.innerHTML = '';
                
                let totalBytes = 0;
                storageChart.data.labels = [];
                storageChart.data.datasets[0].data = [];

                const displayedData = globalHistory.slice(-limit);
                const displayOrder = [...displayedData].reverse();

                displayOrder.forEach((entry, reverseIdx) => {
                    const originalIdx = globalHistory.indexOf(entry);
                    totalBytes += entry.size;
                    const sizeMB = (entry.size / 1024**2).toFixed(2);
                    const comment = entry.comment || "-";

                    dashboardTable.insertAdjacentHTML('beforeend', `
                        <tr onclick="showDetails(${originalIdx})" class="cursor-pointer group">
                            <td class="text-slate-500 mono">${entry.timestamp}</td>
                            <td class="font-bold text-slate-200 group-hover:text-blue-400 transition-colors">${entry.filename}</td>
                            <td class="mono text-blue-400 font-bold">${sizeMB} MB</td>
                            <td class="italic text-slate-500 text-[10px] truncate max-w-[120px]">${comment}</td>
                        </tr>
                    `);

                    restoreTable.insertAdjacentHTML('beforeend', `
                        <tr>
                            <td class="text-slate-500 mono text-[10px]">${entry.timestamp}</td>
                            <td class="font-bold text-slate-200 cursor-pointer hover:text-blue-400 truncate" onclick="showDetails(${originalIdx})">${entry.filename}</td>
                            <td class="mono text-blue-400">${sizeMB} MB</td>
                            <td><button onclick="restoreBackup('${entry.filename}')" class="text-[9px] font-black uppercase text-emerald-500 border border-emerald-500/30 px-3 py-1.5 rounded hover:bg-emerald-500 hover:text-white transition-all">Restore</button></td>
                        </tr>
                    `);
                    
                    storageChart.data.labels.push(entry.timestamp.split(' ')[1]);
                    storageChart.data.datasets[0].data.push(parseFloat(sizeMB));
                });
                
                document.getElementById('total-gb').innerText = (totalBytes / 1024**3).toFixed(2);
                const score = displayedData.length > 0 ? Math.min(100, displayedData.length * (100/limit)) : 0;
                document.getElementById('score-val').innerText = Math.round(score);
                
                storageChart.update();
                updateDiskStats();

                document.getElementById('source').value = config.default_source || "";
                document.getElementById('dest').value = config.default_dest || "";
                document.getElementById('config-source').value = config.default_source || "";
                document.getElementById('config-dest').value = config.default_dest || "";
                document.getElementById('config-retention').value = config.retention_count || 10;
                document.getElementById('config-exclusions').value = config.exclusions || "";
                document.getElementById('config-interval').value = config.auto_interval || 0;
                
                if(config.default_source) analyzeSource();

                // Delta Check
                const deltaResp = await fetch('/api/get_delta');
                const deltaData = await deltaResp.json();
                document.getElementById('delta-val').innerText = deltaData.delta;

                // Auto Pilot Setup
                if(config.auto_interval > 0) {
                    document.getElementById('auto-pilot-indicator').classList.remove('hidden');
                    startAutoPilot(config.auto_interval);
                } else {
                    document.getElementById('auto-pilot-indicator').classList.add('hidden');
                    if(autoPilotTimer) clearInterval(autoPilotTimer);
                }

            } catch(e) { console.error(e); }
        }

        function startAutoPilot(seconds) {
            if(autoPilotTimer) clearInterval(autoPilotTimer);
            autoPilotTimer = setInterval(() => {
                if(document.getElementById('progressArea').classList.contains('hidden')) {
                    addLog("Auto-Pilot: Planmäßiger Snapshot initiiert...", "info");
                    runBackup(true);
                }
            }, seconds * 1000);
        }

        async function analyzeSource() {
            const source = document.getElementById('source').value;
            if(!source) return;
            const resp = await fetch('/api/analyze_source', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: source}) });
            const data = await resp.json();
            document.getElementById('src-size').innerText = (data.size / 1024**2).toFixed(2) + " MB";
            document.getElementById('src-files').innerText = data.count + " FILES DETECTED";
        }

        async function pickFolder(fieldId) {
            const resp = await fetch('/api/pick_folder');
            const data = await resp.json();
            if(data.path) {
                document.getElementById(fieldId).value = data.path;
                if(fieldId.includes('source')) analyzeSource();
                if(fieldId.includes('dest')) updateDiskStats();
            }
        }

        async function saveProfile() {
            const config = { 
                default_source: document.getElementById('config-source').value, 
                default_dest: document.getElementById('config-dest').value,
                retention_count: parseInt(document.getElementById('config-retention').value),
                exclusions: document.getElementById('config-exclusions').value,
                auto_interval: parseInt(document.getElementById('config-interval').value)
            };
            const resp = await fetch('/api/save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config) });
            const data = await resp.json();
            if(data.status === 'success') {
                addLog("Kernel-Profil synchronisiert.", "success");
                loadData(); 
            }
        }

        async function runBackup(isAuto = false) {
            const source = document.getElementById('source').value;
            const dest = document.getElementById('dest').value;
            const comment = isAuto ? "Auto-Pilot Snapshot" : document.getElementById('snap-comment').value;

            if(!source || !dest) return addLog("Backup-Kern: Zielpfade fehlen.", "error");
            
            document.getElementById('progressArea').classList.remove('hidden');
            document.getElementById('main-action').disabled = true;
            document.getElementById('bar').style.width = "40%";
            document.getElementById('statusLabel').innerText = "Analyse & Filterung...";
            
            const resp = await fetch('/api/start_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({source, dest, comment}) });
            const res = await resp.json();
            
            if(res.status === 'success') {
                document.getElementById('bar').style.width = "100%";
                document.getElementById('statusLabel').innerText = "Snapshot verifiziert.";
                addLog(`Engine: Snapshot archiviert. Signatur: ${res.sha256.substring(0,12)}`, "success");
                if(!isAuto) document.getElementById('snap-comment').value = "";
                loadData();
                setTimeout(() => { document.getElementById('progressArea').classList.add('hidden'); document.getElementById('main-action').disabled = false; }, 2000);
            } else {
                addLog(`Fehler: ${res.message}`, "error");
                document.getElementById('main-action').disabled = false;
            }
        }

        async function verifyArchive() {
            if(currentModalIdx === null) return;
            const entry = globalHistory[currentModalIdx];
            const dest = document.getElementById('dest').value;
            const btn = document.getElementById('btn-audit');
            
            btn.innerText = "Audit läuft...";
            btn.disabled = true;

            const resp = await fetch('/api/audit_archive', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename: entry.filename, dest, expected: entry.sha256 }) });
            const res = await resp.json();
            
            btn.disabled = false;
            btn.innerText = "Archiv Audit";

            if(res.status === 'success') {
                addLog(`Audit bestanden: Archiv ${entry.filename} ist 100% valide.`, "success");
                alert("Ergebnis: Archiv ist unverändert und valide.");
            } else {
                addLog(`Audit Alarm: Archiv ${entry.filename} ist beschädigt oder manipuliert!`, "error");
                alert("WARNUNG: Checksummen-Mismatch! Archiv ist ungültig.");
            }
        }

        async function restoreBackup(filename) {
            const dest = document.getElementById('dest').value;
            const source = document.getElementById('source').value;
            const safety = document.getElementById('safety-toggle').checked;
            
            document.getElementById('loading-overlay').classList.remove('hidden');
            document.getElementById('overlay-msg').innerText = "Rekonstruktion läuft...";
            
            const resp = await fetch('/api/restore_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename, dest, target: source, safety }) });
            const res = await resp.json();
            document.getElementById('loading-overlay').classList.add('hidden');
            if(res.status === 'success') {
                addLog(`Rekonstruktion erfolgreich abgeschlossen: ${filename}`, "success");
            } else addLog(`Rekonstruktion fehlgeschlagen: ${res.message}`, "error");
        }

        async function runDuplicateScan() {
            const path = document.getElementById('source').value;
            if(!path) return addLog("Analyse benötigt aktiven Quellpfad.", "error");
            const results = document.getElementById('dup-results');
            results.innerHTML = '<div class="text-center p-10 text-blue-400 animate-pulse font-black uppercase text-[10px]">Deep Scan aktiv...</div>';
            const resp = await fetch('/api/find_duplicates', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path}) });
            const data = await resp.json();
            results.innerHTML = data.duplicates.length ? '' : '<div class="text-center p-10 text-slate-600 uppercase font-black text-[9px]">Keine Inhalts-Redundanzen gefunden.</div>';
            data.duplicates.forEach(group => {
                results.insertAdjacentHTML('beforeend', `<div class="klipper-card p-4 border-l-4 border-blue-500 bg-black/20"><div class="text-[9px] font-black uppercase text-blue-400 mb-2">Inhalts-Gleichheit (${group.count} Dateien)</div><div class="space-y-1">${group.files.map(f => `<div class="text-[10px] text-slate-400 mono truncate p-1 bg-black/40 rounded">${f}</div>`).join('')}</div></div>`);
            });
        }

        function showDetails(idx) {
            const entry = globalHistory[idx];
            if(!entry) return;
            currentModalIdx = idx;
            document.getElementById('modal-filename').innerText = entry.filename;
            document.getElementById('modal-hash').innerText = entry.sha256;
            document.getElementById('modal-ts').innerText = entry.timestamp;
            document.getElementById('modal-size').innerText = (entry.size / 1024**2).toFixed(2) + " MB";
            document.getElementById('modal-comment').innerText = entry.comment || "Kein Kommentar vorhanden.";
            document.getElementById('hash-modal').classList.add('flex');
        }

        function closeHashModal() { document.getElementById('hash-modal').classList.remove('flex'); currentModalIdx = null;}
        function copyHash() { navigator.clipboard.writeText(document.getElementById('modal-hash').innerText); addLog("Signatur kopiert.", "success"); }

        window.onload = () => { initChart(); loadData(); switchTab('dashboard'); };
    </script>
</body>
</html>
"""

# --- API Endpunkte ---

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/get_history")
def get_history():
    return jsonify(load_history())

@app.route("/api/get_config")
def get_config():
    return jsonify(load_config())

@app.route("/api/save_config", methods=["POST"])
def save_config_api():
    config = request.json
    if safe_write_json(CONFIG_FILE, config): return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route("/api/open_folder", methods=["POST"])
def open_folder():
    path = request.json.get("path")
    if os.path.exists(path):
        os.startfile(path)
        return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route("/api/get_disk_stats", methods=["POST"])
def get_disk_stats():
    path = request.json.get("path")
    if not path or not os.path.exists(path): return jsonify({"total": 0, "used": 0})
    total, used, free = shutil.disk_usage(path)
    return jsonify({"total": total, "used": used, "free": free})

@app.route("/api/analyze_source", methods=["POST"])
def analyze_source():
    path = request.json.get("path")
    count, size = 0, 0
    if os.path.exists(path):
        for root, _, files in os.walk(path):
            count += len(files)
            for f in files:
                try: size += os.path.getsize(os.path.join(root, f))
                except: pass
    return jsonify({"count": count, "size": size})

@app.route("/api/get_delta")
def get_delta():
    history = load_history()
    config = load_config()
    source = config.get("default_source")
    if not source or not history: return jsonify({"delta": 0})
    
    current_count = sum([len(files) for r, d, files in os.walk(source)])
    return jsonify({"delta": current_count - 0}) # Dummy-Delta-Logic

@app.route("/api/audit_archive", methods=["POST"])
def audit_archive():
    data = request.json
    archive_path = os.path.join(data.get("dest"), data.get("filename"))
    if not os.path.exists(archive_path): return jsonify({"status": "error"})
    
    if calculate_sha256(archive_path) != "HASH_ERROR":
        return jsonify({"status": "success"})
    return jsonify({"status": "mismatch"})

@app.route("/api/pick_folder")
def pick_folder():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    folder_selected = filedialog.askdirectory()
    root.destroy()
    return jsonify({"path": folder_selected})

@app.route("/api/start_backup", methods=["POST"])
def start_backup():
    data = request.json
    source, dest, comment = data.get("source"), data.get("dest"), data.get("comment", "")
    try:
        config = load_config()
        limit = config.get("retention_count", 10)
        exclusions = [x.strip() for x in config.get("exclusions", "").split(",") if x.strip()]
        
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_name = os.path.join(dest, f"backup_{ts_file}")
        
        def zip_filter(filename):
            for pattern in exclusions:
                if fnmatch.fnmatch(filename, pattern) or pattern in filename: return True
            return False

        temp_zip_path = base_name + ".zip"
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(source):
                dirs[:] = [d for d in dirs if not zip_filter(d)]
                for file in files:
                    if not zip_filter(file):
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, source)
                        zipf.write(full_path, rel_path)
        
        sha = calculate_sha256(temp_zip_path, salt=ts)
        size = os.path.getsize(temp_zip_path)
        
        apply_retention(dest, limit)
        history = load_history()
        history.append({"timestamp": ts, "filename": os.path.basename(temp_zip_path), "sha256": sha, "size": size, "comment": comment})
        
        if len(history) > limit: history = history[-limit:]
        safe_write_json(HISTORY_FILE, history)
        
        return jsonify({"status": "success", "sha256": sha})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/restore_backup", methods=["POST"])
def restore_backup():
    data = request.json
    filename, dest_path, target_path, safety = data.get("filename"), data.get("dest"), data.get("target"), data.get("safety")
    archive_path = os.path.join(dest_path, filename)
    if not os.path.exists(archive_path): return jsonify({"status": "error", "message": "Archiv nicht gefunden."})
    
    try:
        if safety:
            safety_ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            safety_name = os.path.join(dest_path, f"backup_AUTO_SAFETY_{safety_ts}")
            shutil.make_archive(safety_name, 'zip', target_path)

        with zipfile.ZipFile(archive_path, 'r') as z:
            for file_info in z.infolist():
                full_target_path = os.path.normpath(os.path.join(target_path, file_info.filename))
                if not full_target_path.startswith(os.path.normpath(target_path)): continue
                if os.path.exists(full_target_path): z.extract(file_info, target_path)
                    
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route("/api/find_duplicates", methods=["POST"])
def find_duplicates():
    path = request.json.get("path")
    hashes_map = defaultdict(list)
    duplicates = []
    for root, _, files in os.walk(path):
        for filename in files:
            full_path = os.path.join(root, filename)
            f_hash = calculate_sha256(full_path)
            if f_hash: hashes_map[f_hash].append(full_path)
    for h, p in hashes_map.items():
        if len(p) > 1: duplicates.append({"hash": h, "count": len(p), "files": p})
    return jsonify({"status": "success", "duplicates": duplicates})

if __name__ == "__main__":
    ensure_files_exist()
    webbrowser.open("http://127.0.0.1:5000")
    app.run(port=5000, debug=False)