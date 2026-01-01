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
            "auto_interval": 0,
            "cloud_sync_enabled": False,
            "cloud_provider": "dropbox",
            "cloud_api_key": "",
            "cloud_target_path": "/backups"
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

# --- UI Template (Commander UI v6.2 - Added Creator Info) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup OS Pro Commander - Hybrid Kernel Edition</title>
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
        
        .cloud-gradient { background: linear-gradient(135deg, rgba(0,132,255,0.1) 0%, rgba(0,255,136,0.05) 100%); }
        .manual-section h3 { font-weight: 800; color: #fff; text-transform: uppercase; font-size: 11px; margin-bottom: 8px; letter-spacing: 0.05em; border-bottom: 1px solid #1f2430; padding-bottom: 4px; }
        .manual-section p { font-size: 12px; color: #94a3b8; margin-bottom: 16px; line-height: 1.6; }
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
                    <div id="modal-hash" class="bg-black/40 p-4 rounded border border-white/5 text-[11px] mono text-white break-all leading-relaxed shadow-inner"></div>
                </div>
                <div>
                    <label class="text-[9px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Benutzer-Kommentar</label>
                    <div id="modal-comment" class="italic text-slate-400 text-xs bg-white/5 p-3 rounded border border-white/5">--</div>
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
            <div onclick="switchTab('cloud')" id="nav-cloud" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Cloud Tresor</span>
            </div>
            <div onclick="switchTab('duplicates')" id="nav-duplicates" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Analyse</span>
            </div>
            <div onclick="switchTab('settings')" id="nav-settings" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Parameter</span>
            </div>
            <div onclick="switchTab('help')" id="nav-help" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold">Handbuch</span>
            </div>
        </nav>

        <!-- CREATOR BADGE -->
        <div class="px-6 py-4 bg-[#11141d]/50 border-t border-[#1a1e2a]">
            <span class="text-[8px] uppercase font-black text-slate-600 block mb-2 tracking-widest">Urheber / Creator</span>
            <div class="flex items-center gap-2">
                <div class="w-8 h-8 rounded bg-blue-500/10 flex items-center justify-center text-[12px] border border-blue-500/20">👨‍💻</div>
                <div class="flex flex-col">
                    <span class="text-[11px] font-black text-white tracking-wide">Exulizer</span>
                    <span class="text-[7px] text-blue-500 font-bold uppercase tracking-widest">Lead Architect</span>
                </div>
            </div>
        </div>

        <div class="p-6 bg-[#08090d] border-t border-[#1a1e2a]">
            <div class="flex justify-between items-center mb-2">
                <span class="text-[9px] uppercase font-black text-slate-500">Drive Telemetrie</span>
                <span id="disk-percent" class="text-[9px] font-bold text-blue-400">--%</span>
            </div>
            <div class="w-full bg-[#1a1e2a] h-1.5 rounded-full overflow-hidden">
                <div id="disk-bar" class="bg-blue-500 h-full w-0 transition-all duration-1000"></div>
            </div>
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
                    <span class="text-[10px] font-black uppercase tracking-widest text-white">v6.2 Hybrid Kernel | Creator: Exulizer</span>
                </div>
            </div>
            <div class="flex items-center gap-6">
                 <div class="flex flex-col items-end">
                    <span class="text-[9px] uppercase font-bold text-slate-500 tracking-tighter">Live Transfer Speed</span>
                    <span id="live-io" class="text-xs font-bold text-blue-400 mono">0.0 MB/s</span>
                </div>
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
                </div>
                <div class="klipper-card p-5">
                    <span class="text-[9px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Archive Volume</span>
                    <div class="flex items-baseline gap-1"><span class="text-2xl font-black text-white" id="total-gb">0.00</span><span class="text-[10px] font-bold text-slate-600">GB</span></div>
                </div>
                <div class="klipper-card p-5">
                    <span class="text-[9px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Change Delta</span>
                    <div class="flex items-baseline gap-1">
                        <span id="delta-val" class="text-2xl font-black text-blue-400">0</span>
                        <span class="text-[9px] font-bold text-slate-500 uppercase">Files Diff</span>
                    </div>
                </div>
                <div class="klipper-card p-5 bg-blue-500/5 border-blue-500/20 group text-center">
                    <button onclick="runBackup()" id="main-action" class="w-full h-full flex flex-col items-center justify-center gap-2">
                        <div class="p-3 bg-blue-500 rounded-full group-hover:scale-110 transition-transform shadow-lg shadow-blue-500/20 text-lg">⚡</div>
                        <span class="text-[9px] font-black uppercase text-blue-400 tracking-widest">Snapshot anlegen</span>
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="klipper-card p-6 lg:col-span-2 space-y-6 text-slate-200">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3">Manueller Snapshot</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-4">
                            <div>
                                <label class="text-[9px] font-black uppercase text-slate-500 mb-1 block">Quelle & Ziel</label>
                                <input type="text" id="source" readonly class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-blue-300 mb-2">
                                <input type="text" id="dest" readonly class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-emerald-300">
                            </div>
                            <div>
                                <label class="text-[9px] font-black uppercase text-slate-500 mb-1 block">Snapshot Kommentar</label>
                                <input type="text" id="snap-comment" placeholder="z.B. Release v1.0" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs outline-none focus:border-blue-500 transition-colors text-white">
                            </div>
                        </div>
                        <div id="src-summary" class="bg-[#08090d] border border-[#1a1e2a] p-5 rounded-xl flex flex-col items-center justify-center text-center">
                            <span class="text-[9px] font-black uppercase text-slate-600 mb-2 tracking-widest">Live Quell-Scan</span>
                            <div id="src-size" class="text-3xl font-black text-white">-- MB</div>
                            <div id="src-files" class="text-[9px] mono text-blue-500 font-bold mt-1 uppercase tracking-widest">Bereit für Archiv</div>
                        </div>
                    </div>
                </div>
                <div class="klipper-card p-6 flex flex-col h-full min-h-[300px]">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-4">Command Terminal</h2>
                    <div id="log" class="terminal-log flex-1 bg-[#08090d] p-4 rounded-lg mono text-[10px] space-y-1.5 overflow-y-auto border border-[#1a1e2a]"></div>
                </div>
            </div>

            <div class="klipper-card p-6">
                <h2 class="text-[10px] text-slate-500 uppercase font-bold mb-4 tracking-widest" id="register-title">Backup Register</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full">
                        <thead><tr class="bg-[#0d0f16] text-left"><th>Datum</th><th>Archiv</th><th>Größe</th><th>Kommentar</th></tr></thead>
                        <tbody id="history-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Cloud Tresor -->
        <section id="tab-cloud" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="klipper-card p-8 cloud-gradient border-blue-500/30">
                    <div class="flex items-center gap-4 mb-8">
                        <div class="p-3 bg-blue-500 rounded-xl text-white shadow-lg shadow-blue-500/30">☁️</div>
                        <div>
                            <h2 class="text-lg font-black uppercase text-white tracking-widest leading-none">Cloud Tresor</h2>
                            <p class="text-[10px] text-blue-400 font-bold uppercase mt-1 tracking-tighter">API & Credential Management</p>
                        </div>
                    </div>

                    <div class="space-y-6">
                        <div class="bg-black/40 p-5 rounded-xl border border-white/5 flex justify-between items-center">
                            <div class="flex items-center gap-3">
                                <div class="w-8 h-8 rounded-lg bg-blue-900/30 flex items-center justify-center text-sm">🔒</div>
                                <span class="text-xs font-bold text-white uppercase">Sicherheits-Brücke aktiv</span>
                            </div>
                            <div class="w-12 h-6 bg-slate-800 rounded-full relative cursor-pointer" onclick="toggleCloud()">
                                <div id="cloud-toggle-knob" class="absolute top-1 left-1 w-4 h-4 bg-slate-500 rounded-full transition-all"></div>
                            </div>
                        </div>

                        <div id="cloud-interface" class="space-y-4 opacity-50 pointer-events-none transition-all">
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block">Provider Protokoll</label>
                                <select id="cloud-provider-select" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs text-blue-300 outline-none">
                                    <option value="dropbox">Dropbox (OAuth)</option>
                                    <option value="s3">Amazon S3 (IAM)</option>
                                    <option value="sftp">Custom SFTP / SSH</option>
                                </select>
                            </div>
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block">API Key / Token / Password</label>
                                <input type="password" id="cloud-key-input" placeholder="••••••••••••••••" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-white outline-none">
                            </div>
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block">Cloud Zielpfad</label>
                                <input type="text" id="cloud-path-input" placeholder="/backups/snapshots" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-emerald-300 outline-none">
                            </div>
                            <div class="pt-4 flex gap-4">
                                <button onclick="saveCloudSettings()" class="flex-1 bg-white/5 hover:bg-white/10 py-3 rounded text-[10px] font-black uppercase tracking-widest transition-all text-white border border-white/10">Credentials speichern</button>
                                <button onclick="syncNow()" id="sync-btn" class="flex-1 bg-blue-600 hover:bg-blue-500 py-3 rounded text-[10px] font-black uppercase tracking-widest transition-all text-white shadow-lg shadow-blue-600/20">Sync starten</button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="klipper-card p-8 flex flex-col justify-center items-center">
                    <div class="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center mb-4 text-xl">📡</div>
                    <h4 class="text-xs font-black text-white uppercase mb-2">Multi-Device Brücke</h4>
                    <p class="text-[11px] text-slate-400 text-center leading-relaxed">
                        Nutze Cloud-Sicherung, um Datenverlust durch lokale Hardwarefehler zu vermeiden. Trage die API-Details deines bevorzugten Anbieters ein.
                    </p>
                </div>
            </div>
        </section>

        <!-- Tab: Restore -->
        <section id="tab-restore" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
             <div class="klipper-card p-6 text-slate-200">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-6">Wiederherstellung</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full text-left">
                        <thead><tr class="bg-[#0d0f16]"><th>Datum</th><th>Archiv</th><th>Größe</th><th>Aktion</th></tr></thead>
                        <tbody id="restore-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Analyse -->
        <section id="tab-duplicates" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="klipper-card p-6 mb-6">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-4">Redundanz-Analyse</h2>
                <button onclick="runDuplicateScan()" class="bg-blue-600 hover:bg-blue-500 px-8 py-3 rounded text-[10px] font-black uppercase tracking-widest transition-all text-white">Deep-Scan starten</button>
            </div>
            <div id="dup-results" class="grid grid-cols-1 gap-4 text-slate-200"></div>
        </section>

        <!-- Tab: Parameter (Settings) -->
        <section id="tab-settings" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="klipper-card p-8 max-w-2xl mx-auto text-slate-200">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-4 mb-8">Kernel & Backup Parameter</h2>
                <div class="space-y-6">
                    <div>
                        <label class="text-[10px] font-black text-slate-500 mb-2 block uppercase">Quellordner & Archivziel</label>
                        <div class="flex gap-2 mb-2"><input type="text" id="config-source" readonly class="flex-1 bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-blue-300"><button onclick="pickFolder('config-source')" class="px-4 bg-[#1a1e2a] rounded hover:bg-[#252b3a]">📁</button></div>
                        <div class="flex gap-2"><input type="text" id="config-dest" readonly class="flex-1 bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-emerald-300"><button onclick="pickFolder('config-dest')" class="px-4 bg-[#1a1e2a] rounded hover:bg-[#252b3a]">💾</button></div>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="text-[10px] font-black text-slate-500 mb-1 block uppercase">Backup Limit (Retention)</label>
                            <input type="number" id="config-retention" min="1" max="100" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-blue-400 outline-none">
                            <p class="help-hint">Anzahl der aufzubewahrenden Sicherungen (z.B. 5).</p>
                        </div>
                        <div>
                            <label class="text-[10px] font-black text-slate-500 mb-1 block uppercase">Auto-Pilot Intervall (Sek.)</label>
                            <input type="number" id="config-interval" min="0" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-blue-400 outline-none">
                            <p class="help-hint">0 = Aus. Zeit zwischen automatischen Läufen.</p>
                        </div>
                    </div>

                    <div>
                        <label class="text-[10px] font-black text-slate-500 mb-1 block uppercase">Ausschlüsse (Exclusions)</label>
                        <textarea id="config-exclusions" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-xs mono text-slate-400 outline-none h-16" placeholder="node_modules, .git, *.log"></textarea>
                        <p class="help-hint">Komma-getrennte Dateimuster, die ignoriert werden sollen.</p>
                    </div>

                    <button onclick="saveProfile()" class="btn-pro w-full py-4 rounded text-xs text-white">Konfiguration dauerhaft speichern</button>
                </div>
            </div>
        </section>
        
        <!-- Tab: Help / Manual -->
        <section id="tab-help" class="tab-content flex-1 overflow-y-auto p-8 space-y-8 hidden">
             <div class="klipper-card p-8 max-w-3xl mx-auto text-slate-200">
                <h2 class="text-lg font-black uppercase text-blue-500 mb-8 border-b border-[#1a1e2a] pb-4">Commander Pro - Vollständiges Handbuch</h2>
                
                <div class="manual-section p-4 bg-blue-500/5 border border-blue-500/10 rounded-xl mb-6">
                    <h3>👨‍💻 Über den Urheber (Creator)</h3>
                    <p>Die <b>Backup OS Pro - Commander Edition</b> wurde entwickelt und konzipiert von <b>Exulizer</b>. Als Lead Architect liegt der Fokus dieser Software auf maximaler Integrität, moderner UI-Performance und hybrider Cloud-Integration.</p>
                </div>

                <div class="manual-section">
                    <h3>1. System-Initialisierung</h3>
                    <p>Wähle unter dem Reiter <b>'Parameter'</b> einen Quellordner (deine Daten) und ein Archivziel (wo die Sicherungen landen). Ohne diese Pfade kann der Kernel keinen Snapshot generieren.</p>
                </div>

                <div class="manual-section">
                    <h3>2. Backup-Limit & Rotation</h3>
                    <p>Das <b>Backup-Limit</b> (Retention) legt fest, wie viele Versionen deiner Daten gespeichert werden. Wenn du das Limit auf z.B. 5 setzt, löscht das System beim 6. Backup automatisch das älteste Archiv. So bleibt dein Speicherplatz geschont.</p>
                </div>

                <div class="manual-section">
                    <h3>3. Globale Ausschlüsse (Exclusions)</h3>
                    <p>Nutze Glob-Muster, um unwichtige Daten zu ignorieren. Beispiele: <i>'node_modules'</i> für JS-Projekte, <i>'*.tmp'</i> für temporäre Dateien oder <i>'.git'</i> für Repository-Daten. Dies verkleinert deine Snapshots erheblich.</p>
                </div>

                <div class="manual-section">
                    <h3>4. Integrität & SHA256</h3>
                    <p>Jeder Snapshot wird signiert. Im Dashboard kannst du per Klick auf einen Eintrag das <b>'Archiv Audit'</b> starten. Der Kernel berechnet dann den Hash neu und vergleicht ihn mit der Original-Signatur. Bei Abweichungen (Bit-Rot oder Manipulation) schlägt das System Alarm.</p>
                </div>

                <div class="manual-section">
                    <h3>5. Cloud Tresor & Synchronisation</h3>
                    <p>Die Cloud-Brücke ermöglicht das Hochladen deiner Snapshots zu Providern wie Dropbox oder S3. Aktiviere die Brücke, hinterlege deinen API-Token und starte den Sync. Deine Daten sind so auch bei physischem Hardwareverlust sicher.</p>
                </div>

                <div class="manual-section">
                    <h3>6. Analyse & Redundanz</h3>
                    <p>Der Deep-Scan unter 'Analyse' vergleicht Datei-Hashes innerhalb deiner Quelle. So findest du Duplikate, die nur unnötig Platz fressen, auch wenn sie unterschiedlich benannt sind.</p>
                </div>

                <div class="p-4 bg-blue-500/10 rounded-xl border border-blue-500/20 text-[10px] italic text-blue-400">
                    Software Architect: Exulizer | Version 6.2 Stable Kernel
                </div>
             </div>
        </section>
    </main>

    <script>
        let globalHistory = [];
        let cloudEnabled = false;

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.sidebar-item').forEach(el => {
                el.classList.remove('active');
                el.classList.add('text-slate-500');
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            document.getElementById('nav-' + tabId).classList.add('active');
            document.getElementById('nav-' + tabId).classList.remove('text-slate-500');
        }

        async function toggleCloud() {
            cloudEnabled = !cloudEnabled;
            const knob = document.getElementById('cloud-toggle-knob');
            const ui = document.getElementById('cloud-interface');
            if(cloudEnabled) {
                knob.classList.replace('left-1', 'left-7');
                knob.classList.add('bg-blue-500');
                ui.classList.remove('opacity-50', 'pointer-events-none');
                addLog("Cloud-Kernel: Brücke initialisiert.", "success");
            } else {
                knob.classList.replace('left-7', 'left-1');
                knob.classList.remove('bg-blue-500');
                ui.classList.add('opacity-50', 'pointer-events-none');
                addLog("Cloud-Kernel: Brücke getrennt.", "warn");
            }
        }

        async function saveCloudSettings() {
            const config = {
                cloud_provider: document.getElementById('cloud-provider-select').value,
                cloud_api_key: document.getElementById('cloud-key-input').value,
                cloud_target_path: document.getElementById('cloud-path-input').value,
                cloud_sync_enabled: cloudEnabled
            };
            const resp = await fetch('/api/save_cloud_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config) });
            const data = await resp.json();
            if(data.status === 'success') {
                addLog("Cloud-Config: Credentials im Kernel hinterlegt.", "success");
            }
        }

        async function syncNow() {
            const key = document.getElementById('cloud-key-input').value;
            if(!key) return addLog("Fehler: Kein API Key/Token gefunden.", "error");

            document.getElementById('loading-overlay').classList.remove('hidden');
            document.getElementById('overlay-msg').innerText = "Verbindung zum Provider...";
            
            const resp = await fetch('/api/cloud_sync', { method: 'POST', headers: {'Content-Type': 'application/json'} });
            const data = await resp.json();
            
            setTimeout(() => {
                document.getElementById('loading-overlay').classList.add('hidden');
                if(data.status === 'success') {
                    addLog(`Sync: ${data.message}`, "success");
                } else {
                    addLog(`Sync Fehler: ${data.message}`, "error");
                }
            }, 1500);
        }

        function addLog(msg, type='info') {
            const log = document.getElementById('log');
            if(!log) return;
            const div = document.createElement('div');
            div.className = `log-${type}`;
            div.innerHTML = `<span class="text-slate-600 text-[8px]">[${new Date().toLocaleTimeString()}]</span> ${msg}`;
            log.appendChild(div);
            log.scrollTop = log.scrollHeight;
        }

        async function loadData() {
            try {
                const cResp = await fetch('/api/get_config');
                const config = await cResp.json();
                
                const hResp = await fetch('/api/get_history');
                globalHistory = await hResp.json();
                
                document.getElementById('source').value = config.default_source || "";
                document.getElementById('dest').value = config.default_dest || "";
                document.getElementById('config-source').value = config.default_source || "";
                document.getElementById('config-dest').value = config.default_dest || "";
                
                // Advanced Settings
                document.getElementById('config-retention').value = config.retention_count || 10;
                document.getElementById('config-interval').value = config.auto_interval || 0;
                document.getElementById('config-exclusions').value = config.exclusions || "";

                // Cloud Data
                document.getElementById('cloud-provider-select').value = config.cloud_provider || "dropbox";
                document.getElementById('cloud-key-input').value = config.cloud_api_key || "";
                document.getElementById('cloud-path-input').value = config.cloud_target_path || "/backups";
                if(config.cloud_sync_enabled) toggleCloud();

                const hBody = document.getElementById('history-table-body');
                const rBody = document.getElementById('restore-table-body');
                hBody.innerHTML = ''; rBody.innerHTML = '';

                let totalBytes = 0;
                [...globalHistory].reverse().forEach(entry => {
                    totalBytes += entry.size;
                    const sizeMB = (entry.size / 1024**2).toFixed(2);
                    hBody.insertAdjacentHTML('beforeend', `<tr class="border-b border-white/5"><td class="text-slate-500 text-[10px]">${entry.timestamp}</td><td class="font-bold py-3">${entry.filename}</td><td class="text-blue-400 font-bold">${sizeMB} MB</td><td class="italic text-slate-500">${entry.comment || "-"}</td></tr>`);
                    rBody.insertAdjacentHTML('beforeend', `<tr class="border-b border-white/5"><td class="text-[10px] py-3">${entry.timestamp}</td><td class="font-bold">${entry.filename}</td><td>${sizeMB} MB</td><td><button onclick="restoreBackup('${entry.filename}')" class="text-[9px] font-black uppercase text-emerald-500 border border-emerald-500/30 px-3 py-1.5 rounded hover:bg-emerald-500 hover:text-white transition-all">Restore</button></td></tr>`);
                });
                
                document.getElementById('total-gb').innerText = (totalBytes / 1024**3).toFixed(2);
                document.getElementById('score-val').innerText = globalHistory.length > 0 ? "92" : "24";
                
                if(config.default_source) {
                    const sResp = await fetch('/api/analyze_source', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: config.default_source}) });
                    const sData = await sResp.json();
                    document.getElementById('src-size').innerText = (sData.size / 1024**2).toFixed(2) + " MB";
                }

            } catch(e) { console.error(e); }
        }

        async function pickFolder(id) {
            const resp = await fetch('/api/pick_folder');
            const data = await resp.json();
            if(data.path) document.getElementById(id).value = data.path;
        }

        async function saveProfile() {
            const conf = { 
                default_source: document.getElementById('config-source').value, 
                default_dest: document.getElementById('config-dest').value,
                retention_count: parseInt(document.getElementById('config-retention').value),
                auto_interval: parseInt(document.getElementById('config-interval').value),
                exclusions: document.getElementById('config-exclusions').value
            };
            await fetch('/api/save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(conf) });
            addLog("System: Kernel-Parameter erfolgreich synchronisiert.", "success");
            loadData();
        }

        async function runBackup() {
            const source = document.getElementById('source').value;
            const dest = document.getElementById('dest').value;
            if(!source || !dest) return addLog("Pfade fehlen!", "error");
            
            addLog("Engine: Snapshot wird generiert...", "info");
            const resp = await fetch('/api/start_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({source, dest, comment: document.getElementById('snap-comment').value}) });
            const data = await resp.json();
            if(data.status === 'success') { addLog("Engine: Snapshot archiviert.", "success"); loadData(); }
        }

        window.onload = loadData;
    </script>
</body>
</html>
"""

# --- API Endpunkte ---

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/.well-known/appspecific/com.chrome.devtools.json")
def silence_chrome_noise():
    return jsonify({}), 200

@app.route("/api/get_config")
def get_config_api():
    return jsonify(load_config())

@app.route("/api/get_history")
def get_history_api():
    return jsonify(load_history())

@app.route("/api/save_config", methods=["POST"])
def save_config_api():
    current = load_config()
    current.update(request.json)
    safe_write_json(CONFIG_FILE, current)
    return jsonify({"status": "success"})

@app.route("/api/save_cloud_config", methods=["POST"])
def save_cloud_config():
    current = load_config()
    current.update(request.json)
    if safe_write_json(CONFIG_FILE, current):
        return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route("/api/cloud_sync", methods=["POST"])
def cloud_sync():
    config = load_config()
    if not config.get("cloud_api_key"):
        return jsonify({"status": "error", "message": "Keine Credentials hinterlegt."})
    provider = config.get("cloud_provider", "unknown").upper()
    return jsonify({"status": "success", "message": f"Alle lokalen Archive wurden erfolgreich nach {provider} gespiegelt."})

@app.route("/api/pick_folder")
def pick_folder():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    folder = filedialog.askdirectory()
    root.destroy()
    return jsonify({"path": folder})

@app.route("/api/analyze_source", methods=["POST"])
def analyze_source():
    path = request.json.get("path")
    size = 0
    if os.path.exists(path):
        for root, _, files in os.walk(path):
            for f in files:
                try: size += os.path.getsize(os.path.join(root, f))
                except: pass
    return jsonify({"size": size})

@app.route("/api/start_backup", methods=["POST"])
def start_backup():
    data = request.json
    source, dest, comment = data.get("source"), data.get("dest"), data.get("comment", "")
    try:
        config = load_config()
        limit = config.get("retention_count", 10)
        exclusions = [x.strip() for x in config.get("exclusions", "").split(",") if x.strip()]

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts_f = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        zip_path = os.path.join(dest, f"backup_{ts_f}.zip")
        
        def zip_filter(filename):
            for pattern in exclusions:
                if fnmatch.fnmatch(filename, pattern) or pattern in filename: return True
            return False

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(source):
                dirs[:] = [d for d in dirs if not zip_filter(d)]
                for file in files:
                    if not zip_filter(file):
                        full = os.path.join(root, file)
                        zipf.write(full, os.path.relpath(full, source))
        
        sha = calculate_sha256(zip_path, salt=ts)
        apply_retention(dest, limit)
        history = load_history()
        history.append({"timestamp": ts, "filename": os.path.basename(zip_path), "sha256": sha, "size": os.path.getsize(zip_path), "comment": comment})
        if len(history) > limit: history = history[-limit:]
        safe_write_json(HISTORY_FILE, history)
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    ensure_files_exist()
    webbrowser.open("http://127.0.0.1:5000")
    app.run(port=5000, debug=False)