import os
import shutil
import hashlib
import webbrowser
import json
import time
import zipfile
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
    """Initialisierung der Systemdateien."""
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
    if not os.path.exists(CONFIG_FILE):
        default_conf = {
            "default_source": "", 
            "default_dest": "", 
            "retention_count": 10, 
            "auto_verify": True
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default_conf, f, indent=4)

def safe_write_json(file_path, data):
    """Atomares Schreiben zur Vermeidung von Windows Permission Fehlern."""
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
    """Berechnet einen SHA256-Hash. Der 'salt' sorgt für Einzigartigkeit pro Sitzung."""
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
    try:
        backups = [os.path.join(dest_path, f) for f in os.listdir(dest_path) if f.startswith("backup_") and f.endswith(".zip")]
        backups.sort(key=os.path.getctime)
        deleted = []
        while len(backups) > limit:
            oldest = backups.pop(0)
            os.remove(oldest)
            deleted.append(os.path.basename(oldest))
        return deleted
    except: return []

# --- UI Template (Pro Commander Style) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup OS Pro Commander</title>
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
        .klipper-card { background-color: var(--card); border: 1px solid var(--border); border-radius: 12px; transition: border 0.3s; }
        .klipper-card:hover { border-color: #30374a; }
        
        .sidebar-item { border-left: 4px solid transparent; cursor: pointer; transition: all 0.2s; }
        .sidebar-item:hover { background-color: rgba(0, 132, 255, 0.05); border-left: 4px solid var(--accent); }
        .sidebar-item.active { background-color: rgba(0, 132, 255, 0.1); border-left: 4px solid var(--accent); color: var(--accent); box-shadow: var(--glow); }
        
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #1f2430; border-radius: 10px; }
        .hidden { display: none !important; }
        
        .btn-pro { background: var(--accent); font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; transition: all 0.2s; box-shadow: var(--glow); }
        .btn-pro:hover { filter: brightness(1.1); transform: translateY(-1px); }
        
        table { width: 100%; border-spacing: 0; border-collapse: separate; }
        th { text-align: left; font-size: 10px; text-transform: uppercase; color: #4b5563; padding: 12px; border-bottom: 1px solid var(--border); }
        td { padding: 12px; font-size: 12px; border-bottom: 1px solid #1a1e2a; transition: background 0.2s; }
        tr.cursor-pointer:hover td { background: rgba(0, 132, 255, 0.05); }
        
        .health-score { font-size: 2rem; font-weight: 800; color: #00ff88; text-shadow: 0 0 10px rgba(0, 255, 136, 0.4); }

        /* Modal Styles */
        #hash-modal {
            background-color: rgba(0, 0, 0, 0.9);
            backdrop-filter: blur(12px);
            transition: opacity 0.3s ease;
            display: none; /* Initial hidden */
        }
        #hash-modal.flex { display: flex; }
        .modal-content {
            background-color: #11141d;
            border: 1px solid #0084ff55;
            box-shadow: 0 0 50px rgba(0, 132, 255, 0.15);
            animation: modalSlide 0.25s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        @keyframes modalSlide { from { transform: scale(0.9); opacity: 0; } to { transform: scale(1); opacity: 1; } }
    </style>
</head>
<body class="flex h-screen overflow-hidden">

    <!-- Detail Modal -->
    <div id="hash-modal" class="fixed inset-0 z-[999] items-center justify-center p-4">
        <div class="modal-content w-full max-w-2xl rounded-2xl p-8 relative">
            <button onclick="closeHashModal()" class="absolute top-6 right-6 text-slate-500 hover:text-white transition-colors">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
            <div class="flex items-center gap-4 mb-8">
                <div class="p-3 bg-blue-500/20 rounded-xl text-blue-400 border border-blue-500/30">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <div>
                    <h3 class="text-lg font-black uppercase tracking-widest text-white">Integritäts-Protokoll</h3>
                    <p class="text-[10px] text-slate-500 font-bold uppercase tracking-tighter">Verifizierte Snapshot-Signatur</p>
                </div>
            </div>
            
            <div class="space-y-6">
                <div>
                    <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Dateiname (ZIP-Archiv)</label>
                    <div id="modal-filename" class="bg-[#08090d] p-3 rounded-lg border border-[#1a1e2a] text-sm font-bold text-blue-400 mono">--</div>
                </div>
                <div>
                    <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Digitaler Fingerabdruck (SHA256)</label>
                    <div class="relative group">
                        <div id="modal-hash" class="bg-[#08090d] p-5 rounded-lg border border-[#1a1e2a] text-[11px] mono text-slate-300 break-all leading-relaxed shadow-inner">--</div>
                        <button onclick="copyHashToClipboard()" class="absolute top-3 right-3 p-2 bg-[#1a1e2a] rounded-md text-slate-500 hover:text-blue-400 hover:border-blue-500/50 border border-transparent transition-all">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                        </button>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-6">
                    <div>
                        <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block">Zeitstempel</label>
                        <div id="modal-timestamp" class="text-xs font-bold text-white mono">--</div>
                    </div>
                    <div>
                        <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block">Archiv-Größe</label>
                        <div id="modal-size" class="text-xs font-bold text-white mono">--</div>
                    </div>
                </div>
            </div>
            
            <div class="mt-10 pt-6 border-t border-[#1a1e2a] flex justify-between items-center">
                <span id="copy-status" class="text-[9px] font-black uppercase text-green-500 opacity-0 transition-opacity">Hash kopiert!</span>
                <button onclick="closeHashModal()" class="px-8 py-3 bg-[#1a1e2a] rounded-lg text-xs font-black uppercase text-slate-400 hover:text-white hover:bg-[#252b3a] transition-all">Schließen</button>
            </div>
        </div>
    </div>

    <!-- Sidebar -->
    <aside class="w-64 bg-[#0d0f16] border-r border-[#1a1e2a] flex flex-col shadow-2xl z-50">
        <div class="p-6 border-b border-[#1a1e2a] flex flex-col gap-4">
            <div class="flex items-center gap-3">
                <div class="p-2.5 bg-[#0084ff] rounded-xl shadow-lg shadow-blue-500/20">
                    <svg viewBox="0 0 24 24" class="w-6 h-6 text-white" fill="none" stroke="currentColor" stroke-width="2.5">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                </div>
                <div class="flex flex-col">
                    <span class="font-black text-white leading-none tracking-tighter">BACKUP OS</span>
                    <span class="text-[10px] text-[#0084ff] font-bold tracking-[0.3em]">PRO COMMANDER</span>
                </div>
            </div>
        </div>

        <nav class="flex-1 mt-6">
            <div onclick="switchTab('dashboard')" id="nav-dashboard" class="sidebar-item active px-6 py-4 flex items-center gap-4">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"></path></svg>
                <span class="text-sm font-semibold">Zentrale</span>
            </div>
            <div onclick="switchTab('restore')" id="nav-restore" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"></path></svg>
                <span class="text-sm font-semibold">Wiederherstellung</span>
            </div>
            <div onclick="switchTab('duplicates')" id="nav-duplicates" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2"></path></svg>
                <span class="text-sm font-semibold">Analyse</span>
            </div>
            <div onclick="switchTab('settings')" id="nav-settings" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path></svg>
                <span class="text-sm font-semibold">Parameter</span>
            </div>
        </nav>

        <div class="p-6 bg-[#08090d] mt-auto border-t border-[#1a1e2a]">
            <div class="flex justify-between items-center mb-2">
                <span class="text-[10px] uppercase font-black text-slate-500">System Health</span>
                <span id="health-percent" class="text-[10px] font-bold text-[#00ff88]">--</span>
            </div>
            <div class="w-full bg-[#1a1e2a] h-1.5 rounded-full overflow-hidden">
                <div id="health-bar" class="bg-[#00ff88] h-full w-0 transition-all duration-1000"></div>
            </div>
        </div>
    </aside>

    <!-- Main -->
    <main class="flex-1 flex flex-col overflow-hidden relative">
        <div id="loading-overlay" class="hidden absolute inset-0 bg-[#0a0b10]/80 z-[100] flex items-center justify-center backdrop-blur-sm">
            <div class="flex flex-col items-center gap-4">
                <div class="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
                <span id="overlay-msg" class="text-xs font-bold uppercase tracking-widest text-blue-400">Processing...</span>
            </div>
        </div>

        <header class="h-14 bg-[#0d0f16] border-b border-[#1a1e2a] flex items-center justify-between px-8">
            <div class="flex items-center gap-2">
                <span class="w-2 h-2 bg-blue-500 rounded-full animate-pulse shadow-[0_0_8px_#0084ff]"></span>
                <span class="text-[10px] font-black uppercase tracking-[0.2em] text-white">Kernel v5.1 Active</span>
            </div>
            <div class="flex flex-col items-end">
                <span class="text-[9px] uppercase font-bold text-slate-500">I/O Telemetrie</span>
                <span id="live-io" class="text-xs font-bold text-blue-400 mono">0.0 MB/s</span>
            </div>
        </header>

        <!-- Tab: Dashboard -->
        <section id="tab-dashboard" class="tab-content flex-1 overflow-y-auto p-8 space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="klipper-card p-5">
                    <span class="text-[10px] uppercase font-black text-slate-500 mb-2 block">Security Score</span>
                    <span class="health-score" id="score-val">--</span>
                </div>
                <div class="klipper-card p-5">
                    <span class="text-[10px] uppercase font-black text-slate-500 mb-2 block">Gesamtvolumen</span>
                    <div class="flex items-baseline gap-1"><span class="text-2xl font-black text-white" id="total-gb">0.00</span><span class="text-[10px] font-bold text-slate-600">GB</span></div>
                </div>
                <div class="klipper-card p-5">
                    <span class="text-[10px] uppercase font-black text-slate-500 mb-2 block">Snapshots Heute</span>
                    <span class="text-2xl font-black text-blue-500" id="today-count">0</span>
                </div>
                <div class="klipper-card p-5 bg-blue-500/5 border-blue-500/20">
                    <button onclick="runBackup()" id="main-action" class="w-full h-full flex flex-col items-center justify-center gap-2 group">
                        <div class="p-3 bg-blue-500 rounded-full group-hover:scale-110 transition-transform"><svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M12 4v16m8-8H4"></path></svg></div>
                        <span class="text-[9px] font-black uppercase text-blue-400">Snapshot anlegen</span>
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="klipper-card p-6 lg:col-span-2 space-y-6">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-6">Backup Leitstand</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-4">
                            <div>
                                <label class="text-[9px] font-black uppercase text-slate-500 mb-1 block">Source Path</label>
                                <div class="flex bg-[#08090d] border border-[#1a1e2a] rounded-lg p-1">
                                    <input type="text" id="source" readonly class="flex-1 bg-transparent px-3 py-2 text-xs mono text-blue-300 outline-none">
                                    <button onclick="pickFolder('source')" class="px-3 text-slate-400 hover:text-white transition-colors">📁</button>
                                </div>
                            </div>
                            <div>
                                <label class="text-[9px] font-black uppercase text-slate-500 mb-1 block">Target Path</label>
                                <div class="flex bg-[#08090d] border border-[#1a1e2a] rounded-lg p-1">
                                    <input type="text" id="dest" readonly class="flex-1 bg-transparent px-3 py-2 text-xs mono text-emerald-300 outline-none">
                                    <button onclick="pickFolder('dest')" class="px-3 text-slate-400 hover:text-white transition-colors">💾</button>
                                </div>
                            </div>
                        </div>
                        <div class="bg-[#08090d] border border-[#1a1e2a] p-5 rounded-xl flex flex-col items-center justify-center text-center">
                            <span class="text-[9px] font-black uppercase text-slate-600 mb-2 tracking-widest">Inhalts-Analyse</span>
                            <div id="src-size" class="text-2xl font-black text-white">--</div>
                            <div id="src-files" class="text-[9px] mono text-blue-500 font-bold mt-1">Standby</div>
                        </div>
                    </div>
                    <div id="progressArea" class="hidden pt-4">
                        <div class="flex justify-between items-center mb-1"><span class="text-[9px] font-black text-blue-400 uppercase animate-pulse">Engine Active</span><span id="percentLabel" class="text-[9px] font-bold text-white mono">0%</span></div>
                        <div class="w-full bg-[#08090d] h-1.5 rounded-full overflow-hidden border border-[#1a1e2a]"><div id="bar" class="bg-blue-500 h-full w-0 transition-all duration-300"></div></div>
                    </div>
                </div>
                <div class="klipper-card p-6 flex flex-col h-full min-h-[300px]">
                    <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-4">Command Log</h2>
                    <div id="log" class="flex-1 bg-[#08090d] p-4 rounded-lg mono text-[10px] space-y-1 overflow-y-auto border border-[#1a1e2a]"></div>
                </div>
            </div>

            <div class="klipper-card p-6">
                <h2 class="text-[10px] text-slate-500 uppercase font-bold mb-4 tracking-widest">Backup Register (Klick für Details)</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full">
                        <thead>
                            <tr class="bg-[#0d0f16]">
                                <th>Timestamp</th>
                                <th>Datei</th>
                                <th>Größe</th>
                                <th>SHA256 Signatur</th>
                            </tr>
                        </thead>
                        <tbody id="history-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Restore -->
        <section id="tab-restore" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="klipper-card p-6">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-6">Wiederherstellungs-Management</h2>
                <table class="min-w-full">
                    <thead><tr class="bg-[#0d0f16]"><th>Timestamp</th><th>Filename</th><th>Size</th><th>Actions</th></tr></thead>
                    <tbody id="restore-table-body"></tbody>
                </table>
            </div>
        </section>

        <!-- Duplicates -->
        <section id="tab-duplicates" class="tab-content hidden p-8 overflow-y-auto">
            <div class="klipper-card p-6 mb-6">
                <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-4">Inhalts-Signatur Scan</h2>
                <button onclick="runDuplicateScan()" class="bg-blue-500 hover:bg-blue-600 px-6 py-2 rounded text-[10px] font-black uppercase transition-colors">Analyse starten</button>
            </div>
            <div id="dup-results" class="grid grid-cols-1 gap-4"></div>
        </section>

        <!-- Settings -->
        <section id="tab-settings" class="tab-content hidden p-8 overflow-y-auto">
            <div class="klipper-card p-6 max-w-2xl space-y-8">
                 <h2 class="text-xs font-black uppercase tracking-widest text-slate-400 border-b border-[#1a1e2a] pb-3 mb-6">Kernel Konfiguration</h2>
                 
                 <div class="space-y-6">
                    <!-- Standard Pfade Konfiguration -->
                    <div class="space-y-4">
                        <h3 class="text-[10px] font-black uppercase text-[#0084ff] tracking-widest">Standard Verzeichnisse</h3>
                        <div>
                            <label class="text-[9px] font-black text-slate-500 uppercase mb-1 block">Fester Quellpfad</label>
                            <div class="flex bg-[#08090d] border border-[#1a1e2a] rounded-lg p-1 group">
                                <input type="text" id="config-source" readonly class="flex-1 bg-transparent px-3 py-2 text-xs mono text-blue-300 outline-none" placeholder="Standard-Quelle definieren...">
                                <button onclick="pickFolder('config-source')" class="px-3 text-slate-400 hover:text-white transition-colors">📁</button>
                            </div>
                        </div>
                        <div>
                            <label class="text-[9px] font-black text-slate-500 uppercase mb-1 block">Fester Zielpfad</label>
                            <div class="flex bg-[#08090d] border border-[#1a1e2a] rounded-lg p-1 group">
                                <input type="text" id="config-dest" readonly class="flex-1 bg-transparent px-3 py-2 text-xs mono text-emerald-300 outline-none" placeholder="Standard-Ziel definieren...">
                                <button onclick="pickFolder('config-dest')" class="px-3 text-slate-400 hover:text-white transition-colors">💾</button>
                            </div>
                        </div>
                    </div>

                    <!-- System Parameter -->
                    <div class="space-y-4">
                        <h3 class="text-[10px] font-black uppercase text-[#0084ff] tracking-widest">System Parameter</h3>
                        <div>
                            <label class="text-[9px] font-black text-slate-500 uppercase mb-1 block">Retention Limit (Rotation)</label>
                            <input type="number" id="config-retention" class="w-full bg-[#08090d] border border-[#1a1e2a] rounded p-2 text-sm mono text-blue-400 mt-1 outline-none focus:border-blue-500/50">
                            <span class="text-[8px] text-slate-600 italic">Anzahl der Backups, die im Zielverzeichnis aufbewahrt werden.</span>
                        </div>
                    </div>

                    <div class="pt-4 border-t border-[#1a1e2a] flex items-center justify-between">
                        <div id="save-status" class="text-[10px] font-black uppercase text-green-500 opacity-0 transition-opacity">Parameter synchronisiert!</div>
                        <button onclick="saveProfile()" class="btn-pro px-10 py-3 rounded text-xs text-white">Profil Speichern</button>
                    </div>
                 </div>
            </div>
        </section>
    </main>

    <script>
        let globalHistory = [];

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.sidebar-item').forEach(el => {
                el.classList.remove('active', 'text-white');
                el.classList.add('text-slate-500');
            });
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            document.getElementById('nav-' + tabId).classList.add('active', 'text-white');
            document.getElementById('nav-' + tabId).classList.remove('text-slate-500');
        }

        // Modal Logic
        function showBackupDetails(index) {
            if (index === undefined || index === null) return;
            const entry = globalHistory[index];
            if(!entry) return;
            
            const sizeStr = (entry.size / 1024**2).toFixed(2) + " MB";
            document.getElementById('modal-filename').innerText = entry.filename;
            document.getElementById('modal-hash').innerText = entry.sha256;
            document.getElementById('modal-timestamp').innerText = entry.timestamp;
            document.getElementById('modal-size').innerText = sizeStr;
            
            const modal = document.getElementById('hash-modal');
            modal.classList.add('flex');
            modal.classList.remove('hidden');
        }

        function closeHashModal() {
            const modal = document.getElementById('hash-modal');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
            document.getElementById('copy-status').classList.add('opacity-0');
        }

        function copyHashToClipboard() {
            const hashText = document.getElementById('modal-hash').innerText;
            const temp = document.createElement("textarea");
            temp.value = hashText;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand("copy");
            document.body.removeChild(temp);
            
            const status = document.getElementById('copy-status');
            status.classList.remove('opacity-0');
            setTimeout(() => status.classList.add('opacity-0'), 2000);
            addLog("Hash-Signatur exportiert.", "success");
        }

        function addLog(msg, type='info') {
            const log = document.getElementById('log');
            if(!log) return;
            const div = document.createElement('div');
            const colors = { success: 'text-green-400', error: 'text-red-500', info: 'text-blue-400' };
            div.className = (colors[type] || 'text-slate-400') + ' border-l border-white/5 pl-2';
            div.innerHTML = `<span class="text-slate-600">[${new Date().toLocaleTimeString()}]</span> ${msg}`;
            log.appendChild(div);
            log.scrollTop = log.scrollHeight;
        }

        async function loadData() {
            try {
                const hResp = await fetch('/api/get_history');
                const history = await hResp.json();
                
                globalHistory = Array.isArray(history) ? history : [];

                const dashboardTable = document.getElementById('history-table-body');
                const restoreTable = document.getElementById('restore-table-body');
                
                if(dashboardTable) dashboardTable.innerHTML = '';
                if(restoreTable) restoreTable.innerHTML = '';
                
                let totalBytes = 0;
                let todayCount = 0;
                const todayStr = new Date().toISOString().split('T')[0];

                const displayOrder = [...globalHistory].reverse();

                displayOrder.forEach((entry, reverseIndex) => {
                    const originalIndex = globalHistory.length - 1 - reverseIndex;
                    totalBytes += entry.size;
                    if(entry.timestamp && entry.timestamp.startsWith(todayStr)) todayCount++;
                    const sizeMB = (entry.size / 1024**2).toFixed(2) + " MB";

                    if(dashboardTable) {
                        const row = `
                            <tr onclick="showBackupDetails(${originalIndex})" class="cursor-pointer group">
                                <td class="text-slate-500 mono">${entry.timestamp}</td>
                                <td class="font-bold text-slate-200 group-hover:text-blue-400 transition-colors">${entry.filename}</td>
                                <td class="mono text-blue-400">${sizeMB}</td>
                                <td class="mono text-slate-500 text-[10px] group-hover:text-blue-200">${entry.sha256 ? entry.sha256.substring(0, 16) + '...' : 'N/A'}</td>
                            </tr>
                        `;
                        dashboardTable.insertAdjacentHTML('beforeend', row);
                    }

                    if(restoreTable) {
                        const row = `
                            <tr>
                                <td class="text-slate-500 mono">${entry.timestamp}</td>
                                <td class="font-bold text-slate-200 cursor-pointer hover:text-blue-400" onclick="showBackupDetails(${originalIndex})">${entry.filename}</td>
                                <td class="mono text-blue-400">${sizeMB}</td>
                                <td><button onclick="restoreBackup('${entry.filename}')" class="text-[9px] font-black uppercase text-emerald-500 border border-emerald-500/30 px-3 py-1 hover:bg-emerald-500 hover:text-white transition-all">Restore</button></td>
                            </tr>
                        `;
                        restoreTable.insertAdjacentHTML('beforeend', row);
                    }
                });
                
                const totalGBEl = document.getElementById('total-gb');
                const todayCountEl = document.getElementById('today-count');
                const scoreValEl = document.getElementById('score-val');
                const healthPercentEl = document.getElementById('health-percent');
                const healthBarEl = document.getElementById('health-bar');

                if(totalGBEl) totalGBEl.innerText = (totalBytes / 1024**3).toFixed(2);
                if(todayCountEl) todayCountEl.innerText = todayCount;
                
                const score = globalHistory.length > 0 ? Math.min(100, globalHistory.length * 10) : 0;
                if(scoreValEl) scoreValEl.innerText = score;
                if(healthPercentEl) healthPercentEl.innerText = score + "%";
                if(healthBarEl) healthBarEl.style.width = score + "%";
                
            } catch(e) { console.error(e); }

            const cResp = await fetch('/api/get_config');
            const config = await cResp.json();
            
            // Dashboard
            document.getElementById('source').value = config.default_source || "";
            document.getElementById('dest').value = config.default_dest || "";
            
            // Settings Tab
            document.getElementById('config-source').value = config.default_source || "";
            document.getElementById('config-dest').value = config.default_dest || "";
            document.getElementById('config-retention').value = config.retention_count || 10;
            
            if(config.default_source) analyzeSource();
        }

        async function analyzeSource() {
            const source = document.getElementById('source').value;
            if(!source) return;
            const resp = await fetch('/api/analyze_source', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: source}) });
            const data = await resp.json();
            const sizeEl = document.getElementById('src-size');
            const filesEl = document.getElementById('src-files');
            if(sizeEl) sizeEl.innerText = (data.size / 1024**2).toFixed(2) + " MB";
            if(filesEl) filesEl.innerText = data.count + " Files Detected";
        }

        async function pickFolder(fieldId) {
            const resp = await fetch('/api/pick_folder');
            const data = await resp.json();
            if(data.path) {
                const input = document.getElementById(fieldId);
                if(input) input.value = data.path;
                if(fieldId === 'source' || fieldId === 'config-source') analyzeSource();
            }
        }

        async function runBackup() {
            const source = document.getElementById('source').value;
            const dest = document.getElementById('dest').value;
            if(!source || !dest) return addLog("Pfade sind unvollständig.", "error");

            const progress = document.getElementById('progressArea');
            const mainAction = document.getElementById('main-action');
            const bar = document.getElementById('bar');
            const percentLabel = document.getElementById('percentLabel');

            if(progress) progress.classList.remove('hidden');
            if(mainAction) mainAction.disabled = true;
            if(bar) bar.style.width = "40%";
            addLog("Snapshot-Vorgang eingeleitet...", "info");
            
            try {
                const resp = await fetch('/api/start_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({source, dest}) });
                const res = await resp.json();
                
                if(res.status === 'success') {
                    if(bar) bar.style.width = "100%";
                    if(percentLabel) percentLabel.innerText = "100%";
                    addLog("Snapshot erfolgreich archiviert.", "success");
                    loadData();
                    setTimeout(() => { 
                        if(progress) progress.classList.add('hidden'); 
                        if(mainAction) mainAction.disabled = false;
                        if(bar) bar.style.width = "0%";
                    }, 2000);
                } else {
                    addLog("Fehler: " + res.message, "error");
                    if(mainAction) mainAction.disabled = false;
                }
            } catch(e) {
                addLog("Netzwerkfehler beim Snapshot.", "error");
                if(mainAction) mainAction.disabled = false;
            }
        }

        async function restoreBackup(filename) {
            const dest = document.getElementById('dest').value;
            const source = document.getElementById('source').value;
            const loader = document.getElementById('loading-overlay');
            if(loader) loader.classList.remove('hidden');
            
            try {
                const resp = await fetch('/api/restore_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename, dest, target: source }) });
                const res = await resp.json();
                if(loader) loader.classList.add('hidden');
                if(res.status === 'success') addLog(`Restore abgeschlossen: ${filename}`, "success");
                else addLog("Restore-Vorgang fehlgeschlagen.", "error");
            } catch(e) {
                if(loader) loader.classList.add('hidden');
                addLog("Restore-Vorgang abgebrochen.", "error");
            }
        }

        async function saveProfile() {
            const sourceVal = document.getElementById('config-source').value;
            const destVal = document.getElementById('config-dest').value;
            const retentionVal = document.getElementById('config-retention').value;
            
            const config = { 
                default_source: sourceVal, 
                default_dest: destVal, 
                retention_count: parseInt(retentionVal) || 10 
            };
            
            try {
                const resp = await fetch('/api/save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config) });
                const data = await resp.json();
                if(data.status === 'success') {
                    addLog("Kernel-Profil erfolgreich aktualisiert.", "success");
                    const status = document.getElementById('save-status');
                    status.classList.remove('opacity-0');
                    setTimeout(() => status.classList.add('opacity-0'), 3000);
                    loadData(); // Dashboard Pfade aktualisieren
                }
            } catch(e) {
                addLog("Profil konnte nicht gespeichert werden.", "error");
            }
        }

        async function runDuplicateScan() {
            const path = document.getElementById('source').value;
            if(!path) return addLog("Wähle einen Quellpfad für die Analyse.", "error");
            const results = document.getElementById('dup-results');
            if(results) results.innerHTML = '<div class="text-center p-10 text-blue-400 animate-pulse uppercase font-black text-[10px]">Scanne Redundanzen...</div>';
            
            try {
                const resp = await fetch('/api/find_duplicates', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path}) });
                const data = await resp.json();
                
                if(results) {
                    results.innerHTML = data.duplicates.length ? '' : '<div class="text-center p-10 text-slate-600">Keine Redundanzen gefunden.</div>';
                    data.duplicates.forEach(group => {
                        results.insertAdjacentHTML('beforeend', `
                            <div class="klipper-card p-4 border-l-4 border-blue-500 bg-[#08090d]">
                                <div class="text-[9px] font-black uppercase text-blue-400 mb-2">Duplikat Gruppe (${group.count})</div>
                                <div class="space-y-1">
                                    ${group.files.map(f => `<div class="text-[10px] text-slate-400 mono truncate p-1 bg-black/20 rounded">${f}</div>`).join('')}
                                </div>
                            </div>
                        `);
                    });
                }
            } catch(e) {
                if(results) results.innerHTML = '<div class="text-center p-10 text-red-500 uppercase font-black text-[10px]">Analyse-Fehler.</div>';
            }
        }

        window.onload = loadData;
    </script>
</body>
</html>
"""

# --- Flask Routen ---

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

@app.route("/api/analyze_source", methods=["POST"])
def analyze_source():
    path = request.json.get("path")
    count, size = 0, 0
    if os.path.exists(path):
        for root, dirs, files in os.walk(path):
            count += len(files)
            for f in files:
                try: size += os.path.getsize(os.path.join(root, f))
                except: pass
    return jsonify({"count": count, "size": size})

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
    source, dest = data.get("source"), data.get("dest")
    try:
        config = load_config()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        base_name = os.path.join(dest, f"backup_{ts_file}")
        
        archive = shutil.make_archive(base_name, 'zip', source)
        sha = calculate_sha256(archive, salt=ts)
        size = os.path.getsize(archive)
        
        apply_retention(dest, config.get("retention_count", 10))
        
        history_entry = {"timestamp": ts, "filename": os.path.basename(archive), "sha256": sha, "size": size}
        save_to_history(history_entry)
        return jsonify({"status": "success", "sha256": sha})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/restore_backup", methods=["POST"])
def restore_backup():
    data = request.json
    filename, dest_path, target_path = data.get("filename"), data.get("dest"), data.get("target")
    archive_path = os.path.join(dest_path, filename)
    if not os.path.exists(archive_path): return jsonify({"status": "error", "message": "File not found."})
    try:
        with zipfile.ZipFile(archive_path, 'r') as z: z.extractall(target_path)
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route("/api/find_duplicates", methods=["POST"])
def find_duplicates():
    path = request.json.get("path")
    hashes_map = defaultdict(list)
    duplicates = []
    for root, dirs, files in os.walk(path):
        for filename in files:
            full_path = os.path.join(root, filename)
            f_hash = calculate_sha256(full_path)
            if f_hash: hashes_map[f_hash].append(full_path)
    for h, p in hashes_map.items():
        if len(p) > 1: duplicates.append({"hash": h, "count": len(p), "files": p})
    return jsonify({"status": "success", "duplicates": duplicates})

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: return []
    return []

def save_to_history(entry):
    history = load_history()
    history.append(entry)
    return safe_write_json(HISTORY_FILE, history)

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: return {"default_source": "", "default_dest": "", "retention_count": 10}
    return {"default_source": "", "default_dest": "", "retention_count": 10}

if __name__ == "__main__":
    ensure_files_exist()
    webbrowser.open("http://127.0.0.1:5000")
    app.run(port=5000, debug=False)