@echo off
setlocal
cd /d "%~dp0"

REM --- Helper fuer Progress Bar erstellen ---
echo import sys; > "%~dp0_ui_progress.py"
echo try: >> "%~dp0_ui_progress.py"
echo     p = int(sys.argv[1]); >> "%~dp0_ui_progress.py"
echo     msg = sys.argv[2] if len(sys.argv) ^> 2 else ""; >> "%~dp0_ui_progress.py"
echo     w = 30; >> "%~dp0_ui_progress.py"
echo     f = int(w * p / 100); >> "%~dp0_ui_progress.py"
echo     b = '#' * f + '.' * (w - f); >> "%~dp0_ui_progress.py"
echo     sys.stdout.write(f"\r[{b}] {p}%% - {msg}"); >> "%~dp0_ui_progress.py"
echo     sys.stdout.flush(); >> "%~dp0_ui_progress.py"
echo     if p == 100: print(); >> "%~dp0_ui_progress.py"
echo except: pass >> "%~dp0_ui_progress.py"

echo ---------------------------------------------------------------------
echo                    Backup Pro Installer Starter
echo ---------------------------------------------------------------------
echo.

REM --- 1. Python finden ---
set "PY_CMD="

REM Check: Bereits existierendes venv?
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Lokale Umgebung -venv- gefunden.
    set "PY_CMD=.venv\Scripts\python.exe"
    goto :CHECK_DEPS
)

REM Check: Globales Python?
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python"
    goto :CREATE_VENV
)

REM Check: Python Launcher?
where py >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py"
    goto :CREATE_VENV
)

REM Nichts gefunden
echo [ERROR] Kein Python gefunden!
echo Bitte installieren Sie Python von https://www.python.org/downloads/
echo (Haken bei "Add Python to PATH" nicht vergessen!)
pause
exit /b 1

REM --- 2. Venv erstellen (Self-Bootstrapping) ---
:CREATE_VENV
"%PY_CMD%" _ui_progress.py 0 "Erstelle .venv Umgebung..."
"%PY_CMD%" -m venv .venv
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Konnte .venv nicht erstellen.
    del _ui_progress.py
    pause
    exit /b 1
)
"%PY_CMD%" _ui_progress.py 100 "Umgebung erstellt."
set "PY_CMD=.venv\Scripts\python.exe"

REM --- 3. Abhängigkeiten installieren ---
:CHECK_DEPS
"%PY_CMD%" _ui_progress.py 0 "Starte Installation..."
"%PY_CMD%" -m pip install --upgrade pip >nul 2>&1
"%PY_CMD%" _ui_progress.py 15 "Pip aktualisiert"

"%PY_CMD%" -m pip install flask >nul 2>&1
"%PY_CMD%" _ui_progress.py 30 "Flask installiert"

"%PY_CMD%" -m pip install pyzipper >nul 2>&1
"%PY_CMD%" _ui_progress.py 45 "Pyzipper installiert"

"%PY_CMD%" -m pip install paramiko >nul 2>&1
"%PY_CMD%" _ui_progress.py 60 "Paramiko installiert"

"%PY_CMD%" -m pip install pywin32 >nul 2>&1
"%PY_CMD%" _ui_progress.py 75 "PyWin32 installiert"

"%PY_CMD%" -m pip install winshell >nul 2>&1
"%PY_CMD%" _ui_progress.py 90 "Winshell installiert"

"%PY_CMD%" _ui_progress.py 100 "Alle Pakete bereit."
if exist _ui_progress.py del _ui_progress.py

if %errorlevel% neq 0 (
    echo.
    echo [WARN] Fehler bei der Paket-Installation.
    echo Versuche trotzdem fortzufahren...
) else (
    echo.
    echo [OK] Umgebung vollstaendig eingerichtet.
)

REM --- 4. Installer starten ---
echo.
echo [INFO] Starte GUI-Installer...
start "" /wait "%PY_CMD%" install_backup_pro.py

if %errorlevel% neq 0 (
    echo [ERROR] Fehler beim Starten des Installers.
    pause
)

echo [INFO] Setup beendet.
exit
