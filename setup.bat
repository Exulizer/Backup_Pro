@echo off
setlocal
cd /d "%~dp0"

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
echo [INFO] Erstelle isolierte Umgebung (.venv)...
"%PY_CMD%" -m venv .venv
if %errorlevel% neq 0 (
    echo [ERROR] Konnte .venv nicht erstellen.
    pause
    exit /b 1
)
set "PY_CMD=.venv\Scripts\python.exe"

REM --- 3. Abhängigkeiten installieren ---
:CHECK_DEPS
echo [INFO] Installiere/Pruefe Pakete in .venv...
"%PY_CMD%" -m pip install --upgrade pip >nul 2>&1
"%PY_CMD%" -m pip install flask pyzipper paramiko pywin32 winshell >nul 2>&1

if %errorlevel% neq 0 (
    echo [WARN] Fehler bei der Paket-Installation.
    echo Versuche trotzdem fortzufahren...
) else (
    echo [OK] Umgebung bereit.
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
