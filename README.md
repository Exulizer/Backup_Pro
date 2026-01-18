# <img src="https://github.com/Exulizer/Backup_Pro/blob/main/assets/logo/logo.png?raw=true" width="30" height="30" style="vertical-align: bottom;"> Backup OS Pro - Commander Edition

![Version](https://img.shields.io/badge/version-v7.4-blue?style=flat-square) ![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white) ![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-Proprietary-red?style=flat-square)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white) ![Flask](https://img.shields.io/badge/Flask-Backend-000000?style=flat-square&logo=flask&logoColor=white) ![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white) ![Encryption](https://img.shields.io/badge/Encryption-AES--256-success?style=flat-square&logo=guarded-box&logoColor=white)
![GitHub last commit](https://img.shields.io/github/last-commit/Exulizer/Backup_Pro?style=flat-square&color=lightgrey) ![GitHub repo size](https://img.shields.io/github/repo-size/Exulizer/Backup_Pro?style=flat-square) ![GitHub issues](https://img.shields.io/github/issues/Exulizer/Backup_Pro?style=flat-square) ![Localization](https://img.shields.io/badge/Language-DE_%7C_EN-orange?style=flat-square)

<p align="center">
  <img src="https://github.com/Exulizer/Backup_Pro/blob/main/assets/backup_os.jpg?raw=true" width="500" alt="Backup OS Pro Dashboard">
</p>

**Backup OS Pro** ist ein hochmodernes, hybrides Backup-System für **Windows 10/11**, das professionelle Datensicherheit mit einer intuitiven **Weboberfläche** verbindet.

Es wurde entwickelt, um Projekte und wichtige Verzeichnisse nicht nur zu archivieren, sondern **kryptografisch zu sichern**, in die Cloud zu replizieren und bei Bedarf mit einem Klick wiederherzustellen.

---

## **✨ Hauptfunktionen (Highlights)**

### 🛡️ **Maximale Sicherheit**
- **AES-256 Verschlüsselung:** Optionaler Schutz aller Archive mit Industriestandard.
- **Retention Lock:** Sperren Sie wichtige Backups, um sie vor der automatischen Rotation zu schützen.
- **Integritäts-Check:** SHA256-Signaturen und Deep Scans garantieren unveränderte Daten.

### 🌐 **Hybrid Cloud & Konnektivität**
- **SFTP Integration:** Automatischer Upload verschlüsselter Container auf entfernte Server.
- **Offsite-Sicherung:** Schutz bei physischem Hardware-Ausfall.
- **Smart Connection:** Robustes Verbindungshandling auch bei instabilem Internet.

### �️ **Snapshot Inspektor 2.0**
- **Content Preview:** Durchsuchen Sie ZIP-Inhalte direkt im Browser ohne Restore.
- **Metadaten-Editor:** Fügen Sie Kommentare zu Backups hinzu.
- **Smart Sorting & Cleanup:** Verwalten Sie Ihre Backup-Historie effizient.

### 🚀 **Performance & UX**
- **Bilingual (DE/EN):** Vollständig lokalisierte Oberfläche, umschaltbar per Klick.
- **Async Core:** Backups laufen im Hintergrund, die UI bleibt reaktionsschnell.
- **Lazy Loading:** Bis zu 40% schnellerer Start durch optimiertes Ressourcen-Management.

---

## **🚀 Installation & Start**

Wir haben die Installation radikal vereinfacht. Sie benötigen **kein Vorwissen** über Python oder Git.

### **1. Installation**
1. Laden Sie die **`install_backup_pro`** ZIP-Datei herunter und entpacken Sie diese.
2. Starten Sie **`setup.bat`**.
   - *Der Installer prüft Python, erstellt eine isolierte Umgebung (`.venv`) und lädt alle Abhängigkeiten.*
   - Wählen Sie im Installer **"Download App"** und dann **"Installation Starten"**.

### **2. Starten**
- Nutzen Sie das neu erstellte **Desktop-Icon "Backup Pro"**.
- Oder starten Sie manuell die **`start_backup_pro.bat`**.

> **Hinweis:** Das Dashboard öffnet sich automatisch in Ihrem Standard-Browser (Standard: `http://127.0.0.1:5000`).

---

## **🆕 Aktuelles Update (v7.4 Hybrid Kernel)**

Der Fokus dieses Updates lag auf **Internationalisierung** und **Konsistenz**.

- **🌐 Bilinguales Interface:** Vollständige Übersetzung (DE/EN) für Konsole, Scheduler und Logs.
- **🧩 Smarte UI-Elemente:** Sprachabhängige Platzhalter ("Keine Tasks") und Status-Buttons.
- **🔧 Fehlerbehebung:** Konsistente Fehlermeldungen bei SFTP-Verbindungen in der gewählten Sprache.

---

## **🔄 Updates & Wartung**

Das **Sorglos-System** macht Updates kinderleicht:
1. Laden Sie die neue Programmdatei (z.B. `backup_app_v7_5.py`) herunter.
2. Legen Sie sie in den Installationsordner.
3. Starten Sie Backup Pro neu – der **Launcher erkennt automatisch die neueste Version**.

---

## **🛠️ Konfiguration**

### **Verschlüsselung aktivieren**
1. Gehen Sie auf **"Parameter"**.
2. Aktivieren Sie **"AES-256 Verschlüsselung nutzen"** und setzen Sie ein Passwort.

### **Cloud Backup (SFTP)**
1. Unter **"Parameter"** -> **"Cloud Upload (SFTP)"**.
2. Tragen Sie Host, Benutzer, Passwort und Zielpfad ein.

---

<details>
<summary><strong>📜 Änderungshistorie (Ältere Versionen)</strong></summary>

### **v7.3 (Snapshot Inspector)**
- **Deep Scan Engine:** Bit-Integrität per Hash prüfen.
- **Content Preview:** ZIP-Inhalte im Browser ansehen.
- **History Cleanup:** Bereinigung der Datenbank ohne Dateiverlust.

### **v7.2 (Smart Cancel)**
- **Abbruch-Button:** Sicheres Stoppen laufender Backups.
- **Auto-Cleanup:** Entfernt unvollständige Dateien automatisch.
- **Multi-File Support:** Sichern einzelner Dateien aus verschiedenen Orten.

### **v7.1 (Core)**
- **High-Performance Core:** Asynchrone Engine.
- **Smart Chunking:** Optimiert für große Dateien.
- **Auto-Update Launcher:** Startet immer die neuste Version.

</details>

---

## ☕ Support the Project

Gefällt Ihnen **Backup OS Pro**? Helfen Sie mit, die Entwicklung voranzutreiben! Jede Unterstützung fließt direkt in neue Features.

<a href="https://buymeacoffee.com/exulizer" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" >
</a>

---

### License
This project is licensed under a proprietary license. You are free to use it for personal use, but modifications and redistribution are strictly prohibited. See the LICENSE file for the full legal text.

Copyright &copy; 2026 Exulizer
