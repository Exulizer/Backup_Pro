# 🛡️ Backup OS Pro - Commander Edition

**Backup OS Pro** ist ein leistungsstarkes, hybrides Backup-System für **Windows 11**, das eine intuitive **Weboberfläche (Flask)** mit nativen Systemfunktionen kombiniert.  
Es wurde entwickelt, um Web-Projekte und wichtige Verzeichnisse sicher zu archivieren, zu validieren und bei Bedarf mit **einem Klick wiederherzustellen**.

---

## ✨ Features

- **Snapshot-Engine:** Schnelle Komprimierung von Verzeichnissen in ZIP-Archive unter Verwendung nativer Windows-Bibliotheken.  
- **Integritäts-Protokoll:** Jedes Backup erhält eine einzigartige SHA256-Signatur (gesalzen mit Zeitstempeln), um Manipulationen oder Datenkorruption auszuschließen.  
- **One-Click Restore:** Intuitive Wiederherstellung von Daten aus dem Archiv-Register direkt an den Quellort.  
- **Live-Telemetrie:** Überwachung von I/O-Durchsatz und System-Health in Echtzeit über das Dashboard.  
- **Security Score:** Dynamisches Punktesystem, das die Absicherung deines Projekts basierend auf Backup-Frequenz und Integrität bewertet.  
- **Duplikate-Finder:** Identifiziert identische Dateien durch Deep-Scan Inhalts-Signaturen, um Speicherplatz zu sparen.  
- **Retention Policy:** Automatisches Rotations-Management, das alte Sicherungen basierend auf benutzerdefinierten Limits entfernt.  

---

## 🚀 Installation

### Voraussetzungen
- **Windows 11**
- **Python 3.8** oder höher

### Schritt 1: Repository klonen
```bash
git clone https://github.com/Exulizer/Backup_Pro.git
cd Backup_Pro
```
### Schritt 2: Abhängigkeiten installieren

Die Anwendung nutzt Flask für das Backend-Interface.
Zusätzliche Bibliotheken wie tkinter sind in Standard-Python-Installationen für Windows bereits enthalten.
``` 
pip install flask
```
### Schritt 3: Starten

Die Anwendung startet einen lokalen Server.
Öffne anschließend deinen Browser unter:
👉 http://127.0.0.1:5000

### 🛠️ Konfiguration
Über den Reiter „Parameter“ in der Sidebar kannst du das System an deine Bedürfnisse anpassen:

Standard-Pfade: Lege feste Quell- und Zielverzeichnisse fest, die bei jedem Start geladen werden.

Retention Count: Bestimme, wie viele Archiv-Generationen aufbewahrt werden sollen (Standard: 10).

Integrität: Alle Hashes werden im „Backup Register“ gelistet. Ein Klick auf einen Eintrag zeigt die vollständige Signatur inklusive Kopierfunktion an.

### 📄 Lizenz
Dieses Projekt ist unter der MIT-Lizenz lizenziert.
Weitere Details findest du in der LICENSE Datei.
