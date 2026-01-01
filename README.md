Backup OS Pro - Commander Edition 🛡️

Backup OS Pro ist ein leistungsstarkes, hybrides Backup-System für Windows 11, das eine intuitive Weboberfläche (Flask) mit nativen Systemfunktionen kombiniert. Es wurde entwickelt, um Web-Projekte und wichtige Verzeichnisse sicher zu archivieren, zu validieren und bei Bedarf mit einem Klick wiederherzustellen.

!

✨ Features

Snapshot-Engine: Schnelle Komprimierung von Verzeichnissen in ZIP-Archive.

Integritäts-Protokoll: Jedes Backup erhält eine einzigartige SHA256-Signatur zur Validierung.

One-Click Restore: Einfache Wiederherstellung von Daten aus dem Archiv-Register.

Live-Telemetrie: Überwachung von I/O-Geschwindigkeiten und System-Health in Echtzeit.

Security Score: Ein intelligentes Punktesystem, das zeigt, wie sicher deine Daten aktuell sind.

Duplikate-Finder: Identifiziert redundante Inhalte durch Deep-Scan Inhalts-Signaturen.

Retention Policy: Automatisches Löschen alter Backups basierend auf deinen Einstellungen.

🚀 Installation

Voraussetzungen

Stellen Sie sicher, dass Python 3.8 oder höher auf Ihrem System installiert ist.

Schritt 1: Repository klonen

git clone [https://github.com/Exulizer/Backup_Pro](https://github.com/Exulizer/Backup_Pro)
cd backup-os-pro


Schritt 2: Abhängigkeiten installieren

Die App benötigt Flask für das Interface und pywebview für die Desktop-Ansicht (optional):

pip install flask


Hinweis: tkinter ist in der Regel bei Python-Installationen unter Windows bereits enthalten.

Schritt 3: Starten

python backup_app.py


Die Anwendung öffnet sich automatisch in Ihrem Standardbrowser unter http://127.0.0.1:5000.

🛠️ Konfiguration

Über den Reiter "Parameter" in der Sidebar können Sie:

Feste Quellverzeichnisse (z.B. Ihren Web-Ordner) definieren.

Standard-Zielpfade für Sicherungen festlegen.

Das Limit für die Backup-Rotation (Retention Count) einstellen.

📄 Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Weitere Details finden Sie in der LICENSE Datei.

Entwickelt mit ❤️ für Datensicherheit und Ordnung.
