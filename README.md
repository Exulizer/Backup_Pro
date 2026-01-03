# 🛡️ Backup OS Pro - Commander Edition

**Backup OS Pro** ist ein hochmodernes, hybrides Backup-System für **Windows 10/11**, das professionelle Datensicherheit mit einer intuitiven **Weboberfläche** verbindet.

Es wurde entwickelt, um Projekte und wichtige Verzeichnisse nicht nur zu archivieren, sondern **kryptografisch zu sichern**, in die Cloud zu replizieren und bei Bedarf mit einem Klick wiederherzustellen.

---

## **✨ NEUE FEATURES (v7.1+)**

### 🔒 **Military-Grade Security**
- **AES-256 Verschlüsselung:** Alle Backups können optional mit dem AES-256 Standard verschlüsselt werden.
- **Passwortschutz:** Ohne Ihr Passwort sind die Archive für Dritte wertlos.

### ☁️ **Cloud Connect**
- **SFTP Integration:** Laden Sie Ihre verschlüsselten Backups automatisch auf entfernte Server hoch.
- **Offsite-Sicherung:** Schützt Ihre Daten auch bei physischem Verlust des lokalen Rechners.

### ⚡ **High-Performance Core**
- **Asynchrone Engine:** Backups laufen im Hintergrund, ohne die Benutzeroberfläche zu blockieren.
- **Smart Chunking:** Optimierte Verarbeitung großer Dateien für maximale Geschwindigkeit.
- **Auto-Update Launcher:** Das System erkennt automatisch neue Versionen im Ordner und startet immer die aktuellste.

---

## **💎 CLASSIC FEATURES**

- **Snapshot-Engine:** Schnelle ZIP-Komprimierung.
- **Integritäts-Protokoll:** SHA256-Signaturen garantieren unveränderte Daten.
- **One-Click Restore:** Wiederherstellung direkt an den Ursprungsort.
- **Live-Telemetrie:** Echtzeit-Überwachung von I/O und Systemstatus.
- **Retention Policy:** Automatische Löschung alter Backups (Rotation).

---

## **🚀 INSTALLATION (Empfohlen)**

Wir haben die Installation radikal vereinfacht. Sie benötigen **kein Vorwissen** über Python oder Git.

### **1. Schnellstart**
1. Laden Sie die Dateien **`setup.bat`** und **`install_backup_pro.py`** herunter.
2. Starten Sie **`setup.bat`**.
   - *Der Installer prüft automatisch, ob Python installiert ist.*
   - *Er erstellt selbstständig eine isolierte Umgebung (`.venv`).*
3. Im Installer-Fenster:
   - Klicken Sie auf **"Download App"**, um die neueste Version direkt von GitHub zu laden.
   - Klicken Sie auf **"Installation Starten"**.

### **2. Starten**
- Nutzen Sie das neu erstellte **Desktop-Icon "Backup Pro"**.
- Oder starten Sie **`start_backup_pro.bat`**.

---

## **🔄 UPDATES (Sorglos-System)**

Dank des intelligenten Launchers ist das Aktualisieren kinderleicht:

1. Laden Sie einfach die neue Programmdatei (z.B. `backup_app_v7_2.py`) herunter.
2. Legen Sie sie in denselben Ordner wie die alte Version.
3. Starten Sie Backup Pro wie gewohnt.
   - **Der Launcher erkennt automatisch die neuere Version und startet diese.**
   - Keine Neuinstallation nötig!

---

## **🛠️ KONFIGURATION**

Öffnen Sie das Dashboard unter **http://127.0.0.1:5000** (startet automatisch).

### **Verschlüsselung aktivieren**
1. Gehen Sie auf **"Parameter"**.
2. Aktivieren Sie **"AES-256 Verschlüsselung nutzen"**.
3. Setzen Sie ein sicheres **Passwort**.

### **Cloud Backup einrichten**
1. Unter **"Parameter"** -> **"Cloud Upload (SFTP)"**.
2. Tragen Sie Host, Benutzer, Passwort und Zielpfad ein.
3. *Tipp: Nutzen Sie das API-Key Feld als Host-Feld, falls kein separates Feld sichtbar ist (Legacy Mode).*

---

## **📄 LIZENZ**

**MIT-Lizenz** – Free for everyone.
