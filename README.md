
# 🛡️ Backup OS Pro - Commander Edition

**Backup OS Pro** ist ein leistungsstarkes, hybrides Backup-System für **Windows 11**, das eine intuitive **Weboberfläche (Flask)** mit nativen Systemfunktionen kombiniert.  
Es wurde entwickelt, um Web-Projekte und wichtige Verzeichnisse sicher zu archivieren, zu validieren und bei Bedarf mit **einem Klick wiederherzustellen**.

---

## **✨ FEATURES**

- **Snapshot-Engine:** Schnelle Komprimierung von Verzeichnissen in ZIP-Archive unter Verwendung nativer Windows-Bibliotheken.  
- **Integritäts-Protokoll:** Jedes Backup erhält eine einzigartige SHA256-Signatur (gesalzen mit Zeitstempeln), um Manipulationen oder Datenkorruption auszuschließen.  
- **One-Click Restore:** Intuitive Wiederherstellung von Daten aus dem Archiv-Register direkt an den Quellort.  
- **Live-Telemetrie:** Überwachung von I/O-Durchsatz und System-Health in Echtzeit über das Dashboard.  
- **Security Score:** Dynamisches Punktesystem, das die Absicherung deines Projekts basierend auf Backup-Frequenz und Integrität bewertet.  
- **Duplikate-Finder:** Identifiziert identische Dateien durch Deep-Scan Inhalts-Signaturen, um Speicherplatz zu sparen.  
- **Retention Policy:** Automatisches Rotations-Management, das alte Sicherungen basierend auf benutzerdefinierten Limits entfernt.  

---

## **🚀 INSTALLATION**

### **Voraussetzungen**
- **Windows 11**
- **Python 3.8** oder höher

### **Git prüfen/installieren**
```powershell
git --version
```

sollte kein Git installiert sein, fahren sie hier fort:

### Linux/WSL (Ubuntu/Debian) empfohlen:

```bash
sudo apt update && sudo apt install git -y
```

oder

**Git fehlt? Silent-Installation:**
```powershell
$gitUrl = "https://github.com/git-for-windows/git/releases/latest/download/Git-2.48.1-64-bit.exe"
$installer = "$env:TEMP\git-installer.exe"
Invoke-WebRequest $gitUrl -OutFile $installer
Start-Process $installer -ArgumentList '/VERYSILENT','/NORESTART','/SP-' -Wait
Remove-Item $installer
```
### **PyZipper installieren**
```bash
pip install pyzipper paramiko
```

### **Repository laden & starten**
```powershell
git clone https://github.com/Exulizer/Backup_Pro.git
cd Backup_Pro
pip install flask
python backup_app.py
```

**Ohne Git (ZIP):**
```powershell
Invoke-WebRequest "https://github.com/Exulizer/Backup_Pro/archive/refs/heads/main.zip" -OutFile "$env:USERPROFILE\Downloads\Backup_Pro.zip"
Expand-Archive "$env:USERPROFILE\Downloads\Backup_Pro.zip" "$env:USERPROFILE\Downloads"
cd "$env:USERPROFILE\Downloads\Backup_Pro-main"; pip install flask; python backup_app.py
```

### **Browser öffnen**
👉 **http://127.0.0.1:5000**

<p align="center">
  <img src="assets/backup_pro.jpg" alt="Backup Pro Dashboard" width="800"><br>
  <em>🛡️ Backup OS Pro Dashboard</em>
</p>

---

## **🛠️ KONFIGURATION**

### **Parameter-Einstellungen**
Über **„Parameter"** in der Sidebar:

- **Standard-Pfade:** Feste Quell-/Zielverzeichnisse
- **Retention Count:** Generationen (Standard: `10`)
- **Integritäts-Check:** SHA256-Hashes + Kopierfunktion

---

## **📄 LIZENZ**

**MIT-Lizenz** – Siehe [LICENSE](LICENSE)
