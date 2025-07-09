# Database Backup Tool - Pterodactyl Egg

Ein automatisiertes Datenbank-Backup-Tool mit Web-Interface für MySQL, PostgreSQL und MongoDB, entwickelt speziell für Pterodactyl Panel mit Auto-Update Funktionalität.

## 🚀 Features

- **Multi-Database Support**: MySQL, PostgreSQL und MongoDB
- **Web-Interface**: Benutzerfreundliche Weboberfläche
- **Automatische Zeitpläne**: Cron-basierte Backup-Automatisierung  
- **Backup-Verwaltung**: Download, Löschen und Verwalten von Backups
- **Komprimierung**: Automatische Backup-Komprimierung
- **Sicherheit**: JWT-basierte Authentifizierung
- **Rate Limiting**: Schutz vor Missbrauch
- **Cleanup**: Automatisches Löschen alter Backups
- **🔄 Auto-Update**: Automatische Updates von GitHub
- **📊 System-Monitoring**: Detaillierte System-Informationen

## 📋 Systemanforderungen

- **Node.js**: Version 18.x oder höher
- **Database Clients**: mysql-client, postgresql-client, mongodb-database-tools
- **Git**: Für Auto-Update Funktionalität
- **RAM**: Mindestens 512MB
- **Storage**: Abhängig von Backup-Größen

## 🛠️ Installation in Pterodactyl

### 1. Repository Setup

1. Fork oder erstelle ein neues Repository auf GitHub
2. Lade alle Dateien in dein Repository hoch
3. Stelle sicher, dass das Repository öffentlich ist oder verwende SSH-Keys

### 2. Egg Import

1. Lade die `dbtool-egg.json` Datei herunter
2. **WICHTIG**: Ersetze in der JSON-Datei:
   - `DEIN-USERNAME` → deinen GitHub Username
   - `db-backup-tool` → deinen Repository Namen
3. Gehe in dein Pterodactyl Admin Panel
4. Navigiere zu `Admin` → `Nests` → `Import Egg`
5. Wähle die angepasste JSON-Datei aus und importiere sie

### 3. Server erstellen

1. Erstelle einen neuen Server mit dem "DB Backup Tool (Auto-Update)" Egg
2. Konfiguriere die Umgebungsvariablen:

#### 🔧 Umgebungsvariablen

| Variable | Beschreibung | Standard | Beispiel |
|----------|-------------|----------|----------|
| **GITHUB_REPOSITORY** | GitHub Repository URL | `https://github.com/DEIN-USERNAME/db-backup-tool.git` | `https://github.com/maxmuster/backup-tool.git` |
| **GITHUB_BRANCH** | Branch für Updates | `main` | `main` oder `master` |
| **AUTO_UPDATE** | Auto-Update aktivieren | `true` | `true` oder `false` |
| **NODE_ENV** | Node.js Umgebung | `production` | `production` |
| **ADMIN_USERNAME** | Admin Benutzername | `admin` | `admin` |
| **ADMIN_PASSWORD** | Admin Passwort | `admin123` | `dein_sicheres_passwort` |
| **SESSION_SECRET** | Session Secret | `change-this...` | 32+ Zeichen String |
| **JWT_SECRET** | JWT Secret | `change-this...` | 32+ Zeichen String |
| **MAX_BACKUPS** | Max. Anzahl Backups | `10` | `10` |
| **ENABLE_COMPRESSION** | Komprimierung | `true` | `true` |

### 4. Server starten

1. Starte den Server über das Pterodactyl Panel
2. Beim ersten Start wird automatisch das Repository geklont
3. Alle Abhängigkeiten werden installiert
4. Server ist bereit wenn "Server läuft auf Port" in den Logs erscheint

## 🔄 Auto-Update System

### Funktionsweise

1. **Beim Start**: Automatische Prüfung auf Updates
2. **Git-Pull**: Neueste Version wird von GitHub geholt
3. **Backup**: Konfiguration und Zeitpläne werden gesichert
4. **Update**: Code wird aktualisiert, Dependencies installiert
5. **Restore**: Konfiguration wird wiederhergestellt

### Update-Methoden

#### 🔄 Automatisch
- Bei jedem Serverstart
- Kann über `AUTO_UPDATE=false` deaktiviert werden

#### 🖱️ Manuell über Web-Interface
1. Anmelden im Web-Interface
2. "System"-Tab öffnen
3. "Manuelles Update" Button klicken

#### 💻 Manuell über SSH
```bash
cd ~/db-backup-tool
./update.sh
```

### System-Informationen

Das Web-Interface zeigt unter dem "System"-Tab:
- **Version**: Aktuelle Tool-Version
- **Git Commit**: Aktueller Git-Commit Hash
- **Node.js Version**: Installierte Node.js Version
- **Uptime**: Server-Laufzeit
- **Auto-Update Status**: Aktiviert/Deaktiviert
- **Repository**: Konfigurierte Repository URL

## 🎯 Verwendung

### 1. Erster Login

1. Öffne die Server-IP mit dem zugewiesenen Port im Browser
2. Melde dich mit deinen konfigurierten Admin-Daten an
3. **WICHTIG**: Ändere das Passwort nach dem ersten Login!

### 2. Backup erstellen

1. Wähle den Tab "Backup erstellen"
2. Fülle die Datenbankverbindungsdetails aus
3. Klicke auf "Backup erstellen"

### 3. Automatische Zeitpläne

1. Wähle den Tab "Zeitplan"
2. Erstelle einen neuen Zeitplan mit Cron-Expression
3. Zeitpläne überleben Server-Neustarts und Updates

### 4. Backup-Verwaltung

1. Wähle den Tab "Backups verwalten"
2. Download, Löschen und Verwalten von Backups
3. Automatisches Cleanup alter Backups

## 🔒 Sicherheit

### Update-Sicherheit

- **Backup**: Automatisches Backup der Konfiguration vor Updates
- **Rollback**: Git-History ermöglicht Rollbacks
- **Validation**: Überprüfung auf gültige Git-Repository

### Authentifizierung

- JWT-basierte Token-Authentifizierung
- Session-Management mit sicheren Cookies
- Rate Limiting zum Schutz vor Brute-Force-Angriffen

### Passwort-Sicherheit

- Passwörter werden mit bcrypt gehasht
- Standardpasswörter sollten sofort geändert werden

## 📁 Dateistruktur

```
/home/container/
├── db-backup-tool/
│   ├── server.js          # Hauptserver-Datei
│   ├── package.json       # Node.js Abhängigkeiten
│   ├── config.json        # Konfigurationsdatei
│   ├── update.sh          # Update-Script
│   ├── backups/           # Backup-Verzeichnis
│   │   └── schedules.json # Gespeicherte Zeitpläne
│   ├── logs/              # Log-Dateien
│   ├── .git/              # Git Repository
│   └── node_modules/      # Node.js Module
```

## 🚀 Entwicklung & Updates

### Lokale Entwicklung

```bash
# Repository klonen
git clone https://github.com/DEIN-USERNAME/db-backup-tool.git
cd db-backup-tool

# Dependencies installieren
npm install

# Development Server starten
npm run dev
```

### Updates veröffentlichen

```bash
# Änderungen committen
git add .
git commit -m "Neue Features hinzugefügt"
git push origin main

# Auf Servern wird automatisch geupdatet beim nächsten Restart
```

### Versioning

- Version in `package.json` erhöhen
- Git Tags für Releases verwenden
- Changelog in Commits dokumentieren

## 🐛 Troubleshooting

### Auto-Update Probleme

**Problem**: Update schlägt fehl
```bash
# Prüfe Git-Status
cd ~/db-backup-tool
git status
git log --oneline -5

# Manuelles Update
./update.sh
```

**Problem**: Repository nicht gefunden
- Prüfe GITHUB_REPOSITORY URL
- Stelle sicher, dass Repository öffentlich ist
- Prüfe Branch-Name (main vs master)

**Problem**: Git-Konflikte
```bash
# Hard reset zum letzten funktionierenden Zustand
git reset --hard origin/main
```

### Backup-Probleme

**Problem**: Backup schlägt fehl
1. Prüfe Datenbankverbindung
2. Prüfe Benutzerrechte
3. Prüfe verfügbaren Speicherplatz

**Problem**: Zeitpläne verschwinden
- Zeitpläne werden in `backups/schedules.json` gespeichert
- Bei Updates automatisch gesichert und wiederhergestellt

## 📞 Support

Bei Problemen:

1. Prüfe die Logs im Pterodactyl Panel
2. Verwende das System-Tab für Diagnose-Informationen
3. Überprüfe GitHub Repository Einstellungen
4. Prüfe Umgebungsvariablen

## ⚠️ Wichtige Hinweise

- **Repository**: Muss öffentlich zugänglich sein
- **Passwörter**: Ändere alle Standard-Passwörter
- **Backup-Sicherheit**: Sichere den Zugang zu Backups
- **Updates**: Teste Updates in einer Entwicklungsumgebung
- **Git-Repository**: Verwende aussagekräftige Commit-Messages

## 📜 Lizenz

MIT License - Verwende das Tool frei für private und kommerzielle Zwecke.