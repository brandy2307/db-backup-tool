# Database Backup Tool - Pterodactyl Egg

Ein automatisiertes Datenbank-Backup-Tool mit Web-Interface für MySQL, PostgreSQL und MongoDB, entwickelt speziell für Pterodactyl Panel mit **fest integriertem offiziellen Update-Repository**.

## 🚀 Features

- **Multi-Database Support**: MySQL, PostgreSQL und MongoDB
- **Web-Interface**: Benutzerfreundliche Weboberfläche
- **Automatische Zeitpläne**: Cron-basierte Backup-Automatisierung  
- **Backup-Verwaltung**: Download, Löschen und Verwalten von Backups
- **Komprimierung**: Automatische Backup-Komprimierung
- **Sicherheit**: JWT-basierte Authentifizierung
- **Rate Limiting**: Schutz vor Missbrauch
- **Cleanup**: Automatisches Löschen alter Backups
- **🔄 Auto-Update**: Automatische Updates vom **offiziellen Repository**
- **📊 System-Monitoring**: Detaillierte System-Informationen
- **🔒 Fest integriert**: Keine manuelle Repository-Konfiguration nötig

## 📋 Systemanforderungen

- **Node.js**: Version 18.x oder höher
- **Database Clients**: mysql-client, postgresql-client, mongodb-database-tools
- **Git**: Für Auto-Update Funktionalität
- **RAM**: Mindestens 512MB
- **Storage**: Abhängig von Backup-Größen

## 🛠️ Installation in Pterodactyl

### 1. Egg Import

1. Lade die `dbtool-egg.json` Datei herunter
2. **Wichtig**: Du musst **keine Repository-URL** mehr konfigurieren - alles ist fest integriert!
3. Gehe in dein Pterodactyl Admin Panel
4. Navigiere zu `Admin` → `Nests` → `Import Egg`
5. Wähle die JSON-Datei aus und importiere sie

### 2. Server erstellen

1. Erstelle einen neuen Server mit dem "DB Backup Tool (Fest integriertes Repository)" Egg
2. Konfiguriere nur noch die **reduzierten** Umgebungsvariablen:

#### 🔧 Umgebungsvariablen (Vereinfacht!)

| Variable | Beschreibung | Standard | Beispiel |
|----------|-------------|----------|----------|
| **AUTO_UPDATE** | Auto-Update aktivieren | `true` | `true` oder `false` |
| **NODE_ENV** | Node.js Umgebung | `production` | `production` |
| **ADMIN_USERNAME** | Admin Benutzername | `admin` | `admin` |
| **ADMIN_PASSWORD** | Admin Passwort | `admin123` | `dein_sicheres_passwort` |
| **SESSION_SECRET** | Session Secret | `change-this...` | 32+ Zeichen String |
| **JWT_SECRET** | JWT Secret | `change-this...` | 32+ Zeichen String |
| **MAX_BACKUPS** | Max. Anzahl Backups | `10` | `10` |
| **ENABLE_COMPRESSION** | Komprimierung | `true` | `true` |

**✅ Nicht mehr nötig:**
- ~~GITHUB_REPOSITORY~~ (fest integriert)
- ~~GITHUB_BRANCH~~ (fest integriert)

### 3. Server starten

1. Starte den Server über das Pterodactyl Panel
2. Beim ersten Start wird automatisch das **offizielle Repository** geklont
3. Alle Abhängigkeiten werden installiert
4. Server ist bereit wenn "Server läuft auf Port" in den Logs erscheint

## 🔄 Auto-Update System

### Was ist neu?

- **Fest integriertes Repository**: Updates kommen automatisch vom offiziellen `https://github.com/brandy2307/db-backup-tool.git`
- **Keine Konfiguration nötig**: Kein manuelles Setzen von Repository-URLs mehr
- **Sicherer**: Nur Updates vom vertrauenswürdigen offiziellen Repository
- **Einfacher**: Weniger Fehlerquellen bei der Installation

### Funktionsweise

1. **Beim Start**: Automatische Prüfung auf Updates vom offiziellen Repository
2. **Git-Pull**: Neueste Version wird vom offiziellen Repository geholt
3. **Backup**: Konfiguration und Zeitpläne werden gesichert
4. **Update**: Code wird aktualisiert, Dependencies installiert
5. **Restore**: Konfiguration wird wiederhergestellt

### Update-Methoden

#### 🔄 Automatisch
- Bei jedem Serverstart
- Kann über `AUTO_UPDATE=false` deaktiviert werden
- Kommt automatisch vom offiziellen Repository

#### 🖱️ Manuell über Web-Interface
1. Anmelden im Web-Interface
2. "System"-Tab öffnen
3. "Manuelles Update" Button klicken
4. Updates werden vom offiziellen Repository geholt

#### 💻 Manuell über SSH
```bash
cd ~/db-backup-tool
./update.sh
```

### System-Informationen

Das Web-Interface zeigt unter dem "System"-Tab:
- **Version**: Aktuelle Tool-Version
- **Git Commit**: Aktueller Git-Commit Hash (vom offiziellen Repository)
- **Node.js Version**: Installierte Node.js Version
- **Uptime**: Server-Laufzeit
- **Auto-Update Status**: Aktiviert/Deaktiviert
- **Repository**: Offizielles Repository (fest integriert)
- **Branch**: main (fest integriert)

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

## 🔒 Sicherheit & Vorteile

### Update-Sicherheit

- **Offizielles Repository**: Updates nur von der vertrauenswürdigen Quelle
- **Backup**: Automatisches Backup der Konfiguration vor Updates
- **Rollback**: Git-History ermöglicht Rollbacks
- **Validation**: Überprüfung auf gültige Git-Repository
- **Keine User-Repos**: Schutz vor manipulierten oder unsicheren Repositories

### Vereinfachte Installation

- **Weniger Fehlerquellen**: Keine falschen Repository-URLs mehr
- **Einfacher Setup**: Reduzierte Anzahl von Umgebungsvariablen
- **Konsistente Updates**: Alle Installationen verwenden dasselbe Repository
- **Besserer Support**: Einheitliche Codebasis für alle Nutzer

### Authentifizierung

- JWT-basierte Token-Authentifizierung
- Session-Management mit sicheren Cookies
- Rate Limiting zum Schutz vor Brute-Force-Angriffen

## 📁 Dateistruktur

```
/home/container/
├── db-backup-tool/
│   ├── server.js          # Hauptserver-Datei
│   ├── package.json       # Node.js Abhängigkeiten
│   ├── config.json        # Konfigurationsdatei
│   ├── update.sh          # Update-Script (offizielles Repository)
│   ├── backups/           # Backup-Verzeichnis
│   │   └── schedules.json # Gespeicherte Zeitpläne
│   ├── logs/              # Log-Dateien
│   ├── .git/              # Git Repository (offiziell)
│   └── node_modules/      # Node.js Module
```

## 🚀 Für Entwickler

### Offizielle Updates entwickeln

Nur der offizielle Maintainer kann Updates veröffentlichen:

```bash
# Änderungen committen
git add .
git commit -m "Neue Features hinzugefügt"
git push origin main

# Auf allen Servern wird automatisch geupdatet beim nächsten Restart
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

**Problem**: Repository nicht verfügbar
- Das offizielle Repository ist möglicherweise temporär nicht erreichbar
- Warte einige Minuten und versuche es erneut
- Prüfe die Internetverbindung des Servers

**Problem**: Git-Konflikte
```bash
# Hard reset zum letzten funktionierenden Zustand
git reset --hard origin/main
```

**Problem**: Falsches Repository
- Das Tool überprüft automatisch, ob das korrekte offizielle Repository verwendet wird
- Falls nicht, wird die Remote-URL automatisch korrigiert

### Backup-Probleme

**Problem**: Backup schlägt fehl
1. Prüfe Datenbankverbindung
2. Prüfe Benutzerrechte
3. Prüfe verfügbaren Speicherplatz

**Problem**: Zeitpläne verschwinden
- Zeitpläne werden in `backups/schedules.json` gespeichert
- Bei Updates automatisch gesichert und wiederhergestellt

### Installation-Probleme

**Problem**: Installation schlägt fehl
1. Prüfe Internetverbindung
2. Stelle sicher, dass das offizielle Repository erreichbar ist
3. Überprüfe Docker-Container-Logs

**Problem**: Dependencies fehlen
```bash
cd ~/db-backup-tool
npm install --production
```

## 📞 Support

Bei Problemen:

1. Prüfe die Logs im Pterodactyl Panel
2. Verwende das System-Tab für Diagnose-Informationen
3. Überprüfe die Internetverbindung
4. Stelle sicher, dass Auto-Update aktiviert ist

## ⚠️ Wichtige Hinweise

### Was ist neu in dieser Version?

- **✅ Fest integriertes Repository**: Kein manueller Repository-Setup mehr nötig
- **✅ Weniger Umgebungsvariablen**: Einfachere Installation
- **✅ Sicherere Updates**: Nur vom offiziellen Repository
- **✅ Weniger Fehlerquellen**: Keine falschen Repository-URLs mehr möglich
- **✅ Besserer Support**: Einheitliche Codebasis für alle Nutzer

### Wichtige Sicherheitshinweise

- **Passwörter**: Ändere alle Standard-Passwörter nach der Installation
- **Backup-Sicherheit**: Sichere den Zugang zu Backups
- **Netzwerk-Sicherheit**: Verwende Firewalls und sichere Ports
- **Updates**: Lass Auto-Update aktiviert für Sicherheits-Patches

### Upgrade von der alten Version

Falls du bereits eine Installation mit manueller Repository-Konfiguration hast:

1. **Backup erstellen**: Sichere deine `config.json` und `backups/schedules.json`
2. **Server löschen**: Lösche den alten Server
3. **Neues Egg verwenden**: Importiere das neue Egg
4. **Server neu erstellen**: Mit den neuen, reduzierten Umgebungsvariablen
5. **Backup wiederherstellen**: Lade deine Konfigurationsdateien wieder hoch

## 🔄 Migration Guide

### Von manueller Repository-Konfiguration zur fest integrierten Version

```bash
# 1. Backup der wichtigen Dateien
cp config.json config.json.backup
cp backups/schedules.json schedules.json.backup

# 2. Repository-URL prüfen und ggf. korrigieren
git remote set-url origin https://github.com/brandy2307/db-backup-tool.git

# 3. Update durchführen
./update.sh

# 4. Konfiguration wiederherstellen
mv config.json.backup config.json
mv schedules.json.backup backups/schedules.json
```

## 🎉 Vorteile der neuen Version

### Für Administratoren
- **Einfachere Installation**: Weniger zu konfigurierende Variablen
- **Weniger Support-Anfragen**: Standardisierte Installation reduziert Probleme
- **Sicherere Updates**: Nur vom vertrauenswürdigen offiziellen Repository

### Für Endnutzer
- **Zuverlässigere Updates**: Keine Abhängigkeit von User-Repositories
- **Konsistente Erfahrung**: Alle Nutzer haben dieselbe Codebasis
- **Automatische Sicherheit**: Security-Updates kommen automatisch

### Für Entwickler
- **Einheitliche Basis**: Alle Issues und Bugs betreffen dieselbe Codebasis
- **Bessere Kontrolle**: Zentrale Verwaltung von Updates und Features
- **Einfachere Wartung**: Ein Repository für alle Installationen

## 📋 Checklist für neue Installation

- [ ] Pterodactyl Egg importiert
- [ ] Server mit korrekten Umgebungsvariablen erstellt
- [ ] Admin-Passwort geändert
- [ ] Session- und JWT-Secrets gesetzt
- [ ] Auto-Update aktiviert
- [ ] Erste Backup-Tests durchgeführt
- [ ] Zeitpläne konfiguriert (optional)
- [ ] System-Informationen geprüft

## 📜 Lizenz

MIT License - Verwende das Tool frei für private und kommerzielle Zwecke.

## 🤝 Beitragen

Da das Repository nun fest integriert ist, wende dich für Feature-Requests und Bug-Reports an den offiziellen Maintainer:

- **Issues**: Über das offizielle GitHub Repository
- **Feature Requests**: Über GitHub Issues
- **Bug Reports**: Mit detaillierten Logs und Reproduktionsschritten

---

**🔗 Offizielles Repository**: https://github.com/brandy2307/db-backup-tool.git