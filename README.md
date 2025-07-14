# Database Backup Tool - Pterodactyl Egg

Ein automatisiertes Datenbank-Backup-Tool mit Web-Interface für MySQL, PostgreSQL und MongoDB, entwickelt speziell für Pterodactyl Panel mit **fest integriertem offiziellen Update-Repository** und **modularem Frontend**.

## 🚀 Features

- **Multi-Database Support**: MySQL, PostgreSQL und MongoDB
- **Web-Interface**: Benutzerfreundliche Weboberfläche mit separaten Frontend-Dateien
- **Automatische Zeitpläne**: Cron-basierte Backup-Automatisierung  
- **Backup-Verwaltung**: Download, Löschen und Verwalten von Backups
- **Komprimierung**: Automatische Backup-Komprimierung
- **Sicherheit**: JWT-basierte Authentifizierung
- **Rate Limiting**: Schutz vor Missbrauch
- **Cleanup**: Automatisches Löschen alter Backups
- **🔄 Auto-Update**: Automatische Updates vom **offiziellen Repository**
- **📊 System-Monitoring**: Detaillierte System-Informationen
- **🔒 Fest integriert**: Keine manuelle Repository-Konfiguration nötig
- **🎨 Anpassbares Frontend**: Separate HTML, CSS und JavaScript-Dateien
- **📱 Responsive Design**: Optimiert für Desktop und Mobile

## 📁 Neue Frontend-Architektur

Das Frontend wurde in separate Dateien aufgeteilt für bessere Wartbarkeit und Anpassbarkeit:

```
db-backup-tool/
├── server.js              # Backend-Server (Node.js)
├── package.json           # Dependencies
├── config.json            # Konfiguration
├── update.sh              # Auto-Update Script
└── public/                # Frontend-Dateien
    ├── index.html         # HTML-Struktur
    ├── styles.css         # Standard CSS-Styles
    ├── app.js             # JavaScript-Logik
    ├── custom.css         # (Optional) Eigene CSS-Anpassungen
    └── custom.js          # (Optional) Eigene JavaScript-Erweiterungen
```

## 🎨 Frontend-Anpassungen

### Einfache Anpassungen

Du kannst das Design und die Funktionalität einfach erweitern, ohne den Core-Code zu ändern:

1. **Design anpassen**: Erstelle `public/custom.css` für eigene Styles
2. **Funktionen erweitern**: Erstelle `public/custom.js` für zusätzliche Features
3. **Update-sicher**: Deine Anpassungen werden bei Updates automatisch gesichert

### Beispiel: Dark Theme

```css
/* public/custom.css */
body {
    background: #1a1a1a;
    color: #e1e1e1;
}

.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.tab-content, .login-form {
    background: #2d2d2d;
    border: 1px solid #444;
}
```

### Beispiel: Erweiterte Funktionen

```javascript
/* public/custom.js */
// Automatische Backup-Liste Aktualisierung
setInterval(() => {
    if (authToken && document.getElementById('backups-content').classList.contains('active')) {
        loadBackups();
    }
}, 30000);

// Keyboard Shortcuts
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        refreshCurrentTab();
    }
});
```

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
4. Frontend-Dateien werden automatisch bereitgestellt
5. Server ist bereit wenn "Server läuft auf Port" in den Logs erscheint

## 🔄 Auto-Update System

### Was ist neu?

- **Fest integriertes Repository**: Updates kommen automatisch vom offiziellen `https://github.com/brandy2307/db-backup-tool.git`
- **Frontend-Schutz**: Benutzerdefinierte CSS/JS-Dateien werden bei Updates gesichert
- **Keine Konfiguration nötig**: Kein manuelles Setzen von Repository-URLs mehr
- **Sicherer**: Nur Updates vom vertrauenswürdigen offiziellen Repository
- **Einfacher**: Weniger Fehlerquellen bei der Installation

### Funktionsweise

1. **Beim Start**: Automatische Prüfung auf Updates vom offiziellen Repository
2. **Backup**: Konfiguration, Zeitpläne und Frontend-Anpassungen werden gesichert
3. **Git-Pull**: Neueste Version wird vom offiziellen Repository geholt
4. **Update**: Code wird aktualisiert, Dependencies installiert
5. **Restore**: Konfiguration und Anpassungen werden wiederhergestellt
6. **Frontend-Check**: Überprüfung der Frontend-Dateien auf Vollständigkeit

### Update-Sicherheit für Frontend

Das Update-System schützt automatisch deine Anpassungen:

#### ✅ Wird bei Updates gesichert:
- `config.json` - Deine Konfiguration
- `backups/schedules.json` - Deine Zeitpläne
- `backups/` - Alle deine Backup-Dateien
- `public/custom.css` - Deine CSS-Anpassungen
- `public/custom.js` - Deine JavaScript-Erweiterungen

#### 🔄 Wird bei Updates überschrieben:
- `server.js` - Backend-Code
- `public/index.html` - HTML-Struktur
- `public/styles.css` - Standard-CSS
- `public/app.js` - Standard-JavaScript
- `package.json` - Dependencies
- `update.sh` - Update-Script

### Update-Methoden

#### 🔄 Automatisch
- Bei jedem Serverstart
- Kann über `AUTO_UPDATE=false` deaktiviert werden
- Kommt automatisch vom offiziellen Repository
- Sichert Frontend-Anpassungen automatisch

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
- **Frontend-Status**: Überprüfung der Frontend-Dateien

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

### 5. Frontend anpassen

1. Erstelle `public/custom.css` für Design-Anpassungen
2. Erstelle `public/custom.js` für zusätzliche Funktionen
3. Deine Änderungen sind update-sicher

## 🔒 Sicherheit & Vorteile

### Update-Sicherheit

- **Offizielles Repository**: Updates nur von der vertrauenswürdigen Quelle
- **Automatisches Backup**: Konfiguration und Anpassungen vor Updates gesichert
- **Rollback**: Git-History ermöglicht Rollbacks
- **Validation**: Überprüfung auf gültige Git-Repository und Frontend-Dateien
- **Keine User-Repos**: Schutz vor manipulierten oder unsicheren Repositories

### Vereinfachte Installation

- **Weniger Fehlerquellen**: Keine falschen Repository-URLs mehr
- **Einfacher Setup**: Reduzierte Anzahl von Umgebungsvariablen
- **Konsistente Updates**: Alle Installationen verwenden dasselbe Repository
- **Besserer Support**: Einheitliche Codebasis für alle Nutzer
- **Modulares Frontend**: Einfache Anpassungen ohne Core-Änderungen

### Authentifizierung

- JWT-basierte Token-Authentifizierung
- Session-Management mit sicheren Cookies
- Rate Limiting zum Schutz vor Brute-Force-Angriffen

## 📱 Responsive Design

Das Web-Interface ist vollständig responsive und funktioniert auf:

- **Desktop**: Vollständige Funktionalität
- **Tablet**: Optimierte Tab-Navigation
- **Mobile**: Touch-freundliche Bedienung
- **Verschiedene Browser**: Chrome, Firefox, Safari, Edge

### Mobile Features

- Touch-freundliche Buttons
- Optimierte Formulare
- Responsive Tabellen
- Swipe-Navigation (optional mit custom.js)

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

**Problem**: Frontend-Dateien fehlen
```bash
# Prüfe Frontend-Dateien
ls -la public/
# Sollte zeigen: index.html, styles.css, app.js

# Manueller Clone falls nötig
git reset --hard origin/main
```

**Problem**: Repository nicht verfügbar
- Das offizielle Repository ist möglicherweise temporär nicht erreichbar
- Warte einige Minuten und versuche es erneut
- Prüfe die Internetverbindung des Servers

**Problem**: Custom-Dateien verschwinden
- Custom-Dateien werden automatisch gesichert
- Prüfe ob `public/custom.css` und `public/custom.js` nach Update vorhanden sind
- Bei Problemen: Backup aus `temp_backup_*` Ordner wiederherstellen

### Frontend-Probleme

**Problem**: CSS lädt nicht
1. Prüfe ob `public/styles.css` existiert
2. Browser-Cache leeren (Ctrl+F5)
3. Prüfe Browser-Konsole auf Fehler

**Problem**: JavaScript funktioniert nicht
1. Prüfe ob `public/app.js` existiert
2. Öffne Browser-Konsole (F12) für Fehlermeldungen
3. Prüfe ob alle Dependencies geladen sind

**Problem**: Custom-Styles werden nicht angewendet
1. Stelle sicher, dass `custom.css` in `public/` liegt
2. Prüfe CSS-Syntax auf Fehler
3. Verwende `!important` für hartnäckige Styles

### Installation-Probleme

**Problem**: Installation schlägt fehl
1. Prüfe Internetverbindung
2. Stelle sicher, dass das offizielle Repository erreichbar ist
3. Überprüfe Docker-Container-Logs
4. Prüfe ob alle Frontend-Dateien vorhanden sind

**Problem**: Dependencies fehlen
```bash
cd ~/db-backup-tool
npm install --production
```

**Problem**: Frontend wird nicht angezeigt
```bash
# Prüfe ob public-Ordner existiert
ls -la public/

# Erstelle fehlende Verzeichnisse
mkdir -p public

# Reset zum letzten funktionierenden Stand
git reset --hard origin/main
```

## 📞 Support

Bei Problemen:

1. Prüfe die Logs im Pterodactyl Panel
2. Verwende das System-Tab für Diagnose-Informationen
3. Überprüfe die Frontend-Dateien im `public/` Ordner
4. Überprüfe die Internetverbindung
5. Stelle sicher, dass Auto-Update aktiviert ist

## ⚠️ Wichtige Hinweise

### Was ist neu in dieser Version?

- **✅ Fest integriertes Repository**: Kein manueller Repository-Setup mehr nötig
- **✅ Modulares Frontend**: Separate HTML, CSS und JavaScript-Dateien
- **✅ Update-sichere Anpassungen**: Custom-Dateien werden automatisch gesichert
- **✅ Responsive Design**: Optimiert für alle Geräte
- **✅ Weniger Umgebungsvariablen**: Einfachere Installation
- **✅ Sicherere Updates**: Nur vom offiziellen Repository
- **✅ Weniger Fehlerquellen**: Keine falschen Repository-URLs mehr möglich
- **✅ Besserer Support**: Einheitliche Codebasis für alle Nutzer

### Wichtige Sicherheitshinweise

- **Passwörter**: Ändere alle Standard-Passwörter nach der Installation
- **Backup-Sicherheit**: Sichere den Zugang zu Backups
- **Netzwerk-Sicherheit**: Verwende Firewalls und sichere Ports
- **Updates**: Lass Auto-Update aktiviert für Sicherheits-Patches
- **Custom-Code**: Teste eigene JavaScript-Erweiterungen gründlich

### Upgrade von der alten Version

Falls du bereits eine Installation mit manueller Repository-Konfiguration hast:

1. **Backup erstellen**: Sichere deine `config.json`, `backups/schedules.json` und eventuelle Frontend-Anpassungen
2. **Server löschen**: Lösche den alten Server
3. **Neues Egg verwenden**: Importiere das neue Egg
4. **Server neu erstellen**: Mit den neuen, reduzierten Umgebungsvariablen
5. **Backup wiederherstellen**: Lade deine Konfigurationsdateien wieder hoch
6. **Frontend anpassen**: Erstelle neue `custom.css` und `custom.js` wenn gewünscht

## 🔄 Migration Guide

### Von manueller Repository-Konfiguration zur fest integrierten Version

```bash
# 1. Backup der wichtigen Dateien
cp config.json config.json.backup
cp backups/schedules.json schedules.json.backup

# Frontend-Anpassungen sichern (falls vorhanden)
cp public/custom.css custom.css.backup 2>/dev/null || true
cp public/custom.js custom.js.backup 2>/dev/null || true

# 2. Repository-URL prüfen und ggf. korrigieren
git remote set-url origin https://github.com/brandy2307/db-backup-tool.git

# 3. Update durchführen
./update.sh

# 4. Konfiguration wiederherstellen
mv config.json.backup config.json
mv schedules.json.backup backups/schedules.json

# Frontend-Anpassungen wiederherstellen (falls vorhanden)
mv custom.css.backup public/custom.css 2>/dev/null || true
mv custom.js.backup public/custom.js 2>/dev/null || true
```

## 🎉 Vorteile der neuen Version

### Für Administratoren
- **Einfachere Installation**: Weniger zu konfigurierende Variablen
- **Modulares Frontend**: Einfache Anpassungen ohne Core-Änderungen
- **Update-sichere Anpassungen**: Keine Verluste bei Updates
- **Weniger Support-Anfragen**: Standardisierte Installation reduziert Probleme
- **Sicherere Updates**: Nur vom vertrauenswürdigen offiziellen Repository

### Für Endnutzer
- **Anpassbares Design**: Eigene Themes und Styles möglich
- **Erweiterte Funktionen**: Zusätzliche Features via JavaScript
- **Mobile Optimierung**: Funktioniert perfekt auf allen Geräten
- **Zuverlässigere Updates**: Keine Abhängigkeit von User-Repositories
- **Konsistente Erfahrung**: Alle Nutzer haben dieselbe Basis, aber individuelle Anpassungen

### Für Entwickler
- **Klare Trennung**: Frontend und Backend sauber getrennt
- **Einfache Anpassungen**: CSS und JavaScript in separaten Dateien
- **Update-Workflow**: Automatische Sicherung von Custom-Code
- **Einheitliche Basis**: Alle Issues und Bugs betreffen dieselbe Codebasis
- **Bessere Kontrolle**: Zentrale Verwaltung von Updates und Features
- **Einfachere Wartung**: Ein Repository für alle Installationen

## 📋 Checklist für neue Installation

- [ ] Pterodactyl Egg importiert
- [ ] Server mit korrekten Umgebungsvariablen erstellt
- [ ] Admin-Passwort geändert
- [ ] Session- und JWT-Secrets gesetzt
- [ ] Auto-Update aktiviert
- [ ] Frontend-Dateien überprüft (`public/` Ordner)
- [ ] Erste Backup-Tests durchgeführt
- [ ] Zeitpläne konfiguriert (optional)
- [ ] System-Informationen geprüft
- [ ] Responsive Design getestet (Mobile/Desktop)
- [ ] Custom-Anpassungen erstellt (optional)

## 📜 Lizenz

MIT License - Verwende das Tool frei für private und kommerzielle Zwecke.

## 🤝 Beitragen

Da das Repository nun fest integriert ist, wende dich für Feature-Requests und Bug-Reports an den offiziellen Maintainer:

- **Issues**: Über das offizielle GitHub Repository
- **Feature Requests**: Über GitHub Issues
- **Bug Reports**: Mit detaillierten Logs und Reproduktionsschritten
- **Frontend-Anpassungen**: Teile deine `custom.css` und `custom.js` mit der Community

## 🔗 Weitere Informationen

- **Offizielles Repository**: https://github.com/brandy2307/db-backup-tool.git
- **Frontend-Anpassungen**: Siehe `Frontend-Anpassungsanleitung.md`
- **CSS Framework**: Eigenes responsives CSS-System
- **JavaScript**: Vanilla JavaScript (keine Frameworks erforderlich)