# Database Backup Tool - Pterodactyl Egg

Ein automatisiertes Datenbank-Backup-Tool mit Web-Interface für MySQL, PostgreSQL und MongoDB, entwickelt speziell für Pterodactyl Panel.

## 🚀 Features

- **Multi-Database Support**: MySQL, PostgreSQL und MongoDB
- **Web-Interface**: Benutzerfreundliche Weboberfläche
- **Automatische Zeitpläne**: Cron-basierte Backup-Automatisierung  
- **Backup-Verwaltung**: Download, Löschen und Verwalten von Backups
- **Komprimierung**: Automatische Backup-Komprimierung
- **Sicherheit**: JWT-basierte Authentifizierung
- **Rate Limiting**: Schutz vor Missbrauch
- **Cleanup**: Automatisches Löschen alter Backups

## 📋 Systemanforderungen

- **Node.js**: Version 18.x oder höher
- **Database Clients**: mysql-client, postgresql-client, mongodb-database-tools
- **RAM**: Mindestens 512MB
- **Storage**: Abhängig von Backup-Größen

## 🛠️ Installation in Pterodactyl

### 1. Egg Import

1. Lade die `db_backup_egg.json` Datei herunter
2. Gehe in dein Pterodactyl Admin Panel
3. Navigiere zu `Admin` → `Nests` → `Import Egg`
4. Wähle die JSON-Datei aus und importiere sie

### 2. Server erstellen

1. Erstelle einen neuen Server mit dem "DB Backup Tool" Egg
2. Konfiguriere die Umgebungsvariablen:
   - **Node Environment**: `production`
   - **Admin Username**: Dein gewünschter Admin-Benutzername
   - **Admin Password**: Ein sicheres Passwort (mindestens 6 Zeichen)
   - **Session Secret**: Ein 32+ Zeichen langer zufälliger String
   - **JWT Secret**: Ein 32+ Zeichen langer zufälliger String
   - **Max Backups**: Anzahl der zu behaltenden Backups (Standard: 10)
   - **Enable Compression**: `true` für Komprimierung

### 3. Server starten

1. Starte den Server über das Pterodactyl Panel
2. Warte bis die Installation abgeschlossen ist
3. Der Server ist bereit wenn "Server läuft auf Port" in den Logs erscheint

## 🔧 Konfiguration

### Umgebungsvariablen

```bash
NODE_ENV=production
ADMIN_USERNAME=admin
ADMIN_PASSWORD=dein_sicheres_passwort
SESSION_SECRET=dein_32_zeichen_langer_session_secret
JWT_SECRET=dein_32_zeichen_langer_jwt_secret
MAX_BACKUPS=10
ENABLE_COMPRESSION=true
```

### Standard-Ports

- **MySQL**: 3306
- **PostgreSQL**: 5432
- **MongoDB**: 27017

## 🎯 Verwendung

### 1. Erster Login

1. Öffne die Server-IP mit dem zugewiesenen Port im Browser
2. Melde dich mit deinen konfigurierten Admin-Daten an
3. **WICHTIG**: Ändere das Passwort nach dem ersten Login!

### 2. Backup erstellen

1. Wähle den Tab "Backup erstellen"
2. Fülle die Datenbankverbindungsdetails aus:
   - **Datenbanktyp**: MySQL, PostgreSQL oder MongoDB
   - **Host**: IP-Adresse oder Hostname der Datenbank
   - **Port**: Port der Datenbank (wird automatisch gesetzt)
   - **Datenbankname**: Name der zu sichernden Datenbank
   - **Benutzername**: Datenbank-Benutzername
   - **Passwort**: Datenbank-Passwort
3. Klicke auf "Backup erstellen"

### 3. Automatische Zeitpläne

1. Wähle den Tab "Zeitplan"
2. Erstelle einen neuen Zeitplan:
   - **Name**: Beschreibender Name für den Zeitplan
   - **Cron-Expression**: Zeitplan im Cron-Format
   - **Datenbankdetails**: Gleiche Details wie beim manuellen Backup
3. Klicke auf "Zeitplan erstellen"

#### Cron-Expression Beispiele

- `0 2 * * *` - Täglich um 2:00 Uhr
- `0 2 * * 0` - Jeden Sonntag um 2:00 Uhr
- `0 */6 * * *` - Alle 6 Stunden
- `0 2 1 * *` - Am 1. jeden Monats um 2:00 Uhr

### 4. Backup-Verwaltung

1. Wähle den Tab "Backups verwalten"
2. Hier kannst du:
   - Backups herunterladen
   - Backups löschen
   - Backup-Details einsehen

## 🔒 Sicherheit

### Authentifizierung

- JWT-basierte Token-Authentifizierung
- Session-Management mit sicheren Cookies
- Rate Limiting zum Schutz vor Brute-Force-Angriffen

### Passwort-Sicherheit

- Passwörter werden mit bcrypt gehasht
- Mindestlänge von 6 Zeichen
- Standardpasswörter sollten sofort geändert werden

### Netzwerk-Sicherheit

- CORS-Schutz aktiviert
- Helmet.js für zusätzliche HTTP-Header-Sicherheit
- Komprimierung für bessere Performance

## 📁 Dateistruktur

```
/home/container/
├── db-backup-tool/
│   ├── server.js          # Hauptserver-Datei
│   ├── package.json       # Node.js Abhängigkeiten
│   ├── config.json        # Konfigurationsdatei
│   ├── backups/           # Backup-Verzeichnis
│   ├── logs/              # Log-Dateien
│   └── node_modules/      # Node.js Module
```

## 🐛 Troubleshooting

### Server startet nicht

1. Überprüfe die Logs im Pterodactyl Panel
2. Stelle sicher, dass alle Umgebungsvariablen korrekt gesetzt sind
3. Überprüfe, ob genügend RAM verfügbar ist

### Backup schlägt fehl

1. Überprüfe die Datenbankverbindungsdetails
2. Stelle sicher, dass der Datenbankbenutzer Backup-Rechte hat
3. Überprüfe die Netzwerkverbindung zur Datenbank
4. Schaue in die Server-Logs für detaillierte Fehlermeldungen

### Login funktioniert nicht

1. Überprüfe, ob die Admin-Credentials korrekt sind
2. Stelle sicher, dass Session und JWT Secrets gesetzt sind
3. Lösche Browser-Cookies und versuche es erneut

### Backup-Download funktioniert nicht

1. Überprüfe, ob die Backup-Datei existiert
2. Stelle sicher, dass genügend Speicherplatz vorhanden ist
3. Überprüfe Dateiberechtigungen im Backup-Verzeichnis

## 🔧 Erweiterte Konfiguration

### Manuelle Konfiguration

Die `config.json` Datei kann manuell bearbeitet werden:

```json
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0"
  },
  "security": {
    "sessionSecret": "dein-session-secret",
    "jwtSecret": "dein-jwt-secret",
    "defaultAdmin": {
      "username": "admin",
      "password": "admin123"
    }
  },
  "backup": {
    "defaultPath": "./backups",
    "maxBackups": 10,
    "compression": true
  },
  "logging": {
    "level": "info",
    "file": "./logs/app.log"
  }
}
```

### Backup-Pfad ändern

Du kannst den Backup-Pfad in der `config.json` ändern:

```json
{
  "backup": {
    "defaultPath": "/custom/backup/path"
  }
}
```

## 📊 Monitoring

### Log-Dateien

- **Application Logs**: `logs/app.log`
- **Pterodactyl Logs**: Im Panel unter "Console"

### Backup-Status

- Backup-Erfolg/Fehler werden in den Logs dokumentiert
- Web-Interface zeigt aktuelle Backup-Liste
- Zeitplan-Status ist im Interface einsehbar

## 🔄 Updates

Das Tool wird automatisch beim Server-Neustart auf die neueste Version aktualisiert, da es bei jedem Start die neuesten Abhängigkeiten installiert.

## 📞 Support

Bei Problemen oder Fragen:

1. Überprüfe die Logs im Pterodactyl Panel
2. Schaue in die Server-Console für detaillierte Fehlermeldungen
3. Überprüfe die Systemanforderungen
4. Stelle sicher, dass alle Ports erreichbar sind

## ⚠️ Wichtige Hinweise

- **Passwörter ändern**: Ändere alle Standard-Passwörter nach der Installation
- **Backup-Sicherheit**: Backups enthalten sensible Daten - sichere den Zugang
- **Ressourcen**: Große Datenbanken benötigen entsprechend Speicherplatz und RAM
- **Netzwerk**: Stelle sicher, dass die Datenbankserver erreichbar sind
- **Updates**: Halte das System und die Datenbank-Clients aktuell

## 📜 Lizenz

Dieses Tool ist für den privaten und kommerziellen Gebrauch freigegeben. Verwende es auf eigene Verantwortung.