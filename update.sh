#!/bin/bash
# Auto-Update Script für offizielles Repository
# Dieses Script wird automatisch vom DB Backup Tool verwendet

set -e

# Fest definierte Repository-Daten
REPO_URL="https://github.com/brandy2307/db-backup-tool.git"
REPO_BRANCH="main"

echo "================================="
echo "🔄 DB BACKUP TOOL AUTO-UPDATE"
echo "================================="
echo "📦 Offizielles Repository: ${REPO_URL}"
echo "🔗 Branch: ${REPO_BRANCH}"
echo "📁 Verzeichnis: $(pwd)"
echo "================================="

# Prüfe ob wir in einem Git Repository sind
if [ ! -d ".git" ]; then
    echo "❌ Kein Git Repository gefunden!"
    echo "ℹ️  Bitte führe eine Neuinstallation durch"
    exit 1
fi

# Prüfe ob das Repository das offizielle ist
CURRENT_REPO=$(git remote get-url origin 2>/dev/null || echo "unknown")
if [ "$CURRENT_REPO" != "$REPO_URL" ]; then
    echo "⚠️  Repository-URL stimmt nicht überein!"
    echo "   Aktuell: $CURRENT_REPO"
    echo "   Erwartet: $REPO_URL"
    echo "🔄 Aktualisiere Remote-URL..."
    git remote set-url origin "$REPO_URL"
fi

# Backup wichtiger Konfigurationsdateien
echo "💾 Sichere Konfigurationsdateien..."
BACKUP_DIR="./temp_backup_$(date +%s)"
mkdir -p "$BACKUP_DIR"

# Backup der wichtigsten Dateien
if [ -f "config.json" ]; then
    cp config.json "$BACKUP_DIR/config.json"
    echo "✅ config.json gesichert"
fi

if [ -f "backups/schedules.json" ]; then
    cp backups/schedules.json "$BACKUP_DIR/schedules.json"
    echo "✅ schedules.json gesichert"
fi

# Backup des kompletten backups-Ordners (falls vorhanden)
if [ -d "backups" ] && [ "$(ls -A backups)" ]; then
    cp -r backups "$BACKUP_DIR/backups_folder"
    echo "✅ Backup-Ordner gesichert"
fi

# Git Update vom offiziellen Repository
echo "🔍 Prüfe auf Updates..."
git fetch origin

# Hole aktuelle Commit-Hashes
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/$REPO_BRANCH)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "🔄 Update verfügbar! Aktualisiere..."
    echo "   Von: $(git rev-parse --short HEAD)"
    echo "   Zu:  $(git rev-parse --short origin/$REPO_BRANCH)"
    
    # Stash lokale Änderungen (falls vorhanden)
    git stash push -m "Auto-stash before update $(date)"
    
    # Hard reset zum neuesten Stand
    git reset --hard origin/$REPO_BRANCH
    
    # Dependencies aktualisieren
    echo "📦 Aktualisiere Dependencies..."
    npm cache clean --force
    if ! npm install --production; then
        echo "⚠️  Versuche mit legacy-peer-deps..."
        npm install --production --legacy-peer-deps
    fi
    
    # Stelle sicher, dass alle Verzeichnisse existieren
    mkdir -p backups logs config public
    
    # Konfigurationsdateien wiederherstellen
    echo "🔄 Stelle Konfigurationsdateien wieder her..."
    
    if [ -f "$BACKUP_DIR/config.json" ]; then
        mv "$BACKUP_DIR/config.json" config.json
        echo "✅ config.json wiederhergestellt"
    fi
    
    if [ -f "$BACKUP_DIR/schedules.json" ]; then
        mv "$BACKUP_DIR/schedules.json" backups/schedules.json
        echo "✅ schedules.json wiederhergestellt"
    fi
    
    # Backup-Ordner wiederherstellen (merge mit neuen Dateien)
    if [ -d "$BACKUP_DIR/backups_folder" ]; then
        rsync -av "$BACKUP_DIR/backups_folder/" backups/
        echo "✅ Backup-Ordner wiederhergestellt"
    fi
    
    # Berechtigungen setzen
    chmod +x update.sh
    chmod 755 backups logs config public 2>/dev/null || true
    
    echo "✅ Update erfolgreich abgeschlossen!"
    echo "📋 Neue Version: $(git rev-parse --short HEAD)"
    echo "📅 Commit-Datum: $(git log -1 --format=%ci)"
    
else
    echo "✅ Bereits auf dem neuesten Stand!"
    echo "📋 Aktuelle Version: $(git rev-parse --short HEAD)"
fi

# Cleanup der temporären Backup-Dateien
echo "🧹 Räume temporäre Dateien auf..."
rm -rf "$BACKUP_DIR"

# Zeige aktuelle Git-Informationen
echo "================================="
echo "📊 AKTUELLE INSTALLATION"
echo "================================="
echo "Repository: $(git remote get-url origin)"
echo "Branch: $(git branch --show-current)"
echo "Commit: $(git rev-parse --short HEAD)"
echo "Datum: $(git log -1 --format=%ci)"
echo "Node.js: $(node --version)"
echo "NPM: $(npm --version)"
echo "================================="

echo "🎉 Update-Prozess abgeschlossen!"