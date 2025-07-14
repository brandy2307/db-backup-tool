#!/bin/bash
# Auto-Update Script für offizielles Repository - Container-optimiert
# Funktioniert ohne rsync und andere externe Tools

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

# Funktion: Berechtigungen setzen
fix_permissions() {
    echo "🔧 Setze korrekte Berechtigungen..."
    
    # Hauptverzeichnis
    chmod 755 . 2>/dev/null || true
    
    # Ausführbare Dateien
    chmod +x update.sh 2>/dev/null || true
    chmod +x server.js 2>/dev/null || true
    
    # Konfigurationsdateien (lesbar/schreibbar)
    chmod 644 *.json 2>/dev/null || true
    chmod 644 *.js 2>/dev/null || true
    chmod 644 *.md 2>/dev/null || true
    
    # Verzeichnisse (ausführbar für Navigation)
    chmod 755 backups 2>/dev/null || true
    chmod 755 logs 2>/dev/null || true
    chmod 755 config 2>/dev/null || true
    chmod 755 public 2>/dev/null || true
    
    # Frontend-Dateien
    chmod 644 public/*.html 2>/dev/null || true
    chmod 644 public/*.css 2>/dev/null || true
    chmod 644 public/*.js 2>/dev/null || true
    
    # Git-Dateien
    chmod 644 .gitattributes 2>/dev/null || true
    
    # NPM/Node-spezifische Dateien
    chmod 644 package*.json 2>/dev/null || true
    
    echo "✅ Berechtigungen gesetzt"
}

# Funktion: Verzeichnisstruktur prüfen und erstellen
ensure_directories() {
    echo "📁 Prüfe Verzeichnisstruktur..."
    
    # Wichtige Verzeichnisse erstellen
    mkdir -p backups logs config public
    
    # Backup-Zeitpläne-Datei erstellen falls nicht vorhanden
    if [ ! -f "backups/schedules.json" ]; then
        echo "[]" > backups/schedules.json
        echo "✅ schedules.json erstellt"
    fi
    
    # .gitattributes erstellen falls nicht vorhanden
    if [ ! -f ".gitattributes" ]; then
        echo "* text=auto" > .gitattributes
        echo "✅ .gitattributes erstellt"
    fi
    
    echo "✅ Verzeichnisstruktur überprüft"
}

# Funktion: Backup-Ordner sicher wiederherstellen (ohne rsync)
restore_backup_folder() {
    local source_dir="$1"
    local target_dir="$2"
    
    if [ ! -d "$source_dir" ]; then
        return 0
    fi
    
    echo "🔄 Stelle Backup-Ordner wieder her (von $source_dir nach $target_dir)..."
    
    # Stelle sicher, dass das Zielverzeichnis existiert
    mkdir -p "$target_dir"
    
    # Kopiere alle Dateien und Unterverzeichnisse
    (
        cd "$source_dir"
        find . -type f -exec cp --parents {} "../$target_dir/" \; 2>/dev/null || {
            # Fallback für Systeme ohne --parents Flag
            find . -type f | while IFS= read -r file; do
                # Erstelle Verzeichnisstruktur
                mkdir -p "../$target_dir/$(dirname "$file")" 2>/dev/null || true
                # Kopiere Datei
                cp "$file" "../$target_dir/$file" 2>/dev/null || true
            done
        }
    )
    
    # Kopiere Verzeichnisse
    (
        cd "$source_dir"
        find . -type d -exec mkdir -p "../$target_dir/{}" \; 2>/dev/null || true
    )
    
    echo "✅ Backup-Ordner wiederhergestellt"
}

# Berechtigungen am Anfang setzen (falls das Script selbst keine Rechte hatte)
echo "🔧 Erste Berechtigungsreparatur..."
chmod +x "$0" 2>/dev/null || true

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

# Backup des kompletten backups-Ordners (falls vorhanden und nicht leer)
if [ -d "backups" ] && [ "$(ls -A backups 2>/dev/null)" ]; then
    cp -r backups "$BACKUP_DIR/backups_folder" 2>/dev/null || true
    echo "✅ Backup-Ordner gesichert"
fi

# Backup von benutzerdefinierten Frontend-Dateien (falls vorhanden)
if [ -f "public/custom.css" ]; then
    cp public/custom.css "$BACKUP_DIR/custom.css"
    echo "✅ Benutzerdefinierte CSS-Datei gesichert"
fi

if [ -f "public/custom.js" ]; then
    cp public/custom.js "$BACKUP_DIR/custom.js"
    echo "✅ Benutzerdefinierte JS-Datei gesichert"
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
    git stash push -m "Auto-stash before update $(date)" 2>/dev/null || true
    
    # Hard reset zum neuesten Stand
    git reset --hard origin/$REPO_BRANCH
    
    # Berechtigungen sofort nach Git-Update setzen
    fix_permissions
    
    # Dependencies aktualisieren
    echo "📦 Aktualisiere Dependencies..."
    npm cache clean --force 2>/dev/null || true
    
    # NPM install mit verschiedenen Fallback-Optionen
    if npm install --production --omit=dev; then
        echo "✅ Dependencies mit --omit=dev installiert"
    elif npm install --production --legacy-peer-deps; then
        echo "✅ Dependencies mit --legacy-peer-deps installiert"
    elif npm install --production; then
        echo "✅ Dependencies installiert"
    else
        echo "⚠️  Dependency-Installation fehlgeschlagen - fahre trotzdem fort"
    fi
    
    # Verzeichnisse sicherstellen
    ensure_directories
    
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
    
    # Backup-Ordner wiederherstellen (ohne rsync)
    if [ -d "$BACKUP_DIR/backups_folder" ]; then
        restore_backup_folder "$BACKUP_DIR/backups_folder" "backups"
    fi
    
    # Benutzerdefinierte Frontend-Dateien wiederherstellen
    if [ -f "$BACKUP_DIR/custom.css" ]; then
        mv "$BACKUP_DIR/custom.css" public/custom.css
        echo "✅ Benutzerdefinierte CSS-Datei wiederhergestellt"
    fi
    
    if [ -f "$BACKUP_DIR/custom.js" ]; then
        mv "$BACKUP_DIR/custom.js" public/custom.js
        echo "✅ Benutzerdefinierte JS-Datei wiederhergestellt"
    fi
    
    # Frontend-Dateien prüfen
    echo "🎨 Prüfe Frontend-Dateien..."
    
    FRONTEND_FILES=(
        "public/index.html"
        "public/styles.css"
        "public/app.js"
    )
    
    MISSING_FILES=()
    for file in "${FRONTEND_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            MISSING_FILES+=("$file")
        fi
    done
    
    if [ ${#MISSING_FILES[@]} -gt 0 ]; then
        echo "⚠️  Fehlende Frontend-Dateien erkannt:"
        for file in "${MISSING_FILES[@]}"; do
            echo "   - $file"
        done
        echo "ℹ️  Führe 'git reset --hard origin/main' aus, falls Dateien fehlen"
    else
        echo "✅ Alle Frontend-Dateien vorhanden"
    fi
    
    # Finale Berechtigungsreparatur nach dem gesamten Update
    fix_permissions
    
    echo "✅ Update erfolgreich abgeschlossen!"
    echo "📋 Neue Version: $(git rev-parse --short HEAD)"
    echo "📅 Commit-Datum: $(git log -1 --format=%ci)"
    
else
    echo "✅ Bereits auf dem neuesten Stand!"
    echo "📋 Aktuelle Version: $(git rev-parse --short HEAD)"
    
    # Auch bei "kein Update" die Berechtigungen reparieren
    echo "🔧 Repariere Berechtigungen (Wartung)..."
    fix_permissions
    ensure_directories
fi

# Cleanup der temporären Backup-Dateien
echo "🧹 Räume temporäre Dateien auf..."
rm -rf "$BACKUP_DIR" 2>/dev/null || true

# Zeige aktuelle Installation
echo "================================="
echo "📊 AKTUELLE INSTALLATION"
echo "================================="
echo "Repository: $(git remote get-url origin)"
echo "Branch: $(git branch --show-current 2>/dev/null || echo "main")"
echo "Commit: $(git rev-parse --short HEAD)"
echo "Datum: $(git log -1 --format=%ci 2>/dev/null || echo "Unknown")"
echo "Node.js: $(node --version 2>/dev/null || echo "Unknown")"
echo "NPM: $(npm --version 2>/dev/null || echo "Unknown")"
echo ""
echo "📁 Dateistruktur:"
echo "├── server.js $([ -f "server.js" ] && echo "✅" || echo "❌")"
echo "├── package.json $([ -f "package.json" ] && echo "✅" || echo "❌")"
echo "├── config.json $([ -f "config.json" ] && echo "✅" || echo "❌")"
echo "├── update.sh $([ -f "update.sh" ] && echo "✅" || echo "❌") $([ -x "update.sh" ] && echo "(🔓)" || echo "(🔒)")"
echo "└── public/"
echo "    ├── index.html $([ -f "public/index.html" ] && echo "✅" || echo "❌")"
echo "    ├── styles.css $([ -f "public/styles.css" ] && echo "✅" || echo "❌")"
echo "    ├── app.js $([ -f "public/app.js" ] && echo "✅" || echo "❌")"
echo "    ├── custom.css $([ -f "public/custom.css" ] && echo "📝" || echo "⚪")"
echo "    └── custom.js $([ -f "public/custom.js" ] && echo "📝" || echo "⚪")"
echo ""
echo "📂 Verzeichnisse:"
echo "├── backups/ $([ -d "backups" ] && echo "✅" || echo "❌")"
echo "├── logs/ $([ -d "logs" ] && echo "✅" || echo "❌")"
echo "└── config/ $([ -d "config" ] && echo "✅" || echo "❌")"
echo ""
echo "🔧 Verfügbare Tools:"
echo "├── git: $(command -v git >/dev/null 2>&1 && echo "✅" || echo "❌")"
echo "├── npm: $(command -v npm >/dev/null 2>&1 && echo "✅" || echo "❌")"
echo "├── node: $(command -v node >/dev/null 2>&1 && echo "✅" || echo "❌")"
echo "└── rsync: $(command -v rsync >/dev/null 2>&1 && echo "✅" || echo "❌ (nicht benötigt)")"
echo ""
echo "Legende: ✅ OK | ❌ Fehlt | 📝 Benutzerdefiniert | ⚪ Optional | 🔓 Ausführbar | 🔒 Gesperrt"
echo "================================="

echo "🎉 Update-Prozess abgeschlossen!"
echo "🔧 Alle Berechtigungen wurden automatisch repariert!"

# Finale Validierung
if [ -x "update.sh" ]; then
    echo "✅ Update-Script ist korrekt ausführbar"
else
    echo "⚠️  Update-Script Berechtigungen konnten nicht gesetzt werden"
    echo "   Führe manuell aus: chmod +x update.sh"
fi

echo ""
echo "💡 HINWEIS: Frontend-Anpassungen"
echo "Für eigene Anpassungen erstelle:"
echo "├── public/custom.css  - Eigene CSS-Styles"
echo "└── public/custom.js   - Eigene JavaScript-Funktionen"
echo "Diese werden bei Updates automatisch gesichert!"