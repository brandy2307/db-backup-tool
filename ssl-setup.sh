#!/bin/bash
# SSL-Setup Script für Database Backup Tool
# Datei: ssl-setup.sh
# Platzierung: /home/container/db-backup-tool/ssl-setup.sh

set -e

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verzeichnisse
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$SCRIPT_DIR/ssl"
APP_DIR="$SCRIPT_DIR"

# Konfiguration aus Umgebungsvariablen
DOMAIN="${SSL_DOMAIN:-localhost}"
EMAIL="${SSL_EMAIL:-admin@localhost}"
METHOD="${SSL_METHOD:-selfsigned}"
AUTO_RENEWAL="${SSL_AUTO_RENEWAL:-true}"
CLOUDFLARE_TOKEN="${CLOUDFLARE_API_TOKEN:-}"

echo -e "${BLUE}🔐 SSL-Setup für Database Backup Tool${NC}"
echo "============================================="
echo -e "${BLUE}Script-Verzeichnis:${NC} $SCRIPT_DIR"
echo -e "${BLUE}SSL-Verzeichnis:${NC} $SSL_DIR"
echo -e "${BLUE}Domain:${NC} $DOMAIN"
echo -e "${BLUE}Email:${NC} $EMAIL"
echo -e "${BLUE}Methode:${NC} $METHOD"
echo -e "${BLUE}Auto-Renewal:${NC} $AUTO_RENEWAL"
echo "============================================="

# Prüfe ob wir im richtigen Verzeichnis sind
if [ ! -f "$APP_DIR/server.js" ] || [ ! -f "$APP_DIR/package.json" ]; then
    echo -e "${RED}❌ Fehler: Script muss im db-backup-tool Verzeichnis liegen!${NC}"
    echo -e "${RED}   Erwartet: server.js und package.json im selben Verzeichnis${NC}"
    echo -e "${RED}   Aktuell: $APP_DIR${NC}"
    exit 1
fi

# SSL-Verzeichnis erstellen
echo -e "${BLUE}📁 Erstelle SSL-Verzeichnis...${NC}"
mkdir -p "$SSL_DIR"
chmod 700 "$SSL_DIR"

# Hilfsfunktionen
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}❌ $1 ist nicht installiert${NC}"
        return 1
    fi
    return 0
}

install_certbot() {
    echo -e "${YELLOW}📦 Installiere Certbot...${NC}"
    apt update
    apt install -y certbot python3-certbot-nginx
}

install_cloudflare_plugin() {
    echo -e "${YELLOW}📦 Installiere Cloudflare Plugin...${NC}"
    apt update
    apt install -y python3-certbot-dns-cloudflare
}

create_letsencrypt_cert() {
    echo -e "${GREEN}🔒 Erstelle Let's Encrypt Zertifikat...${NC}"
    
    # Prüfe Domain
    if [ "$DOMAIN" = "localhost" ] || [ "$DOMAIN" = "127.0.0.1" ]; then
        echo -e "${RED}❌ Let's Encrypt funktioniert nicht mit localhost/127.0.0.1${NC}"
        echo -e "${YELLOW}⚠️  Verwende Self-Signed Zertifikat als Fallback${NC}"
        return 1
    fi
    
    # Certbot installieren falls nicht vorhanden
    if ! check_command certbot; then
        install_certbot
    fi
    
    # Temporär Port 80 für Standalone-Mode freigeben
    echo -e "${BLUE}🔍 Prüfe Port 80...${NC}"
    if netstat -tlnp | grep -q ":80 "; then
        echo -e "${YELLOW}⚠️  Port 80 ist belegt - stoppe mögliche Services${NC}"
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
    fi
    
    # Certbot ausführen
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        --preferred-challenges http \
        --http-01-port 80 || return 1
    
    # Zertifikate kopieren
    LETSENCRYPT_PATH="/etc/letsencrypt/live/$DOMAIN"
    if [ -d "$LETSENCRYPT_PATH" ]; then
        cp "$LETSENCRYPT_PATH/fullchain.pem" "$SSL_DIR/fullchain.pem"
        cp "$LETSENCRYPT_PATH/privkey.pem" "$SSL_DIR/privkey.pem"
        chmod 644 "$SSL_DIR/fullchain.pem"
        chmod 600 "$SSL_DIR/privkey.pem"
        echo -e "${GREEN}✅ Let's Encrypt Zertifikat erfolgreich erstellt${NC}"
        return 0
    else
        echo -e "${RED}❌ Let's Encrypt Verzeichnis nicht gefunden${NC}"
        return 1
    fi
}

create_cloudflare_cert() {
    echo -e "${GREEN}☁️  Erstelle Cloudflare Origin Certificate...${NC}"
    
    if [ -z "$CLOUDFLARE_TOKEN" ]; then
        echo -e "${RED}❌ CLOUDFLARE_API_TOKEN ist nicht gesetzt${NC}"
        return 1
    fi
    
    # Certbot mit Cloudflare Plugin installieren
    if ! check_command certbot; then
        install_certbot
    fi
    
    if ! certbot plugins | grep -q cloudflare; then
        install_cloudflare_plugin
    fi
    
    # Credentials-Datei erstellen
    CREDS_FILE="$SSL_DIR/.cloudflare-credentials"
    cat > "$CREDS_FILE" << EOF
dns_cloudflare_api_token = $CLOUDFLARE_TOKEN
EOF
    chmod 600 "$CREDS_FILE"
    
    # Certbot mit Cloudflare DNS ausführen
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CREDS_FILE" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domains "$DOMAIN" || {
        rm -f "$CREDS_FILE"
        return 1
    }
    
    # Zertifikate kopieren
    LETSENCRYPT_PATH="/etc/letsencrypt/live/$DOMAIN"
    if [ -d "$LETSENCRYPT_PATH" ]; then
        cp "$LETSENCRYPT_PATH/fullchain.pem" "$SSL_DIR/fullchain.pem"
        cp "$LETSENCRYPT_PATH/privkey.pem" "$SSL_DIR/privkey.pem"
        chmod 644 "$SSL_DIR/fullchain.pem"
        chmod 600 "$SSL_DIR/privkey.pem"
        rm -f "$CREDS_FILE"
        echo -e "${GREEN}✅ Cloudflare Origin Certificate erfolgreich erstellt${NC}"
        return 0
    else
        rm -f "$CREDS_FILE"
        echo -e "${RED}❌ Cloudflare Zertifikat-Verzeichnis nicht gefunden${NC}"
        return 1
    fi
}

create_selfsigned_cert() {
    echo -e "${YELLOW}🔧 Erstelle Self-Signed Zertifikat...${NC}"
    
    if ! check_command openssl; then
        echo -e "${YELLOW}📦 Installiere OpenSSL...${NC}"
        apt update
        apt install -y openssl
    fi
    
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$SSL_DIR/privkey.pem" \
        -out "$SSL_DIR/fullchain.pem" \
        -days 365 -nodes \
        -subj "/C=DE/ST=NRW/L=Sprockhoevel/O=DB Backup Tool/CN=$DOMAIN" || return 1
    
    chmod 644 "$SSL_DIR/fullchain.pem"
    chmod 600 "$SSL_DIR/privkey.pem"
    
    echo -e "${GREEN}✅ Self-Signed Zertifikat erstellt${NC}"
    echo -e "${YELLOW}⚠️  Browser werden eine Sicherheitswarnung anzeigen${NC}"
    return 0
}

check_manual_cert() {
    echo -e "${BLUE}📋 Prüfe manuelle Zertifikat-Installation...${NC}"
    
    if [ ! -f "$SSL_DIR/fullchain.pem" ] || [ ! -f "$SSL_DIR/privkey.pem" ]; then
        echo -e "${RED}❌ Manuelle Zertifikate nicht gefunden${NC}"
        echo -e "${YELLOW}Bitte platziere deine Zertifikatsdateien:${NC}"
        echo -e "${YELLOW}  - Vollständige Zertifikatskette: $SSL_DIR/fullchain.pem${NC}"
        echo -e "${YELLOW}  - Private Key: $SSL_DIR/privkey.pem${NC}"
        return 1
    fi
    
    chmod 644 "$SSL_DIR/fullchain.pem"
    chmod 600 "$SSL_DIR/privkey.pem"
    
    echo -e "${GREEN}✅ Manuelle Zertifikate gefunden und konfiguriert${NC}"
    return 0
}

setup_auto_renewal() {
    if [ "$AUTO_RENEWAL" != "true" ] || [ "$METHOD" = "selfsigned" ] || [ "$METHOD" = "manual" ]; then
        echo -e "${BLUE}🔄 Auto-Renewal übersprungen für Methode: $METHOD${NC}"
        return 0
    fi
    
    echo -e "${BLUE}🔄 Richte Auto-Renewal ein...${NC}"
    
    # Renewal-Script erstellen
    cat > "$SSL_DIR/renewal.sh" << 'RENEWAL_EOF'
#!/bin/bash
# Auto-Renewal Script für Database Backup Tool
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"

echo "🔄 SSL Auto-Renewal läuft..."
echo "Verzeichnis: $APP_DIR"

# Certbot Renewal
if /usr/bin/certbot renew --quiet; then
    echo "✅ Zertifikat erfolgreich erneuert"
    
    # Kopiere neue Zertifikate
    if [ -d "/etc/letsencrypt/live/$SSL_DOMAIN" ]; then
        cp "/etc/letsencrypt/live/$SSL_DOMAIN/fullchain.pem" "$SCRIPT_DIR/fullchain.pem"
        cp "/etc/letsencrypt/live/$SSL_DOMAIN/privkey.pem" "$SCRIPT_DIR/privkey.pem"
        chmod 644 "$SCRIPT_DIR/fullchain.pem"
        chmod 600 "$SCRIPT_DIR/privkey.pem"
        echo "✅ Neue Zertifikate kopiert"
    fi
    
    # Restart Application (optional)
    if pgrep -f "node.*server.js" > /dev/null; then
        echo "🔄 Sende SIGHUP an Node.js Prozess..."
        pkill -HUP -f "node.*server.js" || true
    fi
else
    echo "❌ Zertifikat-Erneuerung fehlgeschlagen"
fi
RENEWAL_EOF
    
    chmod +x "$SSL_DIR/renewal.sh"
    
    # Cron-Job hinzufügen
    CRON_FILE="/etc/cron.d/db-backup-ssl-renewal"
    cat > "$CRON_FILE" << EOF
# Auto-Renewal für DB Backup Tool SSL-Zertifikat
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
SSL_DOMAIN=$DOMAIN

# Täglich um 2:00 Uhr prüfen und erneuern
0 2 * * * root $SSL_DIR/renewal.sh >> /var/log/ssl-renewal.log 2>&1
EOF
    
    echo -e "${GREEN}✅ Auto-Renewal konfiguriert (täglich um 2:00 Uhr)${NC}"
}

show_certificate_info() {
    if [ -f "$SSL_DIR/fullchain.pem" ]; then
        echo -e "${BLUE}🔍 Zertifikat-Informationen:${NC}"
        echo "============================================="
        openssl x509 -in "$SSL_DIR/fullchain.pem" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:)" || true
        echo "============================================="
    fi
}

# Hauptlogik
main() {
    case "$METHOD" in
        "letsencrypt")
            if create_letsencrypt_cert; then
                setup_auto_renewal
            else
                echo -e "${YELLOW}⚠️  Let's Encrypt fehlgeschlagen, verwende Self-Signed Fallback${NC}"
                create_selfsigned_cert
            fi
            ;;
            
        "cloudflare")
            if create_cloudflare_cert; then
                setup_auto_renewal
            else
                echo -e "${YELLOW}⚠️  Cloudflare fehlgeschlagen, verwende Self-Signed Fallback${NC}"
                create_selfsigned_cert
            fi
            ;;
            
        "selfsigned")
            create_selfsigned_cert
            ;;
            
        "manual")
            if ! check_manual_cert; then
                echo -e "${YELLOW}⚠️  Manuelle Zertifikate nicht gefunden, verwende Self-Signed Fallback${NC}"
                create_selfsigned_cert
            fi
            ;;
            
        *)
            echo -e "${RED}❌ Unbekannte SSL-Methode: $METHOD${NC}"
            echo -e "${YELLOW}Verfügbare Methoden: letsencrypt, cloudflare, selfsigned, manual${NC}"
            echo -e "${YELLOW}Verwende Self-Signed Fallback${NC}"
            create_selfsigned_cert
            ;;
    esac
    
    # Überprüfe ob Zertifikate erfolgreich erstellt wurden
    if [ -f "$SSL_DIR/fullchain.pem" ] && [ -f "$SSL_DIR/privkey.pem" ]; then
        show_certificate_info
        echo -e "${GREEN}✅ SSL-Setup erfolgreich abgeschlossen!${NC}"
        echo -e "${BLUE}📁 Zertifikate gespeichert in: $SSL_DIR${NC}"
        echo -e "${BLUE}🚀 Starte den Server neu, um HTTPS zu aktivieren${NC}"
        
        # Konfiguration in config.json updaten
        if [ -f "$APP_DIR/config.json" ]; then
            echo -e "${BLUE}📝 Aktualisiere config.json...${NC}"
            # Backup der Config
            cp "$APP_DIR/config.json" "$APP_DIR/config.json.backup"
            
            # SSL-Konfiguration in config.json setzen (vereinfacht)
            sed -i 's/"requireHttps": false/"requireHttps": true/' "$APP_DIR/config.json" 2>/dev/null || true
        fi
        
        return 0
    else
        echo -e "${RED}❌ SSL-Setup fehlgeschlagen!${NC}"
        return 1
    fi
}

# Script ausführen
main "$@"

echo ""
echo -e "${GREEN}🔐 SSL-Setup beendet${NC}"
echo -e "${BLUE}Zum Aktivieren von HTTPS:${NC}"
echo -e "${BLUE}  1. Setze REQUIRE_HTTPS=true in den Umgebungsvariablen${NC}"
echo -e "${BLUE}  2. Starte den Server neu${NC}"
echo -e "${BLUE}  3. Verbinde dich über https://$DOMAIN:8443${NC}"