#!/bin/bash
# Enhanced SSL-Setup Script für Database Backup Tool
# Erweiterte SSL-Generierung mit besserer Fehlerbehandlung und Validierung

set -e

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Erweiterte Konfiguration
DOMAIN="${SSL_DOMAIN:-localhost}"
EMAIL="${SSL_EMAIL:-admin@localhost}"
METHOD="${SSL_METHOD:-selfsigned}"
AUTO_RENEWAL="${SSL_AUTO_RENEWAL:-true}"
CLOUDFLARE_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
KEY_SIZE="${SSL_KEY_SIZE:-4096}"
CERT_VALIDITY="${SSL_CERT_VALIDITY:-365}"

# Verzeichnisse
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$SCRIPT_DIR/ssl"
BACKUP_DIR="$SSL_DIR/backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$SSL_DIR/ssl-setup.log"

# Logging-Funktion
log() {
    local level="$1"
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

echo -e "${BLUE}🔐 Enhanced SSL-Setup für Database Backup Tool${NC}"
echo "============================================="
echo -e "${BLUE}Script-Verzeichnis:${NC} $SCRIPT_DIR"
echo -e "${BLUE}SSL-Verzeichnis:${NC} $SSL_DIR"
echo -e "${BLUE}Domain:${NC} $DOMAIN"
echo -e "${BLUE}Email:${NC} $EMAIL"
echo -e "${BLUE}Methode:${NC} $METHOD"
echo -e "${BLUE}Auto-Renewal:${NC} $AUTO_RENEWAL"
echo -e "${BLUE}Key-Größe:${NC} $KEY_SIZE bits"
echo -e "${BLUE}Gültigkeit:${NC} $CERT_VALIDITY Tage"
echo "============================================="

# Dependency Check
check_dependencies() {
    log_info "Prüfe System-Dependencies..."
    
    local deps=("openssl" "curl" "git")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Fehlende Dependencies: ${missing[*]}"
        log_info "Installiere fehlende Dependencies..."
        
        # Debian/Ubuntu
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y "${missing[@]}"
        # CentOS/RHEL
        elif command -v yum &> /dev/null; then
            yum install -y "${missing[@]}"
        # Alpine
        elif command -v apk &> /dev/null; then
            apk update
            apk add "${missing[@]}"
        else
            log_error "Unbekannte Paket-Manager - installiere Dependencies manuell"
            exit 1
        fi
    fi
    
    log_info "✅ Alle Dependencies verfügbar"
}

# SSL-Verzeichnis vorbereiten
prepare_ssl_directory() {
    log_info "Bereite SSL-Verzeichnis vor..."
    
    # Backup existierender Zertifikate
    if [ -f "$SSL_DIR/fullchain.pem" ] || [ -f "$SSL_DIR/privkey.pem" ]; then
        log_info "Erstelle Backup existierender Zertifikate..."
        mkdir -p "$BACKUP_DIR"
        
        [ -f "$SSL_DIR/fullchain.pem" ] && cp "$SSL_DIR/fullchain.pem" "$BACKUP_DIR/"
        [ -f "$SSL_DIR/privkey.pem" ] && cp "$SSL_DIR/privkey.pem" "$BACKUP_DIR/"
        
        log_info "✅ Backup erstellt: $BACKUP_DIR"
    fi
    
    # SSL-Verzeichnis erstellen
    mkdir -p "$SSL_DIR"
    chmod 700 "$SSL_DIR"
    
    # Log-Datei initialisieren
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

# Domain-Validierung
validate_domain() {
    log_info "Validiere Domain: $DOMAIN"
    
    # Domain-Format prüfen
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Ungültiges Domain-Format: $DOMAIN"
        return 1
    fi
    
    # DNS-Auflösung prüfen (für Let's Encrypt)
    if [ "$METHOD" = "letsencrypt" ]; then
        if [ "$DOMAIN" = "localhost" ] || [ "$DOMAIN" = "127.0.0.1" ]; then
            log_error "Let's Encrypt funktioniert nicht mit localhost/127.0.0.1"
            return 1
        fi
        
        if ! nslookup "$DOMAIN" &> /dev/null; then
            log_warn "DNS-Auflösung für $DOMAIN fehlgeschlagen"
            log_warn "Stelle sicher, dass die Domain öffentlich erreichbar ist"
        fi
    fi
    
    log_info "✅ Domain-Validierung erfolgreich"
}

# Self-Signed Zertifikat mit erweiterten Optionen
create_selfsigned_cert() {
    log_info "Erstelle Self-Signed Zertifikat..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    local key_file="$SSL_DIR/privkey.pem"
    local config_file="$SSL_DIR/openssl.cnf"
    
    # OpenSSL-Konfiguration erstellen
    cat > "$config_file" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = DE
ST = NRW
L = Sprockhoevel
O = DB Backup Tool
CN = $DOMAIN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.${DOMAIN}
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # Zertifikat erstellen
    openssl req -x509 -newkey rsa:$KEY_SIZE \
        -keyout "$key_file" \
        -out "$cert_file" \
        -days $CERT_VALIDITY \
        -nodes \
        -config "$config_file" \
        -extensions v3_req
    
    # Aufräumen
    rm -f "$config_file"
    
    log_info "✅ Self-Signed Zertifikat erstellt"
}

# Let's Encrypt mit erweiterten Optionen
create_letsencrypt_cert() {
    log_info "Erstelle Let's Encrypt Zertifikat..."
    
    # Certbot installieren
    if ! command -v certbot &> /dev/null; then
        log_info "Installiere Certbot..."
        
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        elif command -v yum &> /dev/null; then
            yum install -y certbot python3-certbot-nginx
        elif command -v snap &> /dev/null; then
            snap install --classic certbot
        else
            log_error "Kann Certbot nicht installieren"
            return 1
        fi
    fi
    
    # Port 80 prüfen
    if netstat -tlnp | grep -q ":80 "; then
        log_warn "Port 80 ist belegt - stoppe Services"
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
        --key-type rsa \
        --rsa-key-size $KEY_SIZE \
        --preferred-challenges http \
        --http-01-port 80 \
        --cert-path "$SSL_DIR/fullchain.pem" \
        --key-path "$SSL_DIR/privkey.pem"
    
    # Zertifikate kopieren
    local letsencrypt_path="/etc/letsencrypt/live/$DOMAIN"
    if [ -d "$letsencrypt_path" ]; then
        cp "$letsencrypt_path/fullchain.pem" "$SSL_DIR/fullchain.pem"
        cp "$letsencrypt_path/privkey.pem" "$SSL_DIR/privkey.pem"
        log_info "✅ Let's Encrypt Zertifikat erstellt"
    else
        log_error "Let's Encrypt Zertifikat-Verzeichnis nicht gefunden"
        return 1
    fi
}

# Cloudflare Origin Certificate
create_cloudflare_cert() {
    log_info "Erstelle Cloudflare Origin Zertifikat..."
    
    if [ -z "$CLOUDFLARE_TOKEN" ]; then
        log_error "CLOUDFLARE_API_TOKEN ist erforderlich"
        return 1
    fi
    
    # Cloudflare Plugin installieren
    if ! certbot plugins | grep -q cloudflare; then
        log_info "Installiere Cloudflare Plugin..."
        
        if command -v apt-get &> /dev/null; then
            apt-get install -y python3-certbot-dns-cloudflare
        elif command -v yum &> /dev/null; then
            yum install -y python3-certbot-dns-cloudflare
        else
            pip3 install certbot-dns-cloudflare
        fi
    fi
    
    # Credentials-Datei erstellen
    local creds_file="$SSL_DIR/.cloudflare-credentials"
    cat > "$creds_file" << EOF
dns_cloudflare_api_token = $CLOUDFLARE_TOKEN
EOF
    chmod 600 "$creds_file"
    
    # Certbot mit Cloudflare ausführen
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$creds_file" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        --key-type rsa \
        --rsa-key-size $KEY_SIZE
    
    # Zertifikate kopieren
    local letsencrypt_path="/etc/letsencrypt/live/$DOMAIN"
    if [ -d "$letsencrypt_path" ]; then
        cp "$letsencrypt_path/fullchain.pem" "$SSL_DIR/fullchain.pem"
        cp "$letsencrypt_path/privkey.pem" "$SSL_DIR/privkey.pem"
        log_info "✅ Cloudflare Origin Zertifikat erstellt"
    else
        log_error "Cloudflare Zertifikat-Verzeichnis nicht gefunden"
        return 1
    fi
    
    # Credentials aufräumen
    rm -f "$creds_file"
}

# Manuelle Zertifikat-Validierung
validate_manual_cert() {
    log_info "Validiere manuelle Zertifikate..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    local key_file="$SSL_DIR/privkey.pem"
    
    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
        log_error "Manuelle Zertifikate nicht gefunden:"
        log_error "  Benötigt: $cert_file"
        log_error "  Benötigt: $key_file"
        return 1
    fi
    
    # Zertifikat validieren
    if ! openssl x509 -in "$cert_file" -text -noout &> /dev/null; then
        log_error "Ungültiges Zertifikat: $cert_file"
        return 1
    fi
    
    # Private Key validieren
    if ! openssl rsa -in "$key_file" -check &> /dev/null; then
        log_error "Ungültiger Private Key: $key_file"
        return 1
    fi
    
    # Zusammengehörigkeit prüfen
    local cert_modulus=$(openssl x509 -noout -modulus -in "$cert_file" | openssl md5)
    local key_modulus=$(openssl rsa -noout -modulus -in "$key_file" | openssl md5)
    
    if [ "$cert_modulus" != "$key_modulus" ]; then
        log_error "Zertifikat und Private Key gehören nicht zusammen"
        return 1
    fi
    
    log_info "✅ Manuelle Zertifikate validiert"
}

# Dateiberechtigungen setzen
set_file_permissions() {
    log_info "Setze Dateiberechtigungen..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    local key_file="$SSL_DIR/privkey.pem"
    
    if [ -f "$cert_file" ]; then
        chmod 644 "$cert_file"
        chown root:root "$cert_file" 2>/dev/null || true
    fi
    
    if [ -f "$key_file" ]; then
        chmod 600 "$key_file"
        chown root:root "$key_file" 2>/dev/null || true
    fi
    
    log_info "✅ Dateiberechtigungen gesetzt"
}

# Zertifikat-Informationen anzeigen
display_cert_info() {
    log_info "Zeige Zertifikat-Informationen..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    
    if [ -f "$cert_file" ]; then
        echo -e "\n${GREEN}📋 Zertifikat-Informationen:${NC}"
        echo "================================="
        
        # Grundinformationen
        openssl x509 -in "$cert_file" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:|DNS:|IP Address:)" | while read line; do
            echo -e "${BLUE}$line${NC}"
        done
        
        # Gültigkeitsprüfung
        local expiry_date=$(openssl x509 -in "$cert_file" -enddate -noout | cut -d= -f2)
        local days_until_expiry=$(( ($(date -d "$expiry_date" +%s) - $(date +%s)) / 86400 ))
        
        echo -e "\n${GREEN}⏰ Gültigkeit:${NC}"
        echo "  Läuft ab: $expiry_date"
        echo "  Verbleibende Tage: $days_until_expiry"
        
        if [ $days_until_expiry -le 30 ]; then
            echo -e "  ${YELLOW}⚠️ Erneuerung empfohlen${NC}"
        fi
        
        echo "================================="
    fi
}

# Auto-Renewal Setup
setup_auto_renewal() {
    if [ "$AUTO_RENEWAL" = "true" ] && [ "$METHOD" != "selfsigned" ] && [ "$METHOD" != "manual" ]; then
        log_info "Richte Auto-Renewal ein..."
        
        # Renewal-Script erstellen
        cat > "$SSL_DIR/renewal.sh" << EOF
#!/bin/bash
# Auto-Renewal Script für $DOMAIN
set -e

export SSL_DOMAIN="$DOMAIN"
export SSL_EMAIL="$EMAIL"
export SSL_METHOD="$METHOD"
export SSL_AUTO_RENEWAL="$AUTO_RENEWAL"
export SSL_KEY_SIZE="$KEY_SIZE"
export CLOUDFLARE_API_TOKEN="$CLOUDFLARE_TOKEN"

cd "$SCRIPT_DIR"
./ssl-setup.sh

# Neustart-Signal an Anwendung
if pgrep -f "node.*server.js" > /dev/null; then
    pkill -HUP -f "node.*server.js" || true
fi
EOF
        
        chmod +x "$SSL_DIR/renewal.sh"
        
        # Cron-Job erstellen
        local cron_file="/etc/cron.d/ssl-renewal-db-backup"
        cat > "$cron_file" << EOF
# Auto-Renewal für DB Backup Tool SSL-Zertifikat
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Täglich um 2:00 Uhr prüfen und erneuern
0 2 * * * root $SSL_DIR/renewal.sh >> $LOG_FILE 2>&1
EOF
        
        log_info "✅ Auto-Renewal konfiguriert"
    else
        log_info "Auto-Renewal übersprungen"
    fi
}

# Cleanup alte Dateien
cleanup_old_files() {
    log_info "Räume alte Dateien auf..."
    
    # Alte Backups (älter als 30 Tage)
    find "$SSL_DIR" -name "backup-*" -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null || true
    
    # Alte Log-Dateien rotieren
    if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt 10485760 ]; then # 10MB
        mv "$LOG_FILE" "$LOG_FILE.old"
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
    
    log_info "✅ Cleanup abgeschlossen"
}

# Hauptfunktion
main() {
    log_info "Starte Enhanced SSL-Setup..."
    
    # Präparation
    check_dependencies
    prepare_ssl_directory
    validate_domain
    
    # Zertifikat generieren
    case "$METHOD" in
        "selfsigned")
            create_selfsigned_cert
            ;;
        "letsencrypt")
            create_letsencrypt_cert
            ;;
        "cloudflare")
            create_cloudflare_cert
            ;;
        "manual")
            validate_manual_cert
            ;;
        *)
            log_error "Unbekannte SSL-Methode: $METHOD"
            exit 1
            ;;
    esac
    
    # Nachbearbeitung
    set_file_permissions
    display_cert_info
    setup_auto_renewal
    cleanup_old_files
    
    log_info "✅ Enhanced SSL-Setup erfolgreich abgeschlossen!"
}

# Fehlerbehandlung
trap 'log_error "SSL-Setup fehlgeschlagen bei Zeile $LINENO"; exit 1' ERR

# Script ausführen
main "$@"

echo -e "\n${GREEN}🎉 SSL-Setup erfolgreich abgeschlossen!${NC}"
echo -e "${BLUE}Logs verfügbar unter: $LOG_FILE${NC}"
echo -e "${BLUE}Zertifikate verfügbar unter: $SSL_DIR${NC}"

if [ -d "$BACKUP_DIR" ]; then
    echo -e "${BLUE}Backup der alten Zertifikate: $BACKUP_DIR${NC}"
fi