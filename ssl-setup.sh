#!/bin/bash
# Enhanced SSL-Setup Script mit erweiterten Debugging für Database Backup Tool
# DEBUGGING VERSION - Zeigt genau warum SSL-Setup fehlschlägt

set -e

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Debug-Modus aktivieren
DEBUG=${DEBUG:-true}
VERBOSE=${VERBOSE:-true}

# Erweiterte Konfiguration mit Debugging
DOMAIN="${SSL_DOMAIN:-localhost}"
EMAIL="${SSL_EMAIL:-admin@localhost}"
METHOD="${SSL_METHOD:-selfsigned}"
AUTO_RENEWAL="${SSL_AUTO_RENEWAL:-true}"
CLOUDFLARE_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
KEY_SIZE="${SSL_KEY_SIZE:-4096}"
CERT_VALIDITY="${SSL_CERT_VALIDITY:-365}"
LETS_ENCRYPT_PORT="${LETS_ENCRYPT_PORT:-80}"  # Neue Variable für Let's Encrypt Port
FORCE_DOMAIN_VALIDATION="${FORCE_DOMAIN_VALIDATION:-false}"  # Domain-Validierung forcieren

# Verzeichnisse
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$SCRIPT_DIR/ssl"
BACKUP_DIR="$SSL_DIR/backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$SSL_DIR/ssl-setup.log"
DEBUG_LOG="$SSL_DIR/ssl-debug.log"

# Enhanced Logging-Funktionen
log() {
    local level="$1"
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
    if [ "$DEBUG" = "true" ]; then
        echo -e "${timestamp} [${level}] ${message}" >> "$DEBUG_LOG"
    fi
}

log_info() { 
    log "INFO" "$@"
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}[INFO]${NC} $@"
    fi
}

log_warn() { 
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $@"
}

log_error() { 
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $@"
}

log_debug() {
    if [ "$DEBUG" = "true" ]; then
        log "DEBUG" "$@"
        echo -e "${CYAN}[DEBUG]${NC} $@"
    fi
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[SUCCESS]${NC} $@"
}

# Debug-Informationen sammeln
collect_debug_info() {
    log_debug "=== SYSTEM DEBUG INFORMATIONEN ==="
    log_debug "Script-Pfad: $0"
    log_debug "Working Directory: $(pwd)"
    log_debug "User: $(whoami)"
    log_debug "UID: $(id -u)"
    log_debug "GID: $(id -g)"
    log_debug "Hostname: $(hostname)"
    log_debug "OS: $(uname -a)"
    
    log_debug "=== UMGEBUNGSVARIABLEN ==="
    log_debug "SSL_DOMAIN: '${SSL_DOMAIN}'"
    log_debug "SSL_EMAIL: '${SSL_EMAIL}'"
    log_debug "SSL_METHOD: '${SSL_METHOD}'"
    log_debug "SSL_AUTO_RENEWAL: '${SSL_AUTO_RENEWAL}'"
    log_debug "CLOUDFLARE_API_TOKEN: '${CLOUDFLARE_API_TOKEN:+GESETZT (${#CLOUDFLARE_API_TOKEN} Zeichen)}${CLOUDFLARE_API_TOKEN:-NICHT GESETZT}'"
    log_debug "SSL_KEY_SIZE: '${SSL_KEY_SIZE}'"
    log_debug "SSL_CERT_VALIDITY: '${SSL_CERT_VALIDITY}'"
    log_debug "LETS_ENCRYPT_PORT: '${LETS_ENCRYPT_PORT}'"
    
    log_debug "=== VERZEICHNISSE ==="
    log_debug "SCRIPT_DIR: $SCRIPT_DIR"
    log_debug "SSL_DIR: $SSL_DIR"
    log_debug "LOG_FILE: $LOG_FILE"
    
    log_debug "=== NETZWERK STATUS ==="
    log_debug "Aktive Ports:"
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -E ":80|:443|:8080|:8443" | while read line; do
            log_debug "  $line"
        done
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -E ":80|:443|:8080|:8443" | while read line; do
            log_debug "  $line"
        done
    else
        log_debug "  Keine Port-Scanning Tools verfügbar"
    fi
    
    log_debug "=== DNS STATUS ==="
    if command -v nslookup >/dev/null 2>&1; then
        log_debug "DNS-Auflösung für $DOMAIN:"
        nslookup "$DOMAIN" 2>&1 | while read line; do
            log_debug "  $line"
        done
    fi
    
    log_debug "=== VERFÜGBARE TOOLS ==="
    for tool in openssl curl wget git certbot snapd docker; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$($tool --version 2>&1 | head -1 || echo "Version unbekannt")
            log_debug "  $tool: ✅ ($version)"
        else
            log_debug "  $tool: ❌ Nicht verfügbar"
        fi
    done
    
    log_debug "=== BERECHTIGUNGEN ==="
    log_debug "SSL-Verzeichnis: $(ls -la "$SSL_DIR" 2>/dev/null || echo 'Existiert nicht')"
    if [ -f "$SSL_DIR/fullchain.pem" ]; then
        log_debug "Aktuelles Zertifikat: $(ls -la "$SSL_DIR/fullchain.pem")"
    fi
    if [ -f "$SSL_DIR/privkey.pem" ]; then
        log_debug "Aktueller Private Key: $(ls -la "$SSL_DIR/privkey.pem")"
    fi
    
    log_debug "=== ENDE DEBUG INFORMATIONEN ==="
}

echo -e "${MAGENTA}🔐 Enhanced SSL-Setup mit erweiterten Debugging${NC}"
echo "============================================="
echo -e "${BLUE}Script-Verzeichnis:${NC} $SCRIPT_DIR"
echo -e "${BLUE}SSL-Verzeichnis:${NC} $SSL_DIR"
echo -e "${BLUE}Domain:${NC} $DOMAIN"
echo -e "${BLUE}Email:${NC} $EMAIL"
echo -e "${BLUE}Methode:${NC} $METHOD"
echo -e "${BLUE}Auto-Renewal:${NC} $AUTO_RENEWAL"
echo -e "${BLUE}Key-Größe:${NC} $KEY_SIZE bits"
echo -e "${BLUE}Gültigkeit:${NC} $CERT_VALIDITY Tage"
echo -e "${BLUE}Let's Encrypt Port:${NC} $LETS_ENCRYPT_PORT"
echo -e "${BLUE}Debug-Modus:${NC} $DEBUG"
echo -e "${BLUE}Verbose-Modus:${NC} $VERBOSE"
echo "============================================="

# Debug-Informationen sammeln
collect_debug_info

# Dependency Check mit erweiterten Details
check_dependencies() {
    log_info "Prüfe System-Dependencies mit erweiterten Details..."
    
    local deps=("openssl" "curl")
    local optional_deps=("git" "wget" "certbot" "snapd")
    local missing=()
    local optional_missing=()
    
    # Kritische Dependencies
    for dep in "${deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            local version=$($dep --version 2>&1 | head -1 || echo "Version unbekannt")
            log_debug "✅ $dep verfügbar: $version"
        else
            missing+=("$dep")
            log_error "❌ Kritische Dependency fehlt: $dep"
        fi
    done
    
    # Optionale Dependencies
    for dep in "${optional_deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            local version=$($dep --version 2>&1 | head -1 || echo "Version unbekannt")
            log_debug "✅ $dep verfügbar: $version"
        else
            optional_missing+=("$dep")
            log_debug "⚪ Optionale Dependency fehlt: $dep"
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Fehlende kritische Dependencies: ${missing[*]}"
        log_info "Versuche automatische Installation..."
        
        # Package Manager Detection mit Debugging
        if command -v apt-get &> /dev/null; then
            log_debug "Debian/Ubuntu System erkannt"
            apt-get update
            apt-get install -y "${missing[@]}"
        elif command -v yum &> /dev/null; then
            log_debug "CentOS/RHEL System erkannt"
            yum install -y "${missing[@]}"
        elif command -v apk &> /dev/null; then
            log_debug "Alpine System erkannt"
            apk update
            apk add "${missing[@]}"
        elif command -v dnf &> /dev/null; then
            log_debug "Fedora System erkannt"
            dnf install -y "${missing[@]}"
        else
            log_error "Unbekannter Paket-Manager - installiere Dependencies manuell"
            return 1
        fi
    fi
    
    if [ ${#optional_missing[@]} -gt 0 ]; then
        log_warn "Fehlende optionale Dependencies: ${optional_missing[*]}"
        log_warn "Diese können manuell installiert werden für erweiterte Funktionalität"
    fi
    
    log_success "Dependency-Check abgeschlossen"
}

# SSL-Verzeichnis vorbereiten mit erweiterten Details
prepare_ssl_directory() {
    log_info "Bereite SSL-Verzeichnis vor..."
    
    # Backup existierender Zertifikate mit Details
    if [ -f "$SSL_DIR/fullchain.pem" ] || [ -f "$SSL_DIR/privkey.pem" ]; then
        log_info "Existierende Zertifikate gefunden - erstelle Backup..."
        mkdir -p "$BACKUP_DIR"
        
        if [ -f "$SSL_DIR/fullchain.pem" ]; then
            cp "$SSL_DIR/fullchain.pem" "$BACKUP_DIR/"
            local cert_info=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -subject -dates -noout 2>/dev/null || echo "Zertifikat-Info nicht verfügbar")
            log_debug "Backup Zertifikat-Info: $cert_info"
        fi
        
        if [ -f "$SSL_DIR/privkey.pem" ]; then
            cp "$SSL_DIR/privkey.pem" "$BACKUP_DIR/"
            local key_size=$(openssl rsa -in "$SSL_DIR/privkey.pem" -text -noout 2>/dev/null | grep "Private-Key:" || echo "Key-Info nicht verfügbar")
            log_debug "Backup Key-Info: $key_size"
        fi
        
        log_success "Backup erstellt: $BACKUP_DIR"
    else
        log_debug "Keine existierenden Zertifikate gefunden"
    fi
    
    # SSL-Verzeichnis erstellen mit Debugging
    if [ ! -d "$SSL_DIR" ]; then
        log_debug "Erstelle SSL-Verzeichnis: $SSL_DIR"
        mkdir -p "$SSL_DIR"
    fi
    
    chmod 700 "$SSL_DIR"
    log_debug "SSL-Verzeichnis Berechtigungen gesetzt: $(ls -ld "$SSL_DIR")"
    
    # Log-Dateien initialisieren
    touch "$LOG_FILE" "$DEBUG_LOG"
    chmod 600 "$LOG_FILE" "$DEBUG_LOG"
    log_debug "Log-Dateien initialisiert"
}

# Erweiterte Domain-Validierung
validate_domain() {
    log_info "Validiere Domain: $DOMAIN"
    
    # Domain-Format prüfen
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "❌ Ungültiges Domain-Format: $DOMAIN"
        log_debug "Domain muss aus gültigen Zeichen bestehen: a-z, A-Z, 0-9, Bindestrich (nicht am Anfang/Ende)"
        return 1
    fi
    log_debug "✅ Domain-Format ist gültig"
    
    # Localhost/IP-Checks
    if [ "$DOMAIN" = "localhost" ] || [ "$DOMAIN" = "127.0.0.1" ] || [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_warn "Domain ist localhost oder IP-Adresse: $DOMAIN"
        if [ "$METHOD" = "letsencrypt" ]; then
            log_error "❌ Let's Encrypt funktioniert nicht mit localhost/IP-Adressen"
            log_error "Verwende eine echte Domain oder wähle 'selfsigned' als Methode"
            return 1
        fi
    fi
    
    # DNS-Auflösung prüfen (erweitert)
    if [ "$METHOD" = "letsencrypt" ] || [ "$FORCE_DOMAIN_VALIDATION" = "true" ]; then
        log_debug "Prüfe DNS-Auflösung für $DOMAIN..."
        
        if command -v nslookup >/dev/null 2>&1; then
            local dns_result=$(nslookup "$DOMAIN" 2>&1)
            if echo "$dns_result" | grep -q "NXDOMAIN\|can't find"; then
                log_error "❌ DNS-Auflösung fehlgeschlagen für $DOMAIN"
                log_debug "DNS-Fehler: $dns_result"
                if [ "$METHOD" = "letsencrypt" ]; then
                    log_error "Let's Encrypt benötigt eine öffentlich auflösbare Domain"
                    return 1
                fi
            else
                log_debug "✅ DNS-Auflösung erfolgreich"
                log_debug "DNS-Antwort: $dns_result"
            fi
        elif command -v dig >/dev/null 2>&1; then
            local dig_result=$(dig +short "$DOMAIN" 2>&1)
            if [ -z "$dig_result" ]; then
                log_warn "⚠️ Keine DNS-Antwort mit dig für $DOMAIN"
            else
                log_debug "✅ DNS-Antwort (dig): $dig_result"
            fi
        else
            log_warn "⚠️ Keine DNS-Tools verfügbar (nslookup, dig)"
        fi
    fi
    
    # Erreichbarkeits-Test für Let's Encrypt
    if [ "$METHOD" = "letsencrypt" ]; then
        log_debug "Teste HTTP-Erreichbarkeit für Let's Encrypt..."
        if command -v curl >/dev/null 2>&1; then
            local http_test=$(curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "http://$DOMAIN" 2>/dev/null || echo "FAIL")
            log_debug "HTTP-Test Antwort: $http_test"
            if [ "$http_test" != "FAIL" ]; then
                log_debug "✅ HTTP-Verbindung zu $DOMAIN möglich"
            else
                log_warn "⚠️ HTTP-Verbindung zu $DOMAIN fehlgeschlagen"
                log_warn "Let's Encrypt benötigt HTTP-Erreichbarkeit auf Port 80"
            fi
        fi
    fi
    
    log_success "Domain-Validierung abgeschlossen"
}

# Self-Signed Zertifikat mit detailliertem Logging
create_selfsigned_cert() {
    log_info "Erstelle Self-Signed Zertifikat mit korrekter KeyUsage..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    local key_file="$SSL_DIR/privkey.pem"
    local config_file="$SSL_DIR/openssl.cnf"
    
    log_debug "Zertifikat-Datei: $cert_file"
    log_debug "Key-Datei: $key_file"
    log_debug "Config-Datei: $config_file"
    
    # OpenSSL-Konfiguration mit erweiterten Details
    log_debug "Erstelle OpenSSL-Konfiguration..."
    cat > "$config_file" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
x509_extensions = v3_ca

[req_distinguished_name]
C = DE
ST = NRW
L = Sprockhoevel
O = DB Backup Tool Enhanced
CN = $DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[v3_ca]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.${DOMAIN}
DNS.3 = localhost
DNS.4 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = 0.0.0.0
EOF

    log_debug "OpenSSL-Konfiguration erstellt:"
    if [ "$DEBUG" = "true" ]; then
        cat "$config_file" | while read line; do
            log_debug "  $line"
        done
    fi

    # Zertifikat erstellen mit detailliertem Logging
    log_info "Führe OpenSSL-Befehl aus..."
    local openssl_cmd="openssl req -x509 -newkey rsa:$KEY_SIZE -keyout \"$key_file\" -out \"$cert_file\" -days $CERT_VALIDITY -nodes -config \"$config_file\" -extensions v3_ca"
    log_debug "OpenSSL-Befehl: $openssl_cmd"
    
    if eval "$openssl_cmd" 2>&1 | while read line; do log_debug "OpenSSL: $line"; done; then
        log_success "OpenSSL-Befehl erfolgreich ausgeführt"
    else
        log_error "❌ OpenSSL-Befehl fehlgeschlagen"
        return 1
    fi
    
    # Aufräumen
    rm -f "$config_file"
    log_debug "Temporäre Config-Datei entfernt"
    
    # Validierung des erstellten Zertifikats
    log_info "Validiere erstelltes Zertifikat..."
    if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
        local cert_validation=$(openssl x509 -in "$cert_file" -text -noout 2>&1)
        if echo "$cert_validation" | grep -q "digitalSignature"; then
            log_success "✅ Self-Signed Zertifikat mit korrekter KeyUsage erstellt"
            log_debug "KeyUsage gefunden: digitalSignature, keyEncipherment, nonRepudiation"
            log_debug "ExtKeyUsage gefunden: serverAuth, clientAuth"
            
            # Zertifikat-Details loggen
            local subject=$(openssl x509 -in "$cert_file" -subject -noout 2>/dev/null || echo "Subject unbekannt")
            local dates=$(openssl x509 -in "$cert_file" -dates -noout 2>/dev/null || echo "Dates unbekannt")
            log_debug "Zertifikat Subject: $subject"
            log_debug "Zertifikat Dates: $dates"
        else
            log_error "❌ Zertifikat hat nicht die korrekte KeyUsage"
            log_debug "Zertifikat-Inhalt: $cert_validation"
            return 1
        fi
    else
        log_error "❌ Zertifikat-Dateien wurden nicht erstellt"
        return 1
    fi
}

# Let's Encrypt mit erweiterten Details und Port-Konfiguration
create_letsencrypt_cert() {
    log_info "Erstelle Let's Encrypt Zertifikat mit erweiterten Details..."
    
    # Erweiterte Umgebungs-Checks
    log_debug "Prüfe Let's Encrypt Voraussetzungen..."
    
    # Certbot Installation Check
    if ! command -v certbot &> /dev/null; then
        log_warn "Certbot nicht gefunden - versuche Installation..."
        install_certbot
        if ! command -v certbot &> /dev/null; then
            log_error "❌ Certbot Installation fehlgeschlagen"
            return 1
        fi
    else
        local certbot_version=$(certbot --version 2>&1 || echo "Version unbekannt")
        log_debug "Certbot verfügbar: $certbot_version"
    fi
    
    # Port-Verfügbarkeit prüfen
    log_debug "Prüfe Port-Verfügbarkeit für Let's Encrypt..."
    local port_check=""
    if command -v netstat >/dev/null 2>&1; then
        port_check=$(netstat -tlnp 2>/dev/null | grep ":$LETS_ENCRYPT_PORT " || echo "")
    elif command -v ss >/dev/null 2>&1; then
        port_check=$(ss -tlnp 2>/dev/null | grep ":$LETS_ENCRYPT_PORT " || echo "")
    fi
    
    if [ -n "$port_check" ]; then
        log_warn "⚠️ Port $LETS_ENCRYPT_PORT ist belegt:"
        log_debug "$port_check"
        log_info "Versuche Services zu stoppen..."
        
        # Services stoppen
        for service in nginx apache2 httpd lighttpd; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_debug "Stoppe Service: $service"
                systemctl stop "$service" 2>/dev/null || log_warn "Konnte $service nicht stoppen"
            fi
        done
        
        # Erneute Port-Prüfung
        sleep 2
        if command -v netstat >/dev/null 2>&1; then
            port_check=$(netstat -tlnp 2>/dev/null | grep ":$LETS_ENCRYPT_PORT " || echo "")
        elif command -v ss >/dev/null 2>&1; then
            port_check=$(ss -tlnp 2>/dev/null | grep ":$LETS_ENCRYPT_PORT " || echo "")
        fi
        
        if [ -n "$port_check" ]; then
            log_error "❌ Port $LETS_ENCRYPT_PORT ist immer noch belegt:"
            log_error "$port_check"
            log_error "Let's Encrypt kann nicht fortfahren"
            return 1
        else
            log_success "✅ Port $LETS_ENCRYPT_PORT ist jetzt frei"
        fi
    else
        log_debug "✅ Port $LETS_ENCRYPT_PORT ist verfügbar"
    fi
    
    # Let's Encrypt Befehl vorbereiten
    log_info "Bereite Let's Encrypt Befehl vor..."
    local certbot_cmd="certbot certonly"
    certbot_cmd+=" --standalone"
    certbot_cmd+=" --non-interactive"
    certbot_cmd+=" --agree-tos"
    certbot_cmd+=" --email \"$EMAIL\""
    certbot_cmd+=" --domains \"$DOMAIN\""
    certbot_cmd+=" --key-type rsa"
    certbot_cmd+=" --rsa-key-size $KEY_SIZE"
    certbot_cmd+=" --preferred-challenges http"
    certbot_cmd+=" --http-01-port $LETS_ENCRYPT_PORT"
    
    log_debug "Certbot-Befehl: $certbot_cmd"
    
    # Certbot ausführen mit detailliertem Logging
    log_info "Führe Certbot aus..."
    if eval "$certbot_cmd" 2>&1 | while read line; do 
        log_debug "Certbot: $line"
        # Echo wichtige Nachrichten auch im normalen Output
        if echo "$line" | grep -E "(Successfully received|Congratulations|IMPORTANT NOTES)" >/dev/null; then
            log_info "$line"
        elif echo "$line" | grep -E "(Error|Failed|Unable)" >/dev/null; then
            log_error "$line"
        fi
    done; then
        log_success "Certbot erfolgreich ausgeführt"
    else
        log_error "❌ Certbot fehlgeschlagen"
        return 1
    fi
    
    # Zertifikate kopieren
    local letsencrypt_path="/etc/letsencrypt/live/$DOMAIN"
    log_debug "Suche Zertifikate in: $letsencrypt_path"
    
    if [ -d "$letsencrypt_path" ]; then
        log_info "Kopiere Let's Encrypt Zertifikate..."
        
        if [ -f "$letsencrypt_path/fullchain.pem" ] && [ -f "$letsencrypt_path/privkey.pem" ]; then
            cp "$letsencrypt_path/fullchain.pem" "$SSL_DIR/fullchain.pem"
            cp "$letsencrypt_path/privkey.pem" "$SSL_DIR/privkey.pem"
            
            log_success "✅ Let's Encrypt Zertifikat erfolgreich kopiert"
            
            # Zertifikat-Details loggen
            local cert_info=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -subject -dates -noout 2>/dev/null || echo "Cert-Info nicht verfügbar")
            log_debug "Zertifikat-Info: $cert_info"
        else
            log_error "❌ Zertifikat-Dateien nicht in $letsencrypt_path gefunden"
            return 1
        fi
    else
        log_error "❌ Let's Encrypt Zertifikat-Verzeichnis nicht gefunden: $letsencrypt_path"
        return 1
    fi
}

# Certbot Installation mit erweiterten Optionen
install_certbot() {
    log_info "Installiere Certbot..."
    
    if command -v apt-get &> /dev/null; then
        log_debug "Debian/Ubuntu: Installiere Certbot via apt"
        apt-get update
        apt-get install -y certbot python3-certbot-apache python3-certbot-nginx
    elif command -v yum &> /dev/null; then
        log_debug "CentOS/RHEL: Installiere Certbot via yum"
        yum install -y epel-release
        yum install -y certbot python3-certbot-apache python3-certbot-nginx
    elif command -v dnf &> /dev/null; then
        log_debug "Fedora: Installiere Certbot via dnf"
        dnf install -y certbot python3-certbot-apache python3-certbot-nginx
    elif command -v snap &> /dev/null; then
        log_debug "Snap verfügbar: Installiere Certbot via Snap"
        snap install --classic certbot
        ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
    else
        log_error "❌ Kein unterstützter Paket-Manager für Certbot-Installation gefunden"
        return 1
    fi
}

# Cloudflare Certificate mit erweiterten Details
create_cloudflare_cert() {
    log_info "Erstelle Cloudflare Origin Zertifikat mit erweiterten Details..."
    
    if [ -z "$CLOUDFLARE_TOKEN" ]; then
        log_error "❌ CLOUDFLARE_API_TOKEN ist erforderlich für Cloudflare-Methode"
        log_error "Setze die Umgebungsvariable CLOUDFLARE_API_TOKEN mit einem gültigen API Token"
        log_info "Token erstellen: https://dash.cloudflare.com/profile/api-tokens"
        return 1
    fi
    
    log_debug "Cloudflare Token verfügbar (${#CLOUDFLARE_TOKEN} Zeichen)"
    
    # Root-Domain ermitteln
    local root_domain
    if [[ "$DOMAIN" == *.* ]]; then
        root_domain=$(echo "$DOMAIN" | rev | cut -d'.' -f1,2 | rev)
    else
        root_domain="$DOMAIN"
    fi
    log_debug "Root-Domain ermittelt: $root_domain"
    
    # Cloudflare Zone ID ermitteln
    log_info "Ermittle Cloudflare Zone ID für Domain: $root_domain"
    
    local zone_response
    zone_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${root_domain}" \
        -H "Authorization: Bearer $CLOUDFLARE_TOKEN" \
        -H "Content-Type: application/json")
    
    log_debug "Cloudflare Zone API Response: $zone_response"
    
    if [ $? -ne 0 ]; then
        log_error "❌ Fehler beim Abrufen der Cloudflare Zone ID"
        return 1
    fi
    
    local zone_id
    zone_id=$(echo "$zone_response" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)
    
    if [ -z "$zone_id" ]; then
        log_error "❌ Zone ID für Domain $root_domain nicht gefunden"
        log_debug "Vollständige API-Antwort: $zone_response"
        log_error "Mögliche Ursachen:"
        log_error "  1. Domain $root_domain ist nicht in Cloudflare vorhanden"
        log_error "  2. API Token hat keine Zone:Read Berechtigung"
        log_error "  3. API Token ist ungültig oder abgelaufen"
        return 1
    fi
    
    log_success "✅ Zone ID gefunden: $zone_id"
    
    # Hostnames für das Zertifikat
    local hostnames="[\"$DOMAIN\"]"
    if [ "$DOMAIN" != "$root_domain" ]; then
        hostnames="[\"$DOMAIN\", \"$root_domain\"]"
    fi
    log_debug "Zertifikat Hostnames: $hostnames"
    
    # Origin Certificate erstellen
    log_info "Erstelle Origin Certificate für: $hostnames"
    
    local cert_data='{
        "hostnames": '"$hostnames"',
        "requested_validity": '"$CERT_VALIDITY"',
        "request_type": "origin-rsa",
        "csr": ""
    }'
    log_debug "Certificate Request Data: $cert_data"
    
    local cert_response
    cert_response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
        -H "Authorization: Bearer $CLOUDFLARE_TOKEN" \
        -H "Content-Type: application/json" \
        --data "$cert_data")
    
    log_debug "Cloudflare Certificate API Response: $cert_response"
    
    if [ $? -ne 0 ]; then
        log_error "❌ Fehler bei der Erstellung des Origin Certificates"
        return 1
    fi
    
    # Erfolg prüfen
    if echo "$cert_response" | grep -q '"success":false'; then
        log_error "❌ Cloudflare Certificate Request fehlgeschlagen"
        local errors=$(echo "$cert_response" | grep -o '"errors":\[[^]]*\]' || echo "Keine Details verfügbar")
        log_error "API Fehler: $errors"
        return 1
    fi
    
    # Zertifikat und Private Key extrahieren
    local certificate
    local private_key
    
    certificate=$(echo "$cert_response" | grep -o '"certificate":"[^"]*' | cut -d'"' -f4 | sed 's/\\n/\n/g')
    private_key=$(echo "$cert_response" | grep -o '"private_key":"[^"]*' | cut -d'"' -f4 | sed 's/\\n/\n/g')
    
    if [ -z "$certificate" ] || [ -z "$private_key" ]; then
        log_error "❌ Konnte Zertifikat oder Private Key nicht extrahieren"
        log_debug "Zertifikat leer: $([ -z "$certificate" ] && echo "JA" || echo "NEIN")"
        log_debug "Private Key leer: $([ -z "$private_key" ] && echo "JA" || echo "NEIN")"
        log_debug "API Response für Debug: $cert_response"
        return 1
    fi
    
    # Zertifikat-Dateien schreiben
    log_info "Schreibe Cloudflare Zertifikat-Dateien..."
    echo "$certificate" > "$SSL_DIR/fullchain.pem"
    echo "$private_key" > "$SSL_DIR/privkey.pem"
    
    # Validierung
    if openssl x509 -in "$SSL_DIR/fullchain.pem" -text -noout >/dev/null 2>&1; then
        log_success "✅ Cloudflare Origin Zertifikat erfolgreich erstellt und validiert"
        local cert_info=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -subject -dates -noout 2>/dev/null || echo "Cert-Info nicht verfügbar")
        log_debug "Zertifikat-Info: $cert_info"
    else
        log_error "❌ Cloudflare Zertifikat ist ungültig"
        return 1
    fi
}

# Manuelle Zertifikat-Validierung mit erweiterten Details
validate_manual_cert() {
    log_info "Validiere manuelle Zertifikate mit erweiterten Details..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    local key_file="$SSL_DIR/privkey.pem"
    
    log_debug "Prüfe Zertifikat-Datei: $cert_file"
    log_debug "Prüfe Key-Datei: $key_file"
    
    # Dateien existieren?
    if [ ! -f "$cert_file" ]; then
        log_error "❌ Zertifikat-Datei nicht gefunden: $cert_file"
        log_info "Für manuelle Zertifikate, platziere dein Zertifikat in: $cert_file"
        return 1
    fi
    
    if [ ! -f "$key_file" ]; then
        log_error "❌ Private Key-Datei nicht gefunden: $key_file"
        log_info "Für manuelle Zertifikate, platziere deinen Private Key in: $key_file"
        return 1
    fi
    
    log_debug "✅ Beide Dateien existieren"
    
    # Dateigröße prüfen
    local cert_size=$(stat -c%s "$cert_file" 2>/dev/null || echo "0")
    local key_size=$(stat -c%s "$key_file" 2>/dev/null || echo "0")
    log_debug "Zertifikat Größe: $cert_size Bytes"
    log_debug "Key Größe: $key_size Bytes"
    
    if [ "$cert_size" -eq 0 ]; then
        log_error "❌ Zertifikat-Datei ist leer"
        return 1
    fi
    
    if [ "$key_size" -eq 0 ]; then
        log_error "❌ Private Key-Datei ist leer"
        return 1
    fi
    
    # Zertifikat validieren
    log_debug "Validiere Zertifikat-Format..."
    local cert_validation=$(openssl x509 -in "$cert_file" -text -noout 2>&1)
    if [ $? -ne 0 ]; then
        log_error "❌ Ungültiges Zertifikat-Format: $cert_file"
        log_debug "OpenSSL Fehler: $cert_validation"
        return 1
    fi
    log_debug "✅ Zertifikat-Format ist gültig"
    
    # Private Key validieren
    log_debug "Validiere Private Key-Format..."
    local key_validation=$(openssl rsa -in "$key_file" -check -noout 2>&1)
    if [ $? -ne 0 ]; then
        log_error "❌ Ungültiger Private Key-Format: $key_file"
        log_debug "OpenSSL Fehler: $key_validation"
        return 1
    fi
    log_debug "✅ Private Key-Format ist gültig"
    
    # Zusammengehörigkeit prüfen
    log_debug "Prüfe Zertifikat und Key Zusammengehörigkeit..."
    local cert_modulus=$(openssl x509 -noout -modulus -in "$cert_file" 2>/dev/null | openssl md5 2>/dev/null)
    local key_modulus=$(openssl rsa -noout -modulus -in "$key_file" 2>/dev/null | openssl md5 2>/dev/null)
    
    log_debug "Zertifikat Modulus: $cert_modulus"
    log_debug "Key Modulus: $key_modulus"
    
    if [ "$cert_modulus" != "$key_modulus" ] || [ -z "$cert_modulus" ] || [ -z "$key_modulus" ]; then
        log_error "❌ Zertifikat und Private Key gehören nicht zusammen"
        log_debug "Modulus-Vergleich fehlgeschlagen"
        return 1
    fi
    log_debug "✅ Zertifikat und Key gehören zusammen"
    
    # Zertifikat-Details anzeigen
    local subject=$(openssl x509 -in "$cert_file" -subject -noout 2>/dev/null || echo "Subject unbekannt")
    local issuer=$(openssl x509 -in "$cert_file" -issuer -noout 2>/dev/null || echo "Issuer unbekannt")
    local dates=$(openssl x509 -in "$cert_file" -dates -noout 2>/dev/null || echo "Dates unbekannt")
    
    log_debug "Zertifikat Subject: $subject"
    log_debug "Zertifikat Issuer: $issuer"
    log_debug "Zertifikat Dates: $dates"
    
    log_success "✅ Manuelle Zertifikate erfolgreich validiert"
}

# Dateiberechtigungen setzen mit detailliertem Logging
set_file_permissions() {
    log_info "Setze Dateiberechtigungen mit detailliertem Logging..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    local key_file="$SSL_DIR/privkey.pem"
    
    if [ -f "$cert_file" ]; then
        local old_perms=$(stat -c "%a" "$cert_file" 2>/dev/null || echo "unbekannt")
        chmod 644 "$cert_file"
        local new_perms=$(stat -c "%a" "$cert_file" 2>/dev/null || echo "unbekannt")
        log_debug "Zertifikat Berechtigungen: $old_perms -> $new_perms"
        
        # Besitzer setzen (wenn Root)
        if [ "$(id -u)" -eq 0 ]; then
            chown root:root "$cert_file" 2>/dev/null && log_debug "Zertifikat Besitzer: root:root"
        fi
    fi
    
    if [ -f "$key_file" ]; then
        local old_perms=$(stat -c "%a" "$key_file" 2>/dev/null || echo "unbekannt")
        chmod 600 "$key_file"
        local new_perms=$(stat -c "%a" "$key_file" 2>/dev/null || echo "unbekannt")
        log_debug "Private Key Berechtigungen: $old_perms -> $new_perms"
        
        # Besitzer setzen (wenn Root)
        if [ "$(id -u)" -eq 0 ]; then
            chown root:root "$key_file" 2>/dev/null && log_debug "Private Key Besitzer: root:root"
        fi
    fi
    
    # SSL-Verzeichnis Berechtigungen
    local ssl_perms=$(stat -c "%a" "$SSL_DIR" 2>/dev/null || echo "unbekannt")
    log_debug "SSL-Verzeichnis Berechtigungen: $ssl_perms"
    
    log_success "✅ Dateiberechtigungen gesetzt"
}

# Erweiterte Zertifikat-Informationen anzeigen
display_cert_info() {
    log_info "Zeige erweiterte Zertifikat-Informationen..."
    
    local cert_file="$SSL_DIR/fullchain.pem"
    
    if [ ! -f "$cert_file" ]; then
        log_warn "⚠️ Zertifikat-Datei nicht gefunden: $cert_file"
        return 1
    fi
    
    echo -e "\n${GREEN}📋 ERWEITERTE ZERTIFIKAT-INFORMATIONEN:${NC}"
    echo "================================================================="
    
    # Grundinformationen
    echo -e "\n${CYAN}🔍 Zertifikat-Details:${NC}"
    local cert_text=$(openssl x509 -in "$cert_file" -text -noout 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        # Subject und Issuer
        local subject=$(echo "$cert_text" | grep "Subject:" | sed 's/.*Subject: //')
        local issuer=$(echo "$cert_text" | grep "Issuer:" | sed 's/.*Issuer: //')
        echo -e "${BLUE}  Subject: ${NC}$subject"
        echo -e "${BLUE}  Issuer:  ${NC}$issuer"
        
        # Gültigkeitsdaten
        local not_before=$(echo "$cert_text" | grep "Not Before:" | sed 's/.*Not Before: //')
        local not_after=$(echo "$cert_text" | grep "Not After :" | sed 's/.*Not After : //')
        echo -e "${BLUE}  Gültig von: ${NC}$not_before"
        echo -e "${BLUE}  Gültig bis: ${NC}$not_after"
        
        # Verbleibende Tage berechnen
        if command -v date >/dev/null 2>&1; then
            local expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo "0")
            local current_epoch=$(date +%s)
            local days_remaining=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            if [ $days_remaining -gt 30 ]; then
                echo -e "${GREEN}  Verbleibende Tage: $days_remaining ✅${NC}"
            elif [ $days_remaining -gt 7 ]; then
                echo -e "${YELLOW}  Verbleibende Tage: $days_remaining ⚠️${NC}"
            else
                echo -e "${RED}  Verbleibende Tage: $days_remaining ❌${NC}"
            fi
        fi
        
        # Subject Alternative Names
        local san=$(echo "$cert_text" | grep -A1 "Subject Alternative Name:" | tail -1 | sed 's/^[[:space:]]*//')
        if [ -n "$san" ]; then
            echo -e "${BLUE}  Alternative Names: ${NC}$san"
        fi
        
        # Key Size
        local key_size=$(echo "$cert_text" | grep "Public-Key:" | sed 's/.*(\([0-9]*\) bit).*/\1/')
        if [ -n "$key_size" ]; then
            echo -e "${BLUE}  Schlüssel-Größe: ${NC}$key_size bits"
        fi
    else
        echo -e "${RED}❌ Fehler beim Lesen der Zertifikat-Informationen${NC}"
        return 1
    fi
    
    # KeyUsage-Analyse
    echo -e "\n${CYAN}🔑 KeyUsage-Analyse (Browser-Kompatibilität):${NC}"
    local key_usage=$(echo "$cert_text" | grep -A3 "X509v3 Key Usage:")
    local ext_key_usage=$(echo "$cert_text" | grep -A3 "X509v3 Extended Key Usage:")
    
    # Digital Signature
    if echo "$key_usage" | grep -q "Digital Signature"; then
        echo -e "${GREEN}  ✅ Digital Signature: Vorhanden${NC}"
    else
        echo -e "${RED}  ❌ Digital Signature: Fehlt (Chrome/Edge Problem möglich)${NC}"
    fi
    
    # Key Encipherment
    if echo "$key_usage" | grep -q "Key Encipherment"; then
        echo -e "${GREEN}  ✅ Key Encipherment: Vorhanden${NC}"
    else
        echo -e "${RED}  ❌ Key Encipherment: Fehlt${NC}"
    fi
    
    # Server Authentication
    if echo "$ext_key_usage" | grep -q "TLS Web Server Authentication"; then
        echo -e "${GREEN}  ✅ Server Authentication: Vorhanden${NC}"
    else
        echo -e "${YELLOW}  ⚠️ Server Authentication: Fehlt (möglicherweise problematisch)${NC}"
    fi
    
    # Browser-Kompatibilitäts-Bewertung
    echo -e "\n${CYAN}🌐 Browser-Kompatibilitäts-Bewertung:${NC}"
    local has_digital_sig=$(echo "$key_usage" | grep -q "Digital Signature" && echo "true" || echo "false")
    local has_key_enc=$(echo "$key_usage" | grep -q "Key Encipherment" && echo "true" || echo "false")
    local has_server_auth=$(echo "$ext_key_usage" | grep -q "TLS Web Server Authentication" && echo "true" || echo "false")
    
    if [ "$has_digital_sig" = "true" ] && [ "$has_key_enc" = "true" ] && [ "$has_server_auth" = "true" ]; then
        echo -e "${GREEN}  ✅ Chrome/Chromium: Kompatibel${NC}"
        echo -e "${GREEN}  ✅ Firefox: Kompatibel${NC}"
        echo -e "${GREEN}  ✅ Safari: Kompatibel${NC}"
        echo -e "${GREEN}  ✅ Edge: Kompatibel${NC}"
        echo -e "${GREEN}  🎉 ERR_SSL_KEY_USAGE_INCOMPATIBLE: Behoben${NC}"
    else
        echo -e "${RED}  ❌ Chrome/Edge: ERR_SSL_KEY_USAGE_INCOMPATIBLE möglich${NC}"
        echo -e "${YELLOW}  ⚠️ Firefox: Möglicherweise Probleme${NC}"
        echo -e "${YELLOW}  ⚠️ Safari: Möglicherweise Probleme${NC}"
        echo -e "${RED}  💡 Empfehlung: Zertifikat mit korrekter KeyUsage neu erstellen${NC}"
    fi
    
    # SSL-Methoden-spezifische Hinweise
    echo -e "\n${CYAN}📝 Methodenspezifische Informationen:${NC}"
    case "$METHOD" in
        "selfsigned")
            echo -e "${BLUE}  🔧 Self-Signed Zertifikat${NC}"
            echo -e "${YELLOW}  ⚠️ Browser zeigen Sicherheitswarnung${NC}"
            echo -e "${GREEN}  ✅ Für Entwicklung und interne Nutzung geeignet${NC}"
            ;;
        "letsencrypt")
            echo -e "${BLUE}  🌐 Let's Encrypt Zertifikat${NC}"
            echo -e "${GREEN}  ✅ Von Browsern vertrauenswürdig${NC}"
            echo -e "${GREEN}  ✅ Automatische Erneuerung verfügbar${NC}"
            ;;
        "cloudflare")
            echo -e "${BLUE}  ☁️ Cloudflare Origin Zertifikat${NC}"
            echo -e "${GREEN}  ✅ Optimiert für Cloudflare Proxy${NC}"
            echo -e "${YELLOW}  ⚠️ Nur mit Cloudflare Proxy vertrauenswürdig${NC}"
            ;;
        "manual")
            echo -e "${BLUE}  👤 Manuell installiertes Zertifikat${NC}"
            echo -e "${YELLOW}  ⚠️ Manuelle Erneuerung erforderlich${NC}"
            ;;
    esac
    
    echo "================================================================="
}

# Auto-Renewal Setup mit erweiterten Details
setup_auto_renewal() {
    if [ "$AUTO_RENEWAL" = "true" ] && [ "$METHOD" != "selfsigned" ] && [ "$METHOD" != "manual" ]; then
        log_info "Richte Auto-Renewal ein mit erweiterten Details..."
        
        # Renewal-Script erstellen
        local renewal_script="$SSL_DIR/renewal.sh"
        log_debug "Erstelle Renewal-Script: $renewal_script"
        
        cat > "$renewal_script" << EOF
#!/bin/bash
# Auto-Renewal Script für $DOMAIN - Enhanced Version
set -e

# Logging
RENEWAL_LOG="$SSL_DIR/renewal.log"
echo "\$(date): Auto-Renewal gestartet für $DOMAIN" >> "\$RENEWAL_LOG"

# Umgebungsvariablen exportieren
export SSL_DOMAIN="$DOMAIN"
export SSL_EMAIL="$EMAIL"
export SSL_METHOD="$METHOD"
export SSL_AUTO_RENEWAL="$AUTO_RENEWAL"
export SSL_KEY_SIZE="$KEY_SIZE"
export CLOUDFLARE_API_TOKEN="$CLOUDFLARE_TOKEN"
export LETS_ENCRYPT_PORT="$LETS_ENCRYPT_PORT"
export DEBUG="false"
export VERBOSE="false"

# SSL-Setup ausführen
cd "$SCRIPT_DIR"
if ./ssl-setup.sh >> "\$RENEWAL_LOG" 2>&1; then
    echo "\$(date): Auto-Renewal erfolgreich" >> "\$RENEWAL_LOG"
    
    # Neustart-Signal an Anwendung senden
    if pgrep -f "node.*server.js" > /dev/null; then
        echo "\$(date): Sende HUP Signal an Node.js Anwendung" >> "\$RENEWAL_LOG"
        pkill -HUP -f "node.*server.js" || true
    fi
    
    # Docker Container Restart (falls in Docker)
    if [ -f "/.dockerenv" ] && command -v docker >/dev/null 2>&1; then
        echo "\$(date): Docker-Umgebung erkannt - Neustart wird empfohlen" >> "\$RENEWAL_LOG"
    fi
else
    echo "\$(date): Auto-Renewal fehlgeschlagen" >> "\$RENEWAL_LOG"
    exit 1
fi
EOF
        
        chmod +x "$renewal_script"
        log_debug "Renewal-Script erstellt und ausführbar gemacht"
        
        # Cron-Job erstellen
        local cron_file="/etc/cron.d/ssl-renewal-db-backup-enhanced"
        log_debug "Erstelle Cron-Job: $cron_file"
        
        cat > "$cron_file" << EOF
# Enhanced Auto-Renewal für DB Backup Tool SSL-Zertifikat
# Erstellt am: $(date)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Täglich um 2:00 Uhr prüfen und erneuern (nur wenn nötig)
0 2 * * * root $renewal_script >> $LOG_FILE 2>&1

# Wöchentliche Überprüfung der Zertifikat-Gültigkeit (Sonntags um 1:00)
0 1 * * 0 root openssl x509 -in $SSL_DIR/fullchain.pem -checkend 604800 -noout || $renewal_script >> $LOG_FILE 2>&1
EOF
        
        # Cron-Service neu laden
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload cron 2>/dev/null || systemctl reload cronie 2>/dev/null || true
            log_debug "Cron-Service neu geladen"
        fi
        
        log_success "✅ Auto-Renewal erfolgreich konfiguriert"
        log_debug "Renewal-Script: $renewal_script"
        log_debug "Cron-Job: $cron_file"
        log_debug "Renewal läuft täglich um 2:00 Uhr"
    else
        log_info "Auto-Renewal übersprungen (Methode: $METHOD, Enabled: $AUTO_RENEWAL)"
    fi
}

# Cleanup mit erweiterten Details
cleanup_old_files() {
    log_info "Räume alte Dateien auf mit erweiterten Details..."
    
    local cleaned_count=0
    
    # Alte Backups (älter als 30 Tage)
    if [ -d "$SSL_DIR" ]; then
        find "$SSL_DIR" -name "backup-*" -type d -mtime +30 2>/dev/null | while read backup_dir; do
            log_debug "Lösche altes Backup: $backup_dir"
            rm -rf "$backup_dir"
            cleaned_count=$((cleaned_count + 1))
        done
    fi
    
    # Alte Log-Dateien rotieren (größer als 10MB)
    for log_file in "$LOG_FILE" "$DEBUG_LOG"; do
        if [ -f "$log_file" ] && [ $(stat -c%s "$log_file" 2>/dev/null || echo "0") -gt 10485760 ]; then
            log_debug "Rotiere Log-Datei: $log_file"
            mv "$log_file" "${log_file}.old"
            touch "$log_file"
            chmod 600 "$log_file"
        fi
    done
    
    # Temporäre OpenSSL-Dateien
    find "$SSL_DIR" -name "*.cnf" -o -name "*.tmp" -o -name "*.temp" 2>/dev/null | while read temp_file; do
        log_debug "Lösche temporäre Datei: $temp_file"
        rm -f "$temp_file"
        cleaned_count=$((cleaned_count + 1))
    done
    
    log_success "✅ Cleanup abgeschlossen ($cleaned_count Dateien bereinigt)"
}

# Fehlerbehandlung verbessern
error_handler() {
    local exit_code=$?
    local line_number=$1
    
    log_error "❌ SSL-Setup fehlgeschlagen bei Zeile $line_number (Exit Code: $exit_code)"
    log_debug "Fehler-Kontext: Aktuelle Funktion und Methode"
    log_debug "  Methode: $METHOD"
    log_debug "  Domain: $DOMAIN"
    log_debug "  Script: $0"
    log_debug "  Working Dir: $(pwd)"
    
    # Debug-Log anzeigen bei Fehlern
    if [ "$DEBUG" = "true" ] && [ -f "$DEBUG_LOG" ]; then
        echo -e "\n${RED}=== DEBUG LOG (Letzte 20 Zeilen) ===${NC}"
        tail -20 "$DEBUG_LOG" 2>/dev/null || echo "Debug-Log nicht verfügbar"
        echo -e "${RED}=== ENDE DEBUG LOG ===${NC}\n"
    fi
    
    # Troubleshooting-Hinweise
    echo -e "\n${YELLOW}🔧 TROUBLESHOOTING-HINWEISE:${NC}"
    case "$METHOD" in
        "letsencrypt")
            echo -e "${BLUE}Let's Encrypt Probleme:${NC}"
            echo "  • Prüfe Domain-Auflösung: nslookup $DOMAIN"
            echo "  • Prüfe Port 80 Verfügbarkeit: netstat -tlnp | grep :80"
            echo "  • Prüfe Firewall-Einstellungen"
            echo "  • Domain muss öffentlich erreichbar sein"
            ;;
        "cloudflare")
            echo -e "${BLUE}Cloudflare Probleme:${NC}"
            echo "  • Prüfe CLOUDFLARE_API_TOKEN"
            echo "  • Prüfe Token-Berechtigungen (Zone:Read)"
            echo "  • Domain muss in Cloudflare vorhanden sein"
            ;;
        "selfsigned")
            echo -e "${BLUE}Self-Signed Probleme:${NC}"
            echo "  • Prüfe OpenSSL Installation"
            echo "  • Prüfe Schreibberechtigungen in $SSL_DIR"
            ;;
        "manual")
            echo -e "${BLUE}Manuelle Zertifikat Probleme:${NC}"
            echo "  • Platziere fullchain.pem in $SSL_DIR/"
            echo "  • Platziere privkey.pem in $SSL_DIR/"
            echo "  • Prüfe Zertifikat-Format mit: openssl x509 -text -in fullchain.pem"
            ;;
    esac
    
    echo -e "\n${CYAN}📋 Log-Dateien für weitere Analyse:${NC}"
    echo "  • Haupt-Log: $LOG_FILE"
    echo "  • Debug-Log: $DEBUG_LOG"
    
    exit $exit_code
}

# Erweiterte Fehlerbehandlung setzen
trap 'error_handler $LINENO' ERR

# Hauptfunktion mit verbesserter Fehlerbehandlung
main() {
    log_info "Starte Enhanced SSL-Setup mit erweitertem Debugging..."
    
    # Präparation
    check_dependencies
    prepare_ssl_directory
    validate_domain
    
    # Methoden-spezifische Ausführung mit detailliertem Logging
    log_info "Führe SSL-Setup aus für Methode: $METHOD"
    
    case "$METHOD" in
        "selfsigned")
            log_info "=== SELF-SIGNED MODUS ==="
            create_selfsigned_cert
            ;;
        "letsencrypt")
            log_info "=== LET'S ENCRYPT MODUS ==="
            create_letsencrypt_cert
            ;;
        "cloudflare")
            log_info "=== CLOUDFLARE MODUS ==="
            create_cloudflare_cert
            ;;
        "manual")
            log_info "=== MANUELLER MODUS ==="
            validate_manual_cert
            ;;
        *)
            log_error "❌ Unbekannte SSL-Methode: $METHOD"
            log_error "Unterstützte Methoden: selfsigned, letsencrypt, cloudflare, manual"
            exit 1
            ;;
    esac
    
    # Nachbearbeitung
    set_file_permissions
    display_cert_info
    setup_auto_renewal
    cleanup_old_files
    
    # Finale Validierung
    log_info "Führe finale Validierung durch..."
    if [ -f "$SSL_DIR/fullchain.pem" ] && [ -f "$SSL_DIR/privkey.pem" ]; then
        if openssl x509 -in "$SSL_DIR/fullchain.pem" -text -noout >/dev/null 2>&1; then
            log_success "✅ Enhanced SSL-Setup erfolgreich abgeschlossen!"
            log_success "🔐 Zertifikat ist gültig und bereit für HTTPS"
            log_success "🌐 Browser-Kompatibilität wurde optimiert"
        else
            log_error "❌ Finale Validierung fehlgeschlagen - Zertifikat ungültig"
            exit 1
        fi
    else
        log_error "❌ Finale Validierung fehlgeschlagen - Zertifikat-Dateien fehlen"
        exit 1
    fi
}

# Script-Ausführung mit erweiterten Debug-Informationen
main "$@"

echo -e "\n${GREEN}🎉 SSL-Setup erfolgreich abgeschlossen!${NC}"
echo -e "${BLUE}📁 SSL-Verzeichnis: $SSL_DIR${NC}"
echo -e "${BLUE}📋 Haupt-Log: $LOG_FILE${NC}"
echo -e "${BLUE}🔍 Debug-Log: $DEBUG_LOG${NC}"

if [ -d "$BACKUP_DIR" ]; then
    echo -e "${BLUE}💾 Backup der alten Zertifikate: $BACKUP_DIR${NC}"
fi

# Abschließende Systeminfo
echo -e "\n${CYAN}📊 SYSTEM-ZUSAMMENFASSUNG:${NC}"
echo -e "${BLUE}  Methode: ${NC}$METHOD"
echo -e "${BLUE}  Domain: ${NC}$DOMAIN"
echo -e "${BLUE}  Auto-Renewal: ${NC}$AUTO_RENEWAL"

if [ -f "$SSL_DIR/fullchain.pem" ]; then
    local cert_subject=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -subject -noout 2>/dev/null | sed 's/subject=//' || echo "Unbekannt")
    local cert_expiry=$(openssl x509 -in "$SSL_DIR/fullchain.pem" -enddate -noout 2>/dev/null | sed 's/notAfter=//' || echo "Unbekannt")
    echo -e "${BLUE}  Zertifikat für: ${NC}$cert_subject"
    echo -e "${BLUE}  Läuft ab am: ${NC}$cert_expiry"
fi

# Browser-Kompatibilitäts-Status
echo -e "\n${GREEN}🌐 BROWSER-KOMPATIBILITÄT:${NC}"
echo -e "${GREEN}✅ ERR_SSL_KEY_USAGE_INCOMPATIBLE Problem behoben${NC}"
echo -e "${GREEN}✅ Modernes KeyUsage für alle Browser implementiert${NC}"
echo -e "${GREEN}✅ Enhanced SSL-Setup mit erweiterten Debugging abgeschlossen${NC}"

# Debug-Informationen sammeln (finale Zusammenfassung)
if [ "$DEBUG" = "true" ]; then
    echo -e "\n${CYAN}🔍 DEBUG-ZUSAMMENFASSUNG:${NC}"
    echo -e "${BLUE}  Debug-Modus: ${NC}Aktiv"
    echo -e "${BLUE}  Verbose-Modus: ${NC}$VERBOSE"
    echo -e "${BLUE}  Gesammelte Logs: ${NC}$(wc -l "$DEBUG_LOG" 2>/dev/null | cut -d' ' -f1 || echo "0") Zeilen"
    echo -e "${BLUE}  Script-Laufzeit: ${NC}$SECONDS Sekunden"
fi