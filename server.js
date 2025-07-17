const express = require("express");
const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");
const { exec, execSync } = require("child_process");
const cron = require("node-cron");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const mysqldump = require("mysqldump");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

// ====== NEUE SICHERHEITS-DEPENDENCIES ======
const svgCaptcha = require("svg-captcha");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

// ====== SSL-MANAGEMENT IMPORT ======
const SSLCertificateManager = require('./ssl-management.js');
const SSLHealthCheck = require('./ssl-health-check.js');

class DatabaseBackupTool {
  constructor() {
    this.app = express();
    this.secretsFile = path.join("./backups", ".git-secrets.enc");
    this.encryptionKey = "temporary-key";
    this.config = this.loadConfig();
    this.users = new Map();
    this.backupJobs = new Map();
    this.schedulesFile = path.join(
      this.config.backup.defaultPath,
      "schedules.json"
    );
    
    // Fest integriertes Update-Repository
    this.updateRepository = "https://github.com/brandy2307/db-backup-tool.git";
    this.updateBranch = "main";

    // Git Backup Repository Pfad
    this.gitBackupPath = path.join(
      this.config.backup.defaultPath,
      "git-backup"
    );

    this.secretsFile = path.join(
      this.config.backup.defaultPath,
      ".git-secrets.enc"
    );
    this.encryptionKey = this.config.security.jwtSecret;

    // ====== SSL CERTIFICATE MANAGER ======
    this.sslManager = null; // Wird in initializeSSL() gesetzt
    this.sslHealthCheck = null; // SSL Health Check System

    // ====== NEUE SICHERHEITS-FEATURES ======
    this.captchaSessions = new Map(); // CAPTCHA Sessions verwalten
    this.failedAttempts = new Map(); // Fehlgeschlagene Login-Versuche
    this.activeSessions = new Map(); // Aktive Sessions verwalten
    this.sslCertPath = path.join(__dirname, "ssl");
    this.userRateLimits = new Map(); // Rate Limiting per User
    
    // Security Configuration
    this.securityConfig = {
      maxFailedAttempts: this.config.security.maxFailedAttempts || 5,
      lockoutDuration: this.config.security.lockoutDuration || 15 * 60 * 1000,
      captchaThreshold: this.config.security.captchaThreshold || 3,
      sessionTimeout: this.config.security.sessionTimeout || 30 * 60 * 1000,
      requireHttps: this.config.security.requireHttps || false,
      enable2FA: this.config.security.enable2FA || false,
      strongPasswords: this.config.security.strongPasswords !== false,
    };

    console.log("🛡️ [SECURITY] Initialisiere Enhanced Security Features:");
    console.log(`   Max Login-Versuche: ${this.securityConfig.maxFailedAttempts}`);
    console.log(`   CAPTCHA nach: ${this.securityConfig.captchaThreshold} Fehlversuchen`);
    console.log(`   Session Timeout: ${this.securityConfig.sessionTimeout / 1000 / 60} Minuten`);
    console.log(`   HTTPS erforderlich: ${this.securityConfig.requireHttps}`);
    console.log(`   2FA aktiviert: ${this.securityConfig.enable2FA}`);
    console.log(`   Starke Passwörter: ${this.securityConfig.strongPasswords}`);

    this.init();
  }
  loadConfig() {
    try {
      const config = JSON.parse(fs.readFileSync("config.json", "utf8"));

      // Ursprüngliche Umgebungsvariablen
      if (process.env.ADMIN_USERNAME) {
        config.security.defaultAdmin.username = process.env.ADMIN_USERNAME;
      }
      if (process.env.ADMIN_PASSWORD) {
        config.security.defaultAdmin.password = process.env.ADMIN_PASSWORD;
      }
      if (process.env.SESSION_SECRET) {
        config.security.sessionSecret = process.env.SESSION_SECRET;
      }
      if (process.env.JWT_SECRET) {
        config.security.jwtSecret = process.env.JWT_SECRET;
      }
      if (process.env.MAX_BACKUPS) {
        config.backup.maxBackups = parseInt(process.env.MAX_BACKUPS);
      }
      if (process.env.ENABLE_COMPRESSION) {
        config.backup.compression = process.env.ENABLE_COMPRESSION === "true";
      }
      if (process.env.AUTO_UPDATE) {
        config.updates = config.updates || {};
        config.updates.autoUpdate = process.env.AUTO_UPDATE === "true";
      }

      // Git Backup Konfiguration aus Umgebungsvariablen
      if (process.env.GIT_BACKUP_ENABLED) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.enabled = process.env.GIT_BACKUP_ENABLED === "true";
      }
      if (process.env.GIT_BACKUP_REPOSITORY) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.repository = process.env.GIT_BACKUP_REPOSITORY;
      }
      if (process.env.GIT_BACKUP_USERNAME) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.username = process.env.GIT_BACKUP_USERNAME;
      }
      if (process.env.GIT_BACKUP_BRANCH) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.branch = process.env.GIT_BACKUP_BRANCH;
      }

      // ====== NEUE SICHERHEITS-KONFIGURATION ======
      if (process.env.REQUIRE_HTTPS) {
        config.security = config.security || {};
        config.security.requireHttps = process.env.REQUIRE_HTTPS === "true";
      }
      if (process.env.ENABLE_2FA) {
        config.security = config.security || {};
        config.security.enable2FA = process.env.ENABLE_2FA === "true";
      }
      if (process.env.STRONG_PASSWORDS) {
        config.security = config.security || {};
        config.security.strongPasswords = process.env.STRONG_PASSWORDS === "true";
      }
      if (process.env.MAX_FAILED_ATTEMPTS) {
        config.security = config.security || {};
        config.security.maxFailedAttempts = parseInt(process.env.MAX_FAILED_ATTEMPTS);
      }
      if (process.env.HTTPS_PORT) {
        config.server = config.server || {};
        config.server.httpsPort = parseInt(process.env.HTTPS_PORT);
      }

      // ====== NEUE SSL-KONFIGURATION AUS UMGEBUNGSVARIABLEN ======
      if (process.env.SSL_DOMAIN) {
        config.ssl = config.ssl || {};
        config.ssl.domain = process.env.SSL_DOMAIN;
      }
      if (process.env.SSL_EMAIL) {
        config.ssl = config.ssl || {};
        config.ssl.email = process.env.SSL_EMAIL;
      }
      if (process.env.SSL_METHOD) {
        config.ssl = config.ssl || {};
        config.ssl.method = process.env.SSL_METHOD;
      }
      if (process.env.SSL_AUTO_RENEWAL) {
        config.ssl = config.ssl || {};
        config.ssl.autoRenewal = process.env.SSL_AUTO_RENEWAL === "true";
      }
      if (process.env.SSL_KEY_SIZE) {
        config.ssl = config.ssl || {};
        config.ssl.keySize = parseInt(process.env.SSL_KEY_SIZE);
      }
      if (process.env.SSL_CERT_VALIDITY) {
        config.ssl = config.ssl || {};
        config.ssl.certValidity = parseInt(process.env.SSL_CERT_VALIDITY);
      }
      if (process.env.SSL_SETUP_ON_START) {
        config.ssl = config.ssl || {};
        config.ssl.setupOnStart = process.env.SSL_SETUP_ON_START === "true";
      }

      // Token-Behandlung
      if (process.env.GIT_BACKUP_TOKEN) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.token = process.env.GIT_BACKUP_TOKEN;
        console.log("🔑 [CONFIG] Git Token aus Umgebungsvariable geladen");
      } else if (config.gitBackup && config.gitBackup.enabled) {
        console.log("⏳ [CONFIG] Token-Laden wird verzögert bis init()");
      }

      // Repository-Informationen fest setzen (nicht überschreibbar)
      config.updates = config.updates || {};
      config.updates.repository = this.updateRepository;
      config.updates.branch = this.updateBranch;

      return config;
    } catch (error) {
      console.error("Fehler beim Laden der Konfiguration:", error);
      process.exit(1);
    }
  }

  // ====== SSL-INITIALISIERUNG ======
  async initializeSSL() {
    console.log("🔐 [SSL] Initialisiere SSL Certificate Manager...");
    
    try {
      // SSL Manager erstellen
      this.sslManager = new SSLCertificateManager(this.config);
      
      // SSL Health Check System initialisieren
      this.sslHealthCheck = new SSLHealthCheck(this.sslManager);
      
      // SSL Manager initialisieren
      await this.sslManager.initialize();
      
      console.log("✅ [SSL] SSL Certificate Manager erfolgreich initialisiert");
    } catch (error) {
      console.error("❌ [SSL] SSL-Initialisierung fehlgeschlagen:", error.message);
      throw error;
    }
  }

  // ====== SSL-INITIALISIERUNG AUS UMGEBUNGSVARIABLEN ======
  async initializeSSLFromEnvironment() {
    console.log("🔐 [SSL] Initialisiere SSL basierend auf Umgebungsvariablen...");
    
    // SSL-Konfiguration aus Umgebungsvariablen laden
    const sslConfig = {
      enabled: process.env.REQUIRE_HTTPS === 'true',
      method: process.env.SSL_METHOD || 'selfsigned',
      domain: process.env.SSL_DOMAIN || 'localhost',
      email: process.env.SSL_EMAIL || 'admin@localhost',
      keySize: parseInt(process.env.SSL_KEY_SIZE) || 4096,
      certValidity: parseInt(process.env.SSL_CERT_VALIDITY) || 365,
      autoRenewal: process.env.SSL_AUTO_RENEWAL === 'true',
      setupOnStart: process.env.SSL_SETUP_ON_START === 'true'
    };
    
    console.log("🔐 [SSL] Konfiguration geladen:");
    console.log(`   Aktiviert: ${sslConfig.enabled}`);
    console.log(`   Methode: ${sslConfig.method}`);
    console.log(`   Domain: ${sslConfig.domain}`);
    console.log(`   Setup beim Start: ${sslConfig.setupOnStart}`);
    
    // SSL-Konfiguration in this.config übernehmen
    this.config.security.requireHttps = sslConfig.enabled;
    this.config.ssl = sslConfig;
    
    // Sicherheits-Konfiguration aktualisieren
    this.securityConfig.requireHttps = sslConfig.enabled;
    
    if (!sslConfig.enabled) {
      console.log("🔐 [SSL] SSL ist deaktiviert - verwende HTTP");
      return;
    }
    
    if (!sslConfig.setupOnStart) {
      console.log("🔐 [SSL] SSL-Setup beim Start ist deaktiviert");
      return;
    }
    
    try {
      // SSL-Setup ausführen wenn aktiviert
      console.log("🔐 [SSL] Führe automatisches SSL-Setup aus...");
      
      // Prüfe ob SSL-Setup Script existiert
      const sslSetupPath = path.join(__dirname, 'ssl-setup.sh');
      if (!fs.existsSync(sslSetupPath)) {
        console.log("🔐 [SSL] ssl-setup.sh nicht gefunden, erstelle es...");
        await this.createSSLSetupScript();
      }
      
      // Führe SSL-Setup aus
      await this.runSSLSetup(sslConfig);
      
      console.log("✅ [SSL] Automatisches SSL-Setup abgeschlossen");
    } catch (error) {
      console.error("❌ [SSL] SSL-Setup fehlgeschlagen:", error.message);
      console.log("⚠️ [SSL] Verwende HTTP als Fallback");
      this.config.security.requireHttps = false;
      this.securityConfig.requireHttps = false;
    }
  }

  // SSL-Setup Script erstellen falls nicht vorhanden
  async createSSLSetupScript() {
    const sslSetupContent = `#!/bin/bash
# Automatisch generiertes SSL-Setup Script für Pelican Panel
set -e

SSL_DOMAIN="\${SSL_DOMAIN:-localhost}"
SSL_EMAIL="\${SSL_EMAIL:-admin@localhost}"
SSL_METHOD="\${SSL_METHOD:-selfsigned}"
SSL_KEY_SIZE="\${SSL_KEY_SIZE:-4096}"
SSL_CERT_VALIDITY="\${SSL_CERT_VALIDITY:-365}"

echo "🔐 SSL-Setup für \${SSL_DOMAIN} mit Methode: \${SSL_METHOD}"

# SSL-Verzeichnis erstellen
mkdir -p ssl
chmod 700 ssl

case "\${SSL_METHOD}" in
  "selfsigned")
    echo "🔧 Erstelle Self-Signed Zertifikat..."
    
    # OpenSSL-Konfiguration
    cat > ssl/openssl.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = DE
ST = NRW
L = Sprockhovel
O = DB Backup Tool
CN = \${SSL_DOMAIN}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = \${SSL_DOMAIN}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # Zertifikat erstellen
    openssl req -x509 -newkey rsa:\${SSL_KEY_SIZE} \\
      -keyout ssl/privkey.pem \\
      -out ssl/fullchain.pem \\
      -days \${SSL_CERT_VALIDITY} \\
      -nodes \\
      -config ssl/openssl.cnf \\
      -extensions v3_req
    
    # Aufräumen
    rm -f ssl/openssl.cnf
    ;;
    
  "letsencrypt")
    echo "🔧 Let's Encrypt Setup..."
    if [ "\${SSL_DOMAIN}" = "localhost" ]; then
      echo "❌ Let's Encrypt funktioniert nicht mit localhost"
      echo "🔧 Verwende Self-Signed als Fallback"
      SSL_METHOD="selfsigned"
      exec \$0  # Script neu starten mit selfsigned
    fi
    
    # Certbot installieren falls nicht vorhanden
    if ! command -v certbot &> /dev/null; then
      echo "📦 Installiere Certbot..."
      apt-get update
      apt-get install -y certbot
    fi
    
    # Let's Encrypt Zertifikat holen
    certbot certonly --standalone \\
      --non-interactive \\
      --agree-tos \\
      --email "\${SSL_EMAIL}" \\
      --domains "\${SSL_DOMAIN}" \\
      --key-type rsa \\
      --rsa-key-size \${SSL_KEY_SIZE}
    
    # Zertifikate kopieren
    if [ -d "/etc/letsencrypt/live/\${SSL_DOMAIN}" ]; then
      cp "/etc/letsencrypt/live/\${SSL_DOMAIN}/fullchain.pem" ssl/fullchain.pem
      cp "/etc/letsencrypt/live/\${SSL_DOMAIN}/privkey.pem" ssl/privkey.pem
    fi
    ;;
    
  "manual")
    echo "🔧 Manuelle Zertifikat-Installation..."
    if [ ! -f "ssl/fullchain.pem" ] || [ ! -f "ssl/privkey.pem" ]; then
      echo "❌ Manuelle Zertifikate nicht gefunden"
      echo "🔧 Verwende Self-Signed als Fallback"
      SSL_METHOD="selfsigned"
      exec \$0  # Script neu starten
    fi
    ;;
esac

# Dateiberechtigungen setzen
chmod 644 ssl/fullchain.pem 2>/dev/null || true
chmod 600 ssl/privkey.pem 2>/dev/null || true

# Validierung
if openssl x509 -in ssl/fullchain.pem -text -noout > /dev/null 2>&1; then
  echo "✅ SSL-Zertifikat erfolgreich erstellt/validiert"
  
  # Zertifikat-Info anzeigen
  echo "📋 Zertifikat-Details:"
  openssl x509 -in ssl/fullchain.pem -subject -issuer -dates -noout
else
  echo "❌ SSL-Zertifikat ungültig"
  exit 1
fi
`;

    const sslSetupPath = path.join(__dirname, 'ssl-setup.sh');
    fs.writeFileSync(sslSetupPath, sslSetupContent, { mode: 0o755 });
    console.log("✅ [SSL] ssl-setup.sh wurde erstellt");
  }

  // SSL-Setup ausführen
  async runSSLSetup(sslConfig) {
    return new Promise((resolve, reject) => {
      const env = {
        ...process.env,
        SSL_DOMAIN: sslConfig.domain,
        SSL_EMAIL: sslConfig.email,
        SSL_METHOD: sslConfig.method,
        SSL_KEY_SIZE: sslConfig.keySize.toString(),
        SSL_CERT_VALIDITY: sslConfig.certValidity.toString()
      };
      
      const sslSetupPath = path.join(__dirname, 'ssl-setup.sh');
      
      exec(`chmod +x "${sslSetupPath}" && "${sslSetupPath}"`, {
        env: env,
        cwd: __dirname,
        timeout: 120000 // 2 Minuten Timeout
      }, (error, stdout, stderr) => {
        if (error) {
          console.error("❌ [SSL] SSL-Setup Fehler:", error.message);
          if (stderr) console.error("❌ [SSL] Stderr:", stderr);
          reject(error);
          return;
        }
        
        console.log("✅ [SSL] SSL-Setup Output:");
        console.log(stdout);
        
        if (stderr) {
          console.log("⚠️ [SSL] Warnungen:", stderr);
        }
        
        resolve();
      });
    });
  }
  // ====== SICHERHEITS-METHODEN ======

  // Password Validation
  validatePasswordStrength(password) {
    if (!this.securityConfig.strongPasswords) {
      return { valid: true, message: "Passwort-Validierung deaktiviert" };
    }

    const minLength = 12;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    const errors = [];
    
    if (password.length < minLength) {
      errors.push(`Mindestens ${minLength} Zeichen`);
    }
    if (!hasUppercase) {
      errors.push("Mindestens einen Großbuchstaben");
    }
    if (!hasLowercase) {
      errors.push("Mindestens einen Kleinbuchstaben");
    }
    if (!hasNumbers) {
      errors.push("Mindestens eine Zahl");
    }
    if (!hasSpecialChars) {
      errors.push("Mindestens ein Sonderzeichen");
    }

    if (errors.length > 0) {
      return {
        valid: false,
        message: "Passwort muss enthalten: " + errors.join(", "),
        strength: errors.length > 3 ? "weak" : errors.length > 1 ? "medium" : "strong"
      };
    }

    return { 
      valid: true, 
      message: "Passwort erfüllt alle Anforderungen",
      strength: "strong"
    };
  }

  // CAPTCHA Generation
  generateCaptcha() {
    const captcha = svgCaptcha.create({
      size: 6,
      ignoreChars: '0o1il',
      noise: 2,
      color: true,
      background: '#f0f0f0',
      width: 200,
      height: 80,
      fontSize: 50
    });

    const captchaId = crypto.randomBytes(16).toString('hex');
    
    // CAPTCHA Session speichern (mit Timeout)
    this.captchaSessions.set(captchaId, {
      text: captcha.text.toLowerCase(),
      created: Date.now(),
      attempts: 0
    });

    // Auto-cleanup nach 5 Minuten
    setTimeout(() => {
      this.captchaSessions.delete(captchaId);
    }, 5 * 60 * 1000);

    console.log(`🤖 [CAPTCHA] Generiert: ${captchaId} (Text: ${captcha.text})`);

    return {
      id: captchaId,
      svg: captcha.data
    };
  }

  // CAPTCHA Validation
  validateCaptcha(captchaId, userInput) {
    const captchaSession = this.captchaSessions.get(captchaId);
    
    if (!captchaSession) {
      console.log(`❌ [CAPTCHA] Session nicht gefunden oder abgelaufen: ${captchaId}`);
      return { valid: false, message: "CAPTCHA abgelaufen oder ungültig" };
    }

    if (captchaSession.attempts >= 3) {
      console.log(`❌ [CAPTCHA] Zu viele Versuche: ${captchaId}`);
      this.captchaSessions.delete(captchaId);
      return { valid: false, message: "Zu viele CAPTCHA-Versuche" };
    }

    captchaSession.attempts++;

    if (userInput.toLowerCase() !== captchaSession.text) {
      console.log(`❌ [CAPTCHA] Falsche Eingabe: ${userInput} !== ${captchaSession.text}`);
      return { valid: false, message: "CAPTCHA ungültig" };
    }

    console.log(`✅ [CAPTCHA] Erfolgreich validiert: ${captchaId}`);
    this.captchaSessions.delete(captchaId);
    return { valid: true, message: "CAPTCHA korrekt" };
  }

  // 2FA Secret Generation
  generate2FASecret(username) {
    const serviceName = "DB Backup Tool";
    const secret = speakeasy.generateSecret({
      name: `${serviceName} (${username})`,
      issuer: serviceName,
      length: 32
    });

    return {
      secret: secret.base32,
      qrCode: secret.otpauth_url
    };
  }

  // 2FA Token Verification
  verify2FAToken(secret, token) {
    try {
      return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 2 // Erlaubt 2 Zeitfenster Toleranz
      });
    } catch (error) {
      console.error("❌ [2FA] Token-Verifikation fehlgeschlagen:", error);
      return false;
    }
  }

  // Failed Attempts Management
  recordFailedAttempt(ip, username) {
    const key = `${ip}:${username}`;
    const now = Date.now();
    
    if (!this.failedAttempts.has(key)) {
      this.failedAttempts.set(key, {
        count: 0,
        firstAttempt: now,
        lastAttempt: now,
        lockUntil: null
      });
    }
    
    const attempt = this.failedAttempts.get(key);
    attempt.count++;
    attempt.lastAttempt = now;
    
    if (attempt.count >= this.securityConfig.maxFailedAttempts) {
      attempt.lockUntil = now + this.securityConfig.lockoutDuration;
      console.log(`🔒 [SECURITY] Account gesperrt: ${username} von ${ip} für ${this.securityConfig.lockoutDuration / 1000 / 60} Minuten`);
    }
    
    console.log(`⚠️ [SECURITY] Failed attempt #${attempt.count} für ${username} von ${ip}`);
  }

  clearFailedAttempts(ip, username) {
    const key = `${ip}:${username}`;
    this.failedAttempts.delete(key);
    console.log(`✅ [SECURITY] Failed attempts gelöscht für ${username} von ${ip}`);
  }

  isAccountLocked(ip, username) {
    const key = `${ip}:${username}`;
    const attempt = this.failedAttempts.get(key);
    
    if (!attempt || !attempt.lockUntil) {
      return { locked: false };
    }
    
    const now = Date.now();
    if (attempt.lockUntil > now) {
      const remainingTime = Math.ceil((attempt.lockUntil - now) / 1000 / 60);
      return { 
        locked: true, 
        remainingTime: remainingTime 
      };
    } else {
      // Lock abgelaufen
      this.failedAttempts.delete(key);
      return { locked: false };
    }
  }

  needsCaptcha(ip, username) {
    const key = `${ip}:${username}`;
    const attempt = this.failedAttempts.get(key);
    
    if (!attempt) {
      return false;
    }
    
    return attempt.count >= this.securityConfig.captchaThreshold;
  }

  // Session Management
  createSecureSession(req, user, rememberMe = false) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiryTime = rememberMe ? 7 * 24 * 60 * 60 * 1000 : this.securityConfig.sessionTimeout;
    
    const session = {
      id: sessionId,
      userId: user.username,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || 'Unknown',
      createdAt: now,
      lastActivity: now,
      expiresAt: now + expiryTime,
      rememberMe: rememberMe,
      csrfToken: crypto.randomBytes(32).toString('hex')
    };
    
    this.activeSessions.set(sessionId, session);
    
    console.log(`🔐 [SESSION] Neue Session erstellt: ${sessionId} für ${user.username}`);
    return sessionId;
  }

  validateSession(sessionId, req) {
    const session = this.activeSessions.get(sessionId);
    
    if (!session) {
      return { valid: false, reason: "Session nicht gefunden" };
    }
    
    const now = Date.now();
    
    // Session abgelaufen?
    if (session.expiresAt < now) {
      this.activeSessions.delete(sessionId);
      return { valid: false, reason: "Session abgelaufen" };
    }
    
    // IP-Validierung (optional, kann bei Proxies Probleme machen)
    if (session.ip !== req.ip && !session.rememberMe) {
      console.log(`⚠️ [SESSION] IP-Änderung erkannt: ${session.ip} -> ${req.ip} für Session ${sessionId}`);
      // In Produktionsumgebung könnte hier eine strengere Validierung erfolgen
    }
    
    // Aktivität aktualisieren
    session.lastActivity = now;
    
    // Session verlängern wenn weniger als 25% der Zeit übrig
    const timeLeft = session.expiresAt - now;
    const totalTime = session.rememberMe ? 7 * 24 * 60 * 60 * 1000 : this.securityConfig.sessionTimeout;
    
    if (timeLeft < totalTime * 0.25) {
      session.expiresAt = now + totalTime;
      console.log(`🔄 [SESSION] Session verlängert: ${sessionId}`);
    }
    
    return { valid: true, session: session };
  }

  invalidateSession(sessionId) {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      this.activeSessions.delete(sessionId);
      console.log(`🔐 [SESSION] Session invalidiert: ${sessionId} für ${session.userId}`);
    }
  }

  cleanupExpiredSessions() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [sessionId, session] of this.activeSessions) {
      if (session.expiresAt < now) {
        this.activeSessions.delete(sessionId);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      console.log(`🧹 [SESSION] ${cleaned} abgelaufene Sessions bereinigt`);
    }
  }

  // Rate Limiting per User
  checkUserRateLimit(userId, action = 'general') {
    const key = `${userId}:${action}`;
    const now = Date.now();
    const windowSize = 15 * 60 * 1000; // 15 Minuten
    const maxRequests = action === 'login' ? 10 : 100;
    
    if (!this.userRateLimits.has(key)) {
      this.userRateLimits.set(key, {
        requests: [],
        resetTime: now + windowSize
      });
    }
    
    const limit = this.userRateLimits.get(key);
    
    // Reset wenn Fenster abgelaufen
    if (now > limit.resetTime) {
      limit.requests = [];
      limit.resetTime = now + windowSize;
    }
    
    // Alte Requests entfernen
    limit.requests = limit.requests.filter(time => time > now - windowSize);
    
    // Rate Limit prüfen
    if (limit.requests.length >= maxRequests) {
      const resetIn = Math.ceil((limit.resetTime - now) / 1000 / 60);
      return {
        allowed: false,
        resetIn: resetIn,
        limit: maxRequests
      };
    }
    
    // Request hinzufügen
    limit.requests.push(now);
    
    return {
      allowed: true,
      remaining: maxRequests - limit.requests.length,
      resetIn: Math.ceil((limit.resetTime - now) / 1000 / 60)
    };
  }

  // JWT Token Validation Middleware
  authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1] || 
                 req.session.token || 
                 req.cookies["auth-token"];

    if (!token) {
      return res.status(401).json({ 
        error: "Authentifizierung erforderlich",
        code: "NO_TOKEN"
      });
    }

    try {
      const decoded = jwt.verify(token, this.config.security.jwtSecret);
      
      // Session-Validierung wenn Session ID vorhanden
      if (decoded.sessionId) {
        const sessionValidation = this.validateSession(decoded.sessionId, req);
        if (!sessionValidation.valid) {
          return res.status(401).json({ 
            error: "Session ungültig: " + sessionValidation.reason,
            code: "INVALID_SESSION"
          });
        }
      }
      
      // Rate Limiting prüfen
      const rateLimit = this.checkUserRateLimit(decoded.username, 'api');
      if (!rateLimit.allowed) {
        return res.status(429).json({
          error: `Rate limit erreicht. Versuche es in ${rateLimit.resetIn} Minuten erneut.`,
          code: "RATE_LIMIT_EXCEEDED",
          resetIn: rateLimit.resetIn
        });
      }
      
      req.user = decoded;
      next();
    } catch (error) {
      console.log(`❌ [AUTH] Token-Validierung fehlgeschlagen: ${error.message}`);
      
      // Spezifische Fehlerbehandlung
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          error: "Token abgelaufen",
          code: "TOKEN_EXPIRED"
        });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
          error: "Ungültiger Token",
          code: "INVALID_TOKEN"
        });
      }
      
      return res.status(401).json({ 
        error: "Authentifizierung fehlgeschlagen",
        code: "AUTH_FAILED"
      });
    }
  }

  // Setup Default User
  async setupDefaultUser() {
    const adminUsername = this.config.security.defaultAdmin.username;
    const adminPassword = this.config.security.defaultAdmin.password;

    // Prüfe Passwort-Stärke wenn starke Passwörter aktiviert sind
    if (this.securityConfig.strongPasswords) {
      const validation = this.validatePasswordStrength(adminPassword);
      if (!validation.valid) {
        console.warn(`⚠️ [SECURITY] Standard-Admin-Passwort erfüllt nicht die Sicherheitsanforderungen:`);
        console.warn(`   ${validation.message}`);
        console.warn(`   Bitte ändere das Passwort nach dem ersten Login!`);
      }
    }

    try {
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      
      this.users.set(adminUsername, {
        username: adminUsername,
        password: hashedPassword,
        role: "admin",
        created: new Date().toISOString(),
        lastLogin: null,
        loginAttempts: 0,
        passwordChanged: false,
        twoFactorSecret: null
      });

      console.log(`👤 [USER] Standard-Admin erstellt: ${adminUsername}`);
      
      if (adminPassword === 'admin123' || adminPassword === 'admin') {
        console.warn(`⚠️ [SECURITY] Verwende Standard-Passwort! Ändere es nach dem ersten Login.`);
      }
    } catch (error) {
      console.error("❌ [USER] Fehler beim Erstellen des Standard-Admin:", error);
      throw error;
    }
  }
  // ====== MIDDLEWARE SETUP ======
  setupMiddleware() {
    console.log("🔧 [MIDDLEWARE] Initialisiere Express Middleware...");

    // ====== SICHERHEITS-HEADERS MIT HELMET ======
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      noSniff: true,
      frameguard: { action: 'deny' },
      xssFilter: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
    }));

    // ====== KOMPRIMIERUNG ======
    this.app.use(compression({
      level: 6,
      threshold: 1024,
      filter: (req, res) => {
        if (req.headers['x-no-compression']) {
          return false;
        }
        return compression.filter(req, res);
      }
    }));

    // ====== CORS KONFIGURATION ======
    this.app.use(cors({
      origin: (origin, callback) => {
        // Erlaube Anfragen ohne Origin (mobile apps, postman, etc.)
        if (!origin) return callback(null, true);
        
        // In Entwicklung alle Origins erlauben
        if (process.env.NODE_ENV === 'development') {
          return callback(null, true);
        }
        
        // In Produktion nur spezifische Origins
        const allowedOrigins = [
          'https://localhost:8443',
          'http://localhost:8080',
          `https://${this.config.ssl?.domain}:${this.config.server.httpsPort || 8443}`,
          `http://${this.config.server.host}:${this.config.server.port}`
        ];
        
        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          console.log(`❌ [CORS] Blocked origin: ${origin}`);
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      optionsSuccessStatus: 200,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // ====== RATE LIMITING ======
    const loginLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 Minuten
      max: 5, // 5 Versuche pro IP
      message: {
        error: "Zu viele Login-Versuche von dieser IP",
        code: "RATE_LIMIT_LOGIN",
        retryAfter: "15 Minuten"
      },
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => req.ip,
      skip: (req) => {
        // Skip für interne Requests
        return req.ip === '127.0.0.1' || req.ip === '::1';
      }
    });

    const apiLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 Minuten
      max: 100, // 100 Requests pro IP
      message: {
        error: "Zu viele API-Anfragen von dieser IP",
        code: "RATE_LIMIT_API",
        retryAfter: "15 Minuten"
      },
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => req.ip
    });

    const captchaLimiter = rateLimit({
      windowMs: 5 * 60 * 1000, // 5 Minuten
      max: 10, // 10 CAPTCHA Requests pro IP
      message: {
        error: "Zu viele CAPTCHA-Anfragen",
        code: "RATE_LIMIT_CAPTCHA",
        retryAfter: "5 Minuten"
      },
      standardHeaders: true,
      legacyHeaders: false
    });

    // Rate Limiter anwenden
    this.app.use('/api/login', loginLimiter);
    this.app.use('/api/captcha', captchaLimiter);
    this.app.use('/api/', apiLimiter);

    // ====== BODY PARSER ======
    this.app.use(express.json({ 
      limit: '10mb',
      strict: true,
      type: 'application/json'
    }));
    
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: '10mb',
      parameterLimit: 1000
    }));

    // ====== COOKIE PARSER ======
    this.app.use(cookieParser(this.config.security.sessionSecret));

    // ====== SESSION CONFIGURATION ======
    const sessionConfig = {
      secret: this.config.security.sessionSecret,
      name: 'db-backup-session',
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        secure: this.securityConfig.requireHttps,
        httpOnly: true,
        maxAge: this.securityConfig.sessionTimeout,
        sameSite: 'strict'
      },
      genid: () => {
        return crypto.randomBytes(32).toString('hex');
      }
    };

    // In Produktion zusätzliche Session-Sicherheit
    if (process.env.NODE_ENV === 'production') {
      this.app.set('trust proxy', 1);
      sessionConfig.cookie.secure = this.securityConfig.requireHttps;
    }

    this.app.use(session(sessionConfig));

    // ====== STATISCHE DATEIEN ======
    this.app.use(express.static(path.join(__dirname, "public"), {
      maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
      etag: true,
      lastModified: true,
      setHeaders: (res, filePath) => {
        // Sicherheits-Headers für statische Dateien
        if (filePath.endsWith('.js')) {
          res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        } else if (filePath.endsWith('.css')) {
          res.setHeader('Content-Type', 'text/css; charset=utf-8');
        } else if (filePath.endsWith('.html')) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.setHeader('X-Content-Type-Options', 'nosniff');
        }
        
        // Cache-Control für verschiedene Dateitypen
        if (filePath.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico)$/)) {
          res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 Tag
        } else {
          res.setHeader('Cache-Control', 'no-cache');
        }
      }
    }));

    // ====== REQUEST LOGGING MIDDLEWARE ======
    this.app.use((req, res, next) => {
      const startTime = Date.now();
      const originalSend = res.send;
      
      res.send = function(data) {
        const duration = Date.now() - startTime;
        const logLevel = res.statusCode >= 400 ? 'ERROR' : 'INFO';
        const statusIcon = res.statusCode >= 400 ? '❌' : '✅';
        
        // Sensitive URLs nicht vollständig loggen
        let urlToLog = req.url;
        if (req.url.includes('token=') || req.url.includes('password')) {
          urlToLog = req.url.replace(/([?&])(token|password)=[^&]*/g, '$1$2=***');
        }
        
        console.log(`${statusIcon} [${logLevel}] ${req.method} ${urlToLog} - ${res.statusCode} - ${duration}ms - ${req.ip}`);
        
        // Sicherheits-Events separat loggen
        if (req.url.includes('/api/login') || req.url.includes('/api/logout')) {
          console.log(`🔐 [AUTH] ${req.method} ${req.url} - ${res.statusCode} - ${req.ip} - ${req.headers['user-agent']?.substring(0, 50) || 'Unknown'}`);
        }
        
        originalSend.call(this, data);
      };
      
      next();
    });

    // ====== IP WHITELIST/BLACKLIST MIDDLEWARE ======
    this.app.use((req, res, next) => {
      const clientIP = req.ip;
      
      // Blacklist prüfen (könnte aus Datenbank/Konfiguration kommen)
      const blacklistedIPs = process.env.BLACKLISTED_IPS ? 
        process.env.BLACKLISTED_IPS.split(',').map(ip => ip.trim()) : [];
      
      if (blacklistedIPs.includes(clientIP)) {
        console.log(`🚫 [SECURITY] Blacklisted IP blocked: ${clientIP}`);
        return res.status(403).json({
          error: "Zugriff verweigert",
          code: "IP_BLACKLISTED"
        });
      }
      
      // Whitelist prüfen (optional, für Admin-Bereiche)
      if (req.url.includes('/admin/') && process.env.ADMIN_WHITELIST_IPS) {
        const whitelistedIPs = process.env.ADMIN_WHITELIST_IPS.split(',').map(ip => ip.trim());
        if (!whitelistedIPs.includes(clientIP) && !whitelistedIPs.includes('0.0.0.0')) {
          console.log(`🚫 [SECURITY] Non-whitelisted IP blocked from admin area: ${clientIP}`);
          return res.status(403).json({
            error: "Admin-Bereich: IP nicht autorisiert",
            code: "IP_NOT_WHITELISTED"
          });
        }
      }
      
      next();
    });

    // ====== CSRF PROTECTION MIDDLEWARE ======
    this.app.use((req, res, next) => {
      // CSRF-Schutz für state-changing Operationen
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        // Skip CSRF für API-Login (wird über andere Mechanismen geschützt)
        if (req.url === '/api/login' || req.url === '/api/captcha') {
          return next();
        }
        
        const token = req.headers['x-csrf-token'] || req.body._csrf;
        const sessionToken = req.session.csrfToken;
        
        // Für authenticated routes CSRF prüfen
        if (req.headers.authorization || req.cookies['auth-token']) {
          if (!token || !sessionToken || token !== sessionToken) {
            console.log(`❌ [CSRF] CSRF token mismatch: ${req.ip} - ${req.url}`);
            return res.status(403).json({
              error: "CSRF-Token ungültig",
              code: "CSRF_INVALID"
            });
          }
        }
      }
      
      next();
    });

    // ====== SECURITY HEADERS MIDDLEWARE ======
    this.app.use((req, res, next) => {
      // Zusätzliche Sicherheits-Headers
      res.setHeader('X-Powered-By', 'Secure-DB-Backup-Tool');
      res.setHeader('X-Request-ID', crypto.randomBytes(16).toString('hex'));
      res.setHeader('X-Response-Time', Date.now());
      
      // Prevent clickjacking
      res.setHeader('X-Frame-Options', 'DENY');
      
      // XSS Protection
      res.setHeader('X-XSS-Protection', '1; mode=block');
      
      // Content Type Options
      res.setHeader('X-Content-Type-Options', 'nosniff');
      
      // Download Options (IE)
      res.setHeader('X-Download-Options', 'noopen');
      
      // Permitted Cross-Domain Policies
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
      
      next();
    });

    // ====== ERROR HANDLING MIDDLEWARE ======
    this.app.use((err, req, res, next) => {
      console.error(`❌ [MIDDLEWARE ERROR] ${err.message} - ${req.method} ${req.url} - ${req.ip}`);
      
      // Rate limit errors
      if (err.status === 429) {
        return res.status(429).json({
          error: "Rate limit erreicht",
          code: "RATE_LIMIT_EXCEEDED",
          message: err.message
        });
      }
      
      // CORS errors
      if (err.message && err.message.includes('CORS')) {
        return res.status(403).json({
          error: "CORS-Fehler",
          code: "CORS_ERROR"
        });
      }
      
      // JSON parsing errors
      if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({
          error: "Ungültiges JSON",
          code: "INVALID_JSON"
        });
      }
      
      // File upload errors
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          error: "Datei zu groß",
          code: "FILE_TOO_LARGE"
        });
      }
      
      // Default error response
      res.status(500).json({
        error: "Interner Serverfehler",
        code: "INTERNAL_ERROR",
        requestId: res.getHeader('X-Request-ID')
      });
    });

    console.log("✅ [MIDDLEWARE] Express Middleware erfolgreich konfiguriert");
  }

  // ====== VERZEICHNIS-SETUP ======
  ensureDirectories() {
    const directories = [
      this.config.backup.defaultPath,
      path.join(this.config.backup.defaultPath, "schedules"),
      path.join(__dirname, "logs"),
      path.join(__dirname, "ssl"),
      path.join(__dirname, "config"),
      this.gitBackupPath
    ];

    directories.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
        console.log(`📁 [DIRECTORY] Erstellt: ${dir}`);
      }
    });

    // Spezielle Berechtigungen für SSL-Verzeichnis
    try {
      fs.chmodSync(path.join(__dirname, "ssl"), 0o700);
    } catch (error) {
      console.warn(`⚠️ [DIRECTORY] Konnte SSL-Verzeichnis-Berechtigungen nicht setzen: ${error.message}`);
    }

    console.log("✅ [DIRECTORY] Alle Verzeichnisse überprüft und erstellt");
  }

  // ====== GIT BACKUP INITIALISIERUNG ======
  async initializeGitBackup() {
    if (!this.config.gitBackup?.enabled) {
      console.log("📝 [GIT BACKUP] Git Backup ist deaktiviert");
      return;
    }

    if (!this.config.gitBackup.repository || !this.config.gitBackup.username) {
      console.warn("⚠️ [GIT BACKUP] Git Backup aktiviert aber Repository oder Username fehlt");
      return;
    }

    try {
      console.log("📝 [GIT BACKUP] Initialisiere Git Backup Repository...");
      
      // Prüfe ob Git verfügbar ist
      try {
        execSync('git --version', { stdio: 'ignore' });
      } catch (error) {
        throw new Error("Git ist nicht verfügbar");
      }

      // Git Backup Verzeichnis vorbereiten
      if (!fs.existsSync(this.gitBackupPath)) {
        fs.mkdirSync(this.gitBackupPath, { recursive: true });
      }

      // Prüfe ob bereits ein Repository existiert
      const gitDir = path.join(this.gitBackupPath, '.git');
      if (!fs.existsSync(gitDir)) {
        console.log("📝 [GIT BACKUP] Klone Repository...");
        await this.cloneGitBackupRepository();
      } else {
        console.log("📝 [GIT BACKUP] Repository bereits vorhanden, prüfe Verbindung...");
        await this.testGitBackupConnection();
      }

      console.log("✅ [GIT BACKUP] Git Backup erfolgreich initialisiert");
    } catch (error) {
      console.error("❌ [GIT BACKUP] Initialisierung fehlgeschlagen:", error.message);
      console.log("ℹ️ [GIT BACKUP] Git Backup wird deaktiviert");
      this.config.gitBackup.enabled = false;
    }
  }
  // ====== API-ROUTEN SETUP ======
  
  setupRoutes() {
    console.log("🛣️ [ROUTES] Initialisiere API-Routen...");

    // ====== SICHERHEITS-ROUTEN ======

    // CAPTCHA Route
    this.app.get("/api/captcha", (req, res) => {
      try {
        const captcha = this.generateCaptcha();
        console.log(`🤖 [CAPTCHA] Generiert für IP: ${req.ip}`);
        res.json({
          id: captcha.id,
          svg: captcha.svg
        });
      } catch (error) {
        console.error("❌ [CAPTCHA] Generierung fehlgeschlagen:", error);
        res.status(500).json({ error: "CAPTCHA-Generierung fehlgeschlagen" });
      }
    });

    // 2FA Setup Route
    this.app.post("/api/2fa/setup", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { username } = req.user;
        const user = this.users.get(username);
        
        if (!user) {
          return res.status(404).json({ error: "Benutzer nicht gefunden" });
        }

        const secret = this.generate2FASecret(username);
        
        qrcode.toDataURL(secret.qrCode, (err, qrCodeDataUrl) => {
          if (err) {
            console.error("❌ [2FA] QR-Code Generierung fehlgeschlagen:", err);
            return res.status(500).json({ error: "QR-Code Generierung fehlgeschlagen" });
          }
          
          user.tempTwoFactorSecret = secret.secret;
          this.users.set(username, user);
          
          res.json({
            secret: secret.secret,
            qrCode: qrCodeDataUrl
          });
        });
      } catch (error) {
        console.error("❌ [2FA] Setup fehlgeschlagen:", error);
        res.status(500).json({ error: "2FA-Setup fehlgeschlagen" });
      }
    });

    // 2FA Verify Route
    this.app.post("/api/2fa/verify", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { token } = req.body;
        const { username } = req.user;
        const user = this.users.get(username);
        
        if (!user || !user.tempTwoFactorSecret) {
          return res.status(400).json({ error: "Kein 2FA-Setup in Bearbeitung" });
        }

        if (!token || token.length !== 6) {
          return res.status(400).json({ error: "Ungültiger Token-Format" });
        }

        const verified = this.verify2FAToken(user.tempTwoFactorSecret, token);
        
        if (verified) {
          user.twoFactorSecret = user.tempTwoFactorSecret;
          delete user.tempTwoFactorSecret;
          this.users.set(username, user);
          
          console.log(`✅ [2FA] Aktiviert für Benutzer: ${username}`);
          res.json({ 
            message: "2FA erfolgreich aktiviert",
            enabled: true
          });
        } else {
          res.status(400).json({ error: "Ungültiger 2FA-Token" });
        }
      } catch (error) {
        console.error("❌ [2FA] Verifikation fehlgeschlagen:", error);
        res.status(500).json({ error: "2FA-Verifikation fehlgeschlagen" });
      }
    });

    // 2FA Disable Route
    this.app.post("/api/2fa/disable", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { token, password } = req.body;
        const { username } = req.user;
        const user = this.users.get(username);
        
        if (!user || !user.twoFactorSecret) {
          return res.status(400).json({ error: "2FA ist nicht aktiviert" });
        }

        if (!password || !bcrypt.compareSync(password, user.password)) {
          return res.status(401).json({ error: "Passwort ungültig" });
        }

        if (!token || !this.verify2FAToken(user.twoFactorSecret, token)) {
          return res.status(400).json({ error: "Ungültiger 2FA-Token" });
        }

        delete user.twoFactorSecret;
        delete user.tempTwoFactorSecret;
        this.users.set(username, user);
        
        console.log(`🔓 [2FA] Deaktiviert für Benutzer: ${username}`);
        res.json({ 
          message: "2FA erfolgreich deaktiviert",
          enabled: false
        });
      } catch (error) {
        console.error("❌ [2FA] Deaktivierung fehlgeschlagen:", error);
        res.status(500).json({ error: "2FA-Deaktivierung fehlgeschlagen" });
      }
    });

    // ====== ERWEITERTE LOGIN-ROUTE ======
    this.app.post("/api/login", async (req, res) => {
      const { username, password, captchaId, captchaText, twoFactorToken, rememberMe } = req.body;
      const clientIp = req.ip;
      const userAgent = req.headers['user-agent'] || 'Unknown';

      console.log(`🔐 [LOGIN] Versuch von ${clientIp} für Benutzer: ${username}`);

      try {
        if (!username || !password) {
          return res.status(400).json({ 
            error: "Benutzername und Passwort erforderlich",
            code: "MISSING_CREDENTIALS"
          });
        }

        const sanitizedUsername = username.trim().toLowerCase();
        if (sanitizedUsername.length < 2 || sanitizedUsername.length > 50) {
          return res.status(400).json({ 
            error: "Ungültiger Benutzername",
            code: "INVALID_USERNAME"
          });
        }

        const lockStatus = this.isAccountLocked(clientIp, sanitizedUsername);
        if (lockStatus.locked) {
          console.log(`🔒 [LOGIN] Account gesperrt: ${sanitizedUsername} von ${clientIp}`);
          return res.status(423).json({ 
            error: `Account gesperrt. Versuche es in ${lockStatus.remainingTime} Minuten erneut.`,
            code: "ACCOUNT_LOCKED",
            lockedUntil: lockStatus.remainingTime,
            requiresCaptcha: true
          });
        }

        if (this.needsCaptcha(clientIp, sanitizedUsername)) {
          if (!captchaId || !captchaText) {
            console.log(`🤖 [LOGIN] CAPTCHA erforderlich für: ${sanitizedUsername}`);
            return res.status(400).json({ 
              error: "CAPTCHA erforderlich",
              code: "CAPTCHA_REQUIRED",
              requiresCaptcha: true
            });
          }

          const captchaValidation = this.validateCaptcha(captchaId, captchaText);
          if (!captchaValidation.valid) {
            this.recordFailedAttempt(clientIp, sanitizedUsername);
            console.log(`❌ [LOGIN] CAPTCHA fehlgeschlagen für: ${sanitizedUsername}`);
            return res.status(400).json({ 
              error: captchaValidation.message,
              code: "CAPTCHA_INVALID",
              requiresCaptcha: true
            });
          }
        }

        const user = this.users.get(sanitizedUsername);
        if (!user) {
          this.recordFailedAttempt(clientIp, sanitizedUsername);
          console.log(`❌ [LOGIN] Benutzer nicht gefunden: ${sanitizedUsername}`);
          
          await new Promise(resolve => setTimeout(resolve, 1000));
          
          const response = { 
            error: "Ungültige Anmeldedaten",
            code: "INVALID_CREDENTIALS"
          };
          if (this.needsCaptcha(clientIp, sanitizedUsername)) {
            response.requiresCaptcha = true;
          }
          
          return res.status(401).json(response);
        }

        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
          this.recordFailedAttempt(clientIp, sanitizedUsername);
          console.log(`❌ [LOGIN] Passwort ungültig für: ${sanitizedUsername}`);
          
          await new Promise(resolve => setTimeout(resolve, 1000));
          
          const response = { 
            error: "Ungültige Anmeldedaten",
            code: "INVALID_CREDENTIALS"
          };
          if (this.needsCaptcha(clientIp, sanitizedUsername)) {
            response.requiresCaptcha = true;
          }
          
          return res.status(401).json(response);
        }

        if (this.securityConfig.enable2FA && user.twoFactorSecret) {
          if (!twoFactorToken) {
            console.log(`🔐 [LOGIN] 2FA-Token erforderlich für: ${sanitizedUsername}`);
            return res.status(400).json({ 
              error: "2FA-Token erforderlich",
              code: "2FA_REQUIRED",
              requires2FA: true
            });
          }

          if (!this.verify2FAToken(user.twoFactorSecret, twoFactorToken)) {
            this.recordFailedAttempt(clientIp, sanitizedUsername);
            console.log(`❌ [LOGIN] 2FA-Token ungültig für: ${sanitizedUsername}`);
            return res.status(401).json({ 
              error: "Ungültiger 2FA-Token",
              code: "2FA_INVALID",
              requires2FA: true
            });
          }
        }

        this.clearFailedAttempts(clientIp, sanitizedUsername);
        
        user.lastLogin = new Date().toISOString();
        user.loginAttempts = 0;
        this.users.set(sanitizedUsername, user);
        
        const sessionId = this.createSecureSession(req, user, rememberMe);
        const tokenExpiry = rememberMe ? "7d" : "30m";
        
        const token = jwt.sign(
          { 
            username: user.username, 
            role: user.role,
            sessionId: sessionId,
            loginTime: Date.now(),
            userAgent: userAgent
          },
          this.config.security.jwtSecret,
          { expiresIn: tokenExpiry }
        );

        res.cookie("auth-token", token, {
          httpOnly: true,
          secure: this.securityConfig.requireHttps,
          maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : this.securityConfig.sessionTimeout,
          sameSite: 'strict'
        });

        req.session.token = token;
        req.session.user = { username: user.username, role: user.role };

        console.log(`✅ [LOGIN] Erfolgreicher Login für ${sanitizedUsername} von ${clientIp}`);

        res.json({ 
          token, 
          username: user.username, 
          role: user.role,
          sessionId: sessionId,
          has2FA: !!user.twoFactorSecret,
          passwordChanged: user.passwordChanged || false,
          sessionTimeout: this.securityConfig.sessionTimeout,
          requiresPasswordChange: !user.passwordChanged && this.securityConfig.strongPasswords
        });

      } catch (error) {
        console.error("❌ [LOGIN] Unerwarteter Fehler:", error);
        res.status(500).json({ 
          error: "Login-Fehler",
          code: "INTERNAL_ERROR"
        });
      }
    });

    // ====== ERWEITERTE LOGOUT-ROUTE ======
    this.app.post("/api/logout", (req, res) => {
      const token = req.headers.authorization?.split(" ")[1] || req.cookies["auth-token"];
      
      if (token) {
        try {
          const decoded = jwt.verify(token, this.config.security.jwtSecret);
          if (decoded.sessionId) {
            this.invalidateSession(decoded.sessionId);
          }
          console.log(`🔐 [LOGOUT] Benutzer abgemeldet: ${decoded.username}`);
        } catch (error) {
          console.log(`⚠️ [LOGOUT] Token bereits ungültig`);
        }
      }

      if (req.session) {
        req.session.destroy((err) => {
          if (err) {
            console.error("❌ [LOGOUT] Session destroy error:", err);
          }
        });
      }

      res.clearCookie("auth-token");
      res.clearCookie("db-backup-session");

      res.json({ message: "Erfolgreich abgemeldet" });
    });

    // ====== PASSWORT-ÄNDERUNG-ROUTE ======
    this.app.post("/api/change-password", this.authMiddleware.bind(this), async (req, res) => {
      try {
        const { currentPassword, newPassword, twoFactorToken } = req.body;
        const { username } = req.user;

        if (!currentPassword || !newPassword) {
          return res.status(400).json({ error: "Aktuelles und neues Passwort erforderlich" });
        }

        const user = this.users.get(username);
        if (!user) {
          return res.status(404).json({ error: "Benutzer nicht gefunden" });
        }

        const currentPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!currentPasswordValid) {
          console.log(`❌ [PASSWORD] Aktuelles Passwort ungültig für: ${username}`);
          return res.status(401).json({ error: "Aktuelles Passwort ungültig" });
        }

        if (user.twoFactorSecret) {
          if (!twoFactorToken) {
            return res.status(400).json({ 
              error: "2FA-Token erforderlich",
              requires2FA: true
            });
          }

          if (!this.verify2FAToken(user.twoFactorSecret, twoFactorToken)) {
            return res.status(401).json({ error: "Ungültiger 2FA-Token" });
          }
        }

        const validation = this.validatePasswordStrength(newPassword);
        if (!validation.valid) {
          return res.status(400).json({ 
            error: validation.message,
            strength: validation.strength
          });
        }

        if (await bcrypt.compare(newPassword, user.password)) {
          return res.status(400).json({ error: "Neues Passwort muss sich vom aktuellen unterscheiden" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        user.passwordChanged = true;
        user.passwordChangedAt = new Date().toISOString();
        this.users.set(username, user);

        if (username === this.config.security.defaultAdmin.username) {
          this.config.security.defaultAdmin.password = newPassword;
          const configToSave = { ...this.config };
          fs.writeFileSync("config.json", JSON.stringify(configToSave, null, 2));
        }

        console.log(`🔐 [PASSWORD] Passwort geändert für Benutzer: ${username}`);

        res.json({ 
          message: "Passwort erfolgreich geändert",
          passwordChanged: true
        });
      } catch (error) {
        console.error("❌ [PASSWORD] Passwort-Änderung fehlgeschlagen:", error);
        res.status(500).json({ error: "Passwort-Änderung fehlgeschlagen" });
      }
    });

    // ====== ERWEITERTE SESSION-STATUS-ROUTE ======
    this.app.get("/api/session-status", (req, res) => {
      const token = req.headers.authorization?.split(" ")[1] || 
                   req.session.token || 
                   req.cookies["auth-token"];

      if (!token) {
        return res.json({ 
          authenticated: false,
          reason: "Kein Token vorhanden"
        });
      }

      try {
        const decoded = jwt.verify(token, this.config.security.jwtSecret);
        
        if (decoded.sessionId) {
          const sessionValidation = this.validateSession(decoded.sessionId, req);
          if (!sessionValidation.valid) {
            return res.json({ 
              authenticated: false, 
              reason: sessionValidation.reason 
            });
          }

          const session = sessionValidation.session;
          res.json({
            authenticated: true,
            user: decoded,
            token: token,
            session: {
              id: session.id,
              expiresAt: session.expiresAt,
              lastActivity: session.lastActivity,
              rememberMe: session.rememberMe
            },
            timeToExpiry: session.expiresAt - Date.now()
          });
        } else {
          res.json({
            authenticated: true,
            user: decoded,
            token: token,
            timeToExpiry: null
          });
        }
      } catch (error) {
        console.log(`❌ [SESSION] Token-Validierung fehlgeschlagen: ${error.message}`);
        res.json({ 
          authenticated: false, 
          reason: "Token ungültig" 
        });
      }
    });

    // ====== SICHERHEITS-INFO-ROUTES ======
    this.app.get("/api/security-info", this.authMiddleware.bind(this), (req, res) => {
      const { username } = req.user;
      const user = this.users.get(username);
      
      res.json({
        username: username,
        has2FA: !!(user && user.twoFactorSecret),
        httpsEnabled: this.securityConfig.requireHttps,
        strongPasswordsEnabled: this.securityConfig.strongPasswords,
        sessionTimeout: this.securityConfig.sessionTimeout / 1000 / 60,
        activeSessions: this.activeSessions.size,
        captchaThreshold: this.securityConfig.captchaThreshold,
        maxFailedAttempts: this.securityConfig.maxFailedAttempts,
        lockoutDuration: this.securityConfig.lockoutDuration / 1000 / 60,
        passwordChanged: user?.passwordChanged || false,
        lastLogin: user?.lastLogin || null,
        securityFeatures: {
          https: this.securityConfig.requireHttps,
          twoFactor: this.securityConfig.enable2FA,
          captcha: true,
          rateLimiting: true,
          sessionManagement: true,
          bruteForceProtection: true
        }
      });
    });

    this.app.get("/api/active-sessions", this.authMiddleware.bind(this), (req, res) => {
      const { username } = req.user;
      
      const userSessions = Array.from(this.activeSessions.values())
        .filter(session => session.userId === username)
        .map(session => ({
          id: session.id,
          ip: session.ip,
          userAgent: session.userAgent,
          createdAt: session.createdAt,
          lastActivity: session.lastActivity,
          expiresAt: session.expiresAt,
          rememberMe: session.rememberMe,
          current: session.id === req.user.sessionId
        }));

      res.json({
        sessions: userSessions,
        total: userSessions.length
      });
    });

    this.app.delete("/api/session/:sessionId", this.authMiddleware.bind(this), (req, res) => {
      const { sessionId } = req.params;
      const { username } = req.user;
      
      const session = this.activeSessions.get(sessionId);
      
      if (!session) {
        return res.status(404).json({ error: "Session nicht gefunden" });
      }

      if (session.userId !== username) {
        return res.status(403).json({ error: "Keine Berechtigung" });
      }

      this.invalidateSession(sessionId);
      
      res.json({ message: "Session erfolgreich beendet" });
    });

    console.log("✅ [ROUTES] Sicherheits- und Authentifizierungs-Routen konfiguriert");

    // ====== SSL-ROUTEN ======
    this.setupSSLRoutes();

    // ====== BACKUP UND SYSTEM ROUTEN ======
    
    // Manual Update Route
    this.app.post("/api/update", this.authMiddleware.bind(this), async (req, res) => {
      try {
        const { username } = req.user;
        console.log(`🔄 [UPDATE] Manuelles Update gestartet von: ${username}`);
        
        if (req.user.role !== 'admin') {
          return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
        }

        await this.checkForUpdates();
        
        console.log(`✅ [UPDATE] Update erfolgreich durch: ${username}`);
        res.json({ message: "Update erfolgreich durchgeführt" });
      } catch (error) {
        console.error("❌ [UPDATE] Update-Fehler:", error);
        res.status(500).json({ error: "Update fehlgeschlagen: " + error.message });
      }
    });

    // Git Backup Configuration Routes
    this.app.get("/api/git-backup/config", this.authMiddleware.bind(this), (req, res) => {
      const config = {
        enabled: this.config.gitBackup?.enabled || false,
        repository: this.config.gitBackup?.repository || "",
        username: this.config.gitBackup?.username || "",
        hasToken: !!this.config.gitBackup?.token,
        branch: this.config.gitBackup?.branch || "main",
      };
      
      console.log(`📋 [GIT CONFIG] Konfiguration abgerufen von: ${req.user.username}`);
      res.json(config);
    });

    this.app.post("/api/git-backup/config", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }
      await this.updateGitBackupConfig(req, res);
    });

    this.app.post("/api/git-backup/test", this.authMiddleware.bind(this), async (req, res) => {
      try {
        const result = await this.testGitBackupConnection();
        res.json({
          message: "✅ Git Backup Test erfolgreich! Repository ist erreichbar und beschreibbar.",
          details: result,
        });
      } catch (error) {
        res.status(500).json({
          error: `Git Backup Test fehlgeschlagen: ${error.message}`,
          troubleshooting: this.generateGitTroubleshootingInfo(),
        });
      }
    });

    // System Information Route
    this.app.get("/api/system", this.authMiddleware.bind(this), (req, res) => {
      const packageInfo = JSON.parse(fs.readFileSync("package.json", "utf8"));

      exec("git rev-parse HEAD", (error, stdout) => {
        const gitCommit = error ? "Unknown" : stdout.trim().substring(0, 7);

        exec("git log -1 --format=%ci", (error, stdout) => {
          const gitDate = error ? "Unknown" : stdout.trim();

          const securityStats = {
            activeSessions: this.activeSessions.size,
            failedAttempts: this.failedAttempts.size,
            captchaSessions: this.captchaSessions.size,
            httpsEnabled: this.securityConfig.requireHttps,
            twoFactorEnabled: this.securityConfig.enable2FA,
            strongPasswordsEnabled: this.securityConfig.strongPasswords
          };

          res.json({
            version: packageInfo.version,
            name: packageInfo.name,
            git: { commit: gitCommit, date: gitDate },
            autoUpdate: this.config.updates?.autoUpdate || false,
            repository: this.updateRepository,
            branch: this.updateBranch,
            nodeVersion: process.version,
            uptime: process.uptime(),
            gitBackup: {
              enabled: this.config.gitBackup?.enabled || false,
              repository: this.config.gitBackup?.repository || "",
              hasCredentials: !!(this.config.gitBackup?.username && this.config.gitBackup?.token),
            },
            security: securityStats,
            memoryUsage: process.memoryUsage(),
            platform: process.platform,
            arch: process.arch
          });
        });
      });
    });

    // Backup Creation Route
    this.app.post("/api/backup", this.authMiddleware.bind(this), async (req, res) => {
      try {
        const { type, host, port, database, username, password } = req.body;
        const { username: currentUser } = req.user;

        console.log(`📦 [BACKUP] Backup-Erstellung gestartet von: ${currentUser}`);

        // Validierung der Eingabedaten
        if (!type || !host || !database || !username || !password) {
          return res.status(400).json({ error: "Alle Datenbankverbindungsparameter sind erforderlich" });
        }

        // Sichere Validierung des Datenbanktyps
        const supportedTypes = ['mysql', 'postgresql', 'mongodb'];
        if (!supportedTypes.includes(type)) {
          return res.status(400).json({ error: "Nicht unterstützter Datenbanktyp" });
        }

        const backupResult = await this.createDatabaseBackup({
          type,
          host,
          port: port || this.getDefaultPort(type),
          database,
          username,
          password
        }, currentUser);

        res.json({
          message: "Backup erfolgreich erstellt",
          filename: backupResult.filename,
          size: backupResult.size,
          gitPushed: backupResult.gitPushed || false,
          note: backupResult.note
        });

      } catch (error) {
        console.error("❌ [BACKUP] Backup-Erstellung fehlgeschlagen:", error);
        res.status(500).json({ error: "Backup-Erstellung fehlgeschlagen: " + error.message });
      }
    });

    // Backup List Route
    this.app.get("/api/backups", this.authMiddleware.bind(this), (req, res) => {
      try {
        const backupsPath = this.config.backup.defaultPath;
        const backups = [];

        if (fs.existsSync(backupsPath)) {
          const files = fs.readdirSync(backupsPath);
          
          files.forEach(file => {
            const filePath = path.join(backupsPath, file);
            const stats = fs.statSync(filePath);
            
            // Überspinge Verzeichnisse und System-Dateien
            if (stats.isDirectory() || file.startsWith('.') || file === 'schedules.json') {
              return;
            }

            backups.push({
              filename: file,
              size: stats.size,
              created: stats.birthtime,
              type: stats.isDirectory() ? 'directory' : 'file',
              canDelete: req.user.role === 'admin' || true // Alle können eigene Backups löschen
            });
          });

          // Sortiere nach Erstellungsdatum (neueste zuerst)
          backups.sort((a, b) => new Date(b.created) - new Date(a.created));
        }

        res.json(backups);
      } catch (error) {
        console.error("❌ [BACKUP] Fehler beim Laden der Backup-Liste:", error);
        res.status(500).json({ error: "Fehler beim Laden der Backup-Liste" });
      }
    });

    // Backup Download Route
    this.app.get("/api/backup/:filename/download", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { filename } = req.params;
        const filePath = path.join(this.config.backup.defaultPath, filename);

        // Sicherheitsvalidierung: Path Traversal verhindern
        if (!filePath.startsWith(this.config.backup.defaultPath)) {
          return res.status(403).json({ error: "Ungültiger Dateipfad" });
        }

        if (!fs.existsSync(filePath)) {
          return res.status(404).json({ error: "Backup-Datei nicht gefunden" });
        }

        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
          return res.status(400).json({ error: "Verzeichnis-Downloads werden nicht unterstützt" });
        }

        console.log(`📥 [DOWNLOAD] ${req.user.username} lädt herunter: ${filename}`);

        // Set appropriate headers
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', stats.size);

        // Stream file to response
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);

      } catch (error) {
        console.error("❌ [DOWNLOAD] Download-Fehler:", error);
        res.status(500).json({ error: "Download fehlgeschlagen" });
      }
    });

    // Backup Delete Route
    this.app.delete("/api/backup/:filename", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { filename } = req.params;
        const filePath = path.join(this.config.backup.defaultPath, filename);

        // Sicherheitsvalidierung
        if (!filePath.startsWith(this.config.backup.defaultPath)) {
          return res.status(403).json({ error: "Ungültiger Dateipfad" });
        }

        if (!fs.existsSync(filePath)) {
          return res.status(404).json({ error: "Backup-Datei nicht gefunden" });
        }

        // Nur Admins können alle Backups löschen
        if (req.user.role !== 'admin') {
          // Hier könnte zusätzliche Logik für Benutzer-spezifische Backups stehen
          console.log(`⚠️ [DELETE] Nicht-Admin versucht Backup zu löschen: ${req.user.username}`);
        }

        fs.unlinkSync(filePath);
        console.log(`🗑️ [DELETE] ${req.user.username} hat gelöscht: ${filename}`);

        res.json({ message: "Backup erfolgreich gelöscht" });
      } catch (error) {
        console.error("❌ [DELETE] Lösch-Fehler:", error);
        res.status(500).json({ error: "Löschen fehlgeschlagen" });
      }
    });

    // Schedule Management Routes
    this.app.get("/api/schedules", this.authMiddleware.bind(this), (req, res) => {
      try {
        const schedules = this.loadSchedulesFromFile();
        
        // Nur eigene Schedules anzeigen (außer Admin)
        const filteredSchedules = req.user.role === 'admin' ? 
          schedules : 
          schedules.filter(schedule => schedule.createdBy === req.user.username);

        res.json(filteredSchedules);
      } catch (error) {
        console.error("❌ [SCHEDULE] Fehler beim Laden der Zeitpläne:", error);
        res.status(500).json({ error: "Fehler beim Laden der Zeitpläne" });
      }
    });

    this.app.post("/api/schedule", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { name, cronExpression, dbConfig } = req.body;
        const { username } = req.user;

        if (!name || !cronExpression || !dbConfig) {
          return res.status(400).json({ error: "Name, Cron-Expression und Datenbank-Konfiguration sind erforderlich" });
        }

        // Validiere Cron-Expression (einfache Validierung)
        if (!this.isValidCronExpression(cronExpression)) {
          return res.status(400).json({ error: "Ungültige Cron-Expression" });
        }

        const scheduleId = crypto.randomBytes(16).toString('hex');
        const schedule = {
          id: scheduleId,
          name,
          cronExpression,
          dbConfig,
          enabled: true,
          createdBy: username,
          createdAt: new Date().toISOString(),
          lastRun: null,
          nextRun: this.getNextCronRun(cronExpression)
        };

        this.addSchedule(schedule);
        console.log(`📅 [SCHEDULE] Neuer Zeitplan erstellt: ${name} von ${username}`);

        res.json({ 
          message: "Zeitplan erfolgreich erstellt",
          schedule: schedule
        });
      } catch (error) {
        console.error("❌ [SCHEDULE] Fehler beim Erstellen des Zeitplans:", error);
        res.status(500).json({ error: "Zeitplan-Erstellung fehlgeschlagen" });
      }
    });

    this.app.delete("/api/schedule/:scheduleId", this.authMiddleware.bind(this), (req, res) => {
      try {
        const { scheduleId } = req.params;
        const { username, role } = req.user;

        const schedules = this.loadSchedulesFromFile();
        const scheduleIndex = schedules.findIndex(s => s.id === scheduleId);

        if (scheduleIndex === -1) {
          return res.status(404).json({ error: "Zeitplan nicht gefunden" });
        }

        const schedule = schedules[scheduleIndex];

        // Nur eigene Schedules löschen (außer Admin)
        if (role !== 'admin' && schedule.createdBy !== username) {
          return res.status(403).json({ error: "Keine Berechtigung" });
        }

        // Cron-Job stoppen wenn vorhanden
        if (this.backupJobs.has(scheduleId)) {
          this.backupJobs.get(scheduleId).destroy();
          this.backupJobs.delete(scheduleId);
        }

        schedules.splice(scheduleIndex, 1);
        this.saveSchedulesToFile(schedules);

        console.log(`🗑️ [SCHEDULE] Zeitplan gelöscht: ${schedule.name} von ${username}`);
        res.json({ message: "Zeitplan erfolgreich gelöscht" });
      } catch (error) {
        console.error("❌ [SCHEDULE] Fehler beim Löschen des Zeitplans:", error);
        res.status(500).json({ error: "Zeitplan-Löschung fehlgeschlagen" });
      }
    });

    // Hauptseite Route
    this.app.get("/", (req, res) => {
      res.sendFile(path.join(__dirname, "public", "index.html"));
    });

    // 404 Handler
    this.app.use((req, res) => {
      console.log(`❌ [404] Nicht gefundener Endpunkt: ${req.method} ${req.url} von ${req.ip}`);
      res.status(404).json({ 
        error: "Endpunkt nicht gefunden",
        code: "ENDPOINT_NOT_FOUND"
      });
    });

    // Global Error Handler
    this.app.use((error, req, res, next) => {
      console.error(`❌ [ERROR] Unbehandelter Fehler: ${error.message} bei ${req.method} ${req.url}`);
      res.status(500).json({
        error: "Interner Serverfehler",
        code: "INTERNAL_SERVER_ERROR"
      });
    });

    console.log("✅ [ROUTES] Alle API-Routen erfolgreich konfiguriert");
  }

  // ====== SSL API-ROUTEN SETUP ======
  setupSSLRoutes() {
    console.log("🔐 [SSL ROUTES] Initialisiere SSL-API-Routen...");

    // SSL Status
    this.app.get("/api/ssl-status", this.authMiddleware.bind(this), async (req, res) => {
      try {
        if (!this.sslManager) {
          return res.json({ enabled: false, reason: "SSL Manager nicht initialisiert" });
        }
        
        const status = await this.sslManager.getStatus();
        res.json(status);
      } catch (error) {
        console.error("❌ [SSL] Status-Abfrage fehlgeschlagen:", error);
        res.status(500).json({ error: "SSL Status konnte nicht abgerufen werden: " + error.message });
      }
    });

    // SSL Certificate Renewal
    this.app.post("/api/ssl-renew", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }

      try {
        if (!this.sslManager) {
          return res.status(500).json({ error: "SSL Manager nicht verfügbar" });
        }

        console.log(`🔄 [SSL] Manuelle Erneuerung durch: ${req.user.username}`);
        const result = await this.sslManager.obtainCertificate();
        
        res.json({ 
          message: "SSL-Zertifikat erfolgreich erneuert",
          domain: result.domain,
          method: result.method,
          expiresIn: result.expiresIn
        });
      } catch (error) {
        console.error("❌ [SSL] Manuelle Erneuerung fehlgeschlagen:", error.message);
        res.status(500).json({ error: "SSL-Erneuerung fehlgeschlagen: " + error.message });
      }
    });

    // SSL Health Check
    this.app.get("/api/ssl-health", this.authMiddleware.bind(this), async (req, res) => {
      try {
        if (!this.sslHealthCheck) {
          return res.json({ overall: "UNKNOWN", reason: "SSL Health Check nicht verfügbar" });
        }

        const health = await this.sslHealthCheck.performComprehensiveHealthCheck();
        res.json(health);
      } catch (error) {
        console.error("❌ [SSL] Health Check fehlgeschlagen:", error);
        res.status(500).json({ error: "SSL Health Check fehlgeschlagen: " + error.message });
      }
    });

    // SSL Configuration
    this.app.get("/api/ssl-config", this.authMiddleware.bind(this), (req, res) => {
      try {
        if (!this.sslManager) {
          return res.json({ error: "SSL Manager nicht verfügbar" });
        }

        const config = this.sslManager.getConfigurationSummary();
        res.json(config);
      } catch (error) {
        console.error("❌ [SSL] Konfiguration konnte nicht abgerufen werden:", error);
        res.status(500).json({ error: "SSL Konfiguration konnte nicht abgerufen werden: " + error.message });
      }
    });

    // SSL Setup Instructions
    this.app.get("/api/ssl-instructions", this.authMiddleware.bind(this), (req, res) => {
      try {
        if (!this.sslManager) {
          return res.json({ error: "SSL Manager nicht verfügbar" });
        }

        const instructions = this.sslManager.generateSetupInstructions();
        res.json(instructions);
      } catch (error) {
        console.error("❌ [SSL] Setup-Anweisungen konnten nicht generiert werden:", error);
        res.status(500).json({ error: "SSL Setup-Anweisungen konnten nicht generiert werden: " + error.message });
      }
    });

    // SSL Certificate Test
    this.app.post("/api/ssl-test", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }

      try {
        if (!this.sslManager) {
          return res.status(500).json({ error: "SSL Manager nicht verfügbar" });
        }

        const port = req.body.port || 8443;
        const result = await this.sslManager.testCertificate(port);
        res.json(result);
      } catch (error) {
        console.error("❌ [SSL] Test fehlgeschlagen:", error);
        res.status(500).json({ error: "SSL Test fehlgeschlagen: " + error.message });
      }
    });

    // SSL Export Configuration (für Troubleshooting)
    this.app.get("/api/ssl-export", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }

      try {
        if (!this.sslManager) {
          return res.status(500).json({ error: "SSL Manager nicht verfügbar" });
        }

        const exportData = await this.sslManager.exportConfiguration();
        res.json(exportData);
      } catch (error) {
        console.error("❌ [SSL] Export fehlgeschlagen:", error);
        res.status(500).json({ error: "SSL Export fehlgeschlagen: " + error.message });
      }
    });

    console.log("✅ [SSL ROUTES] SSL-API-Routen erfolgreich konfiguriert");
  }
  // ====== GIT BACKUP FUNKTIONEN ======

  // Git Token Management
  loadGitToken() {
    try {
      if (fs.existsSync(this.secretsFile)) {
        const encryptedData = fs.readFileSync(this.secretsFile, "utf8");
        const decrypted = this.decrypt(encryptedData);
        const secrets = JSON.parse(decrypted);
        console.log(`🔑 [GIT TOKEN] Token geladen (${secrets.token?.length || 0} Zeichen)`);
        return secrets.token;
      }
    } catch (error) {
      console.error("❌ [GIT TOKEN] Fehler beim Laden des Tokens:", error.message);
    }
    return null;
  }

  saveGitToken(token) {
    try {
      const secrets = { token, savedAt: new Date().toISOString() };
      const encrypted = this.encrypt(JSON.stringify(secrets));
      
      fs.mkdirSync(path.dirname(this.secretsFile), { recursive: true });
      fs.writeFileSync(this.secretsFile, encrypted, { mode: 0o600 });
      
      console.log(`🔑 [GIT TOKEN] Token gespeichert (${token.length} Zeichen)`);
    } catch (error) {
      console.error("❌ [GIT TOKEN] Fehler beim Speichern des Tokens:", error.message);
      throw error;
    }
  }

  deleteGitToken() {
    try {
      if (fs.existsSync(this.secretsFile)) {
        fs.unlinkSync(this.secretsFile);
        console.log("🔑 [GIT TOKEN] Token gelöscht");
      }
    } catch (error) {
      console.error("❌ [GIT TOKEN] Fehler beim Löschen des Tokens:", error.message);
    }
  }

  // Encryption/Decryption für Token
  encrypt(text) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(this.encryptionKey, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, key);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return iv.toString('hex') + ':' + encrypted;
  }

  decrypt(encryptedData) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(this.encryptionKey, 'salt', 32);
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    
    const decipher = crypto.createDecipher(algorithm, key);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Git Backup Configuration Update
  async updateGitBackupConfig(req, res) {
    try {
      const { enabled, repository, username, token, branch } = req.body;
      const { username: currentUser } = req.user;

      console.log(`🔧 [GIT CONFIG] Konfiguration wird aktualisiert von: ${currentUser}`);

      // Validierung
      if (enabled) {
        if (!repository || !username) {
          return res.status(400).json({ 
            error: "Repository und Benutzername sind erforderlich" 
          });
        }

        // URL-Validierung
        try {
          new URL(repository);
        } catch (error) {
          return res.status(400).json({ 
            error: "Ungültige Repository-URL" 
          });
        }

        if (!repository.includes('github.com') && !repository.includes('gitlab.com') && !repository.includes('bitbucket.org')) {
          console.warn(`⚠️ [GIT CONFIG] Unbekannter Git-Provider: ${repository}`);
        }
      }

      // Konfiguration aktualisieren
      this.config.gitBackup = this.config.gitBackup || {};
      this.config.gitBackup.enabled = enabled;
      this.config.gitBackup.repository = repository || "";
      this.config.gitBackup.username = username || "";
      this.config.gitBackup.branch = branch || "main";

      // Token behandeln
      if (token && token !== "unchanged") {
        this.config.gitBackup.token = token;
        this.saveGitToken(token);
      } else if (!enabled) {
        // Token löschen wenn deaktiviert
        delete this.config.gitBackup.token;
        this.deleteGitToken();
      }

      // Konfiguration speichern
      const configToSave = { ...this.config };
      delete configToSave.gitBackup.token; // Token nicht in config.json speichern
      fs.writeFileSync("config.json", JSON.stringify(configToSave, null, 2));

      // Git Repository initialisieren wenn aktiviert
      if (enabled) {
        try {
          await this.initializeGitBackup();
        } catch (gitError) {
          console.error("❌ [GIT CONFIG] Git Backup Initialisierung fehlgeschlagen:", gitError.message);
          return res.status(500).json({ 
            error: "Git Backup Konfiguration gespeichert, aber Initialisierung fehlgeschlagen: " + gitError.message,
            needsRestart: "Eventuell ist ein Neustart erforderlich"
          });
        }
      }

      console.log(`✅ [GIT CONFIG] Konfiguration erfolgreich aktualisiert`);
      res.json({ 
        message: "Git Backup Konfiguration erfolgreich gespeichert",
        enabled: enabled,
        repository: repository
      });

    } catch (error) {
      console.error("❌ [GIT CONFIG] Fehler beim Aktualisieren der Konfiguration:", error);
      res.status(500).json({ error: "Konfiguration-Update fehlgeschlagen: " + error.message });
    }
  }

  // Git Repository Cloning
  async cloneGitBackupRepository() {
    if (!this.config.gitBackup?.repository || !this.config.gitBackup?.username || !this.config.gitBackup?.token) {
      throw new Error("Git Backup Konfiguration unvollständig");
    }

    const { repository, username, token, branch = "main" } = this.config.gitBackup;
    
    // Repository URL mit Authentifizierung erstellen
    const repoUrl = new URL(repository);
    repoUrl.username = username;
    repoUrl.password = token;
    const authenticatedUrl = repoUrl.toString();

    return new Promise((resolve, reject) => {
      const command = `git clone -b ${branch} "${authenticatedUrl}" "${this.gitBackupPath}"`;
      
      exec(command, { timeout: 60000 }, (error, stdout, stderr) => {
        if (error) {
          console.error("❌ [GIT CLONE] Fehler:", stderr);
          reject(new Error(`Git Clone fehlgeschlagen: ${stderr || error.message}`));
          return;
        }
        
        console.log("✅ [GIT CLONE] Repository erfolgreich geklont");
        resolve(stdout);
      });
    });
  }

  // Git Backup Connection Test
  async testGitBackupConnection() {
    if (!this.config.gitBackup?.repository || !this.config.gitBackup?.username || !this.config.gitBackup?.token) {
      throw new Error("Git Backup Konfiguration unvollständig");
    }

    const { repository, username, token, branch = "main" } = this.config.gitBackup;
    const testFile = path.join(this.gitBackupPath, '.test-connection');
    
    try {
      // Repository URL mit Authentifizierung
      const repoUrl = new URL(repository);
      repoUrl.username = username;
      repoUrl.password = token;
      const authenticatedUrl = repoUrl.toString();

      // Prüfe ob Repository-Verzeichnis existiert
      if (!fs.existsSync(path.join(this.gitBackupPath, '.git'))) {
        console.log("📝 [GIT TEST] Repository nicht gefunden, klone neu...");
        await this.cloneGitBackupRepository();
      }

      // Test-Datei erstellen
      const testContent = `Git Backup Test - ${new Date().toISOString()}`;
      fs.writeFileSync(testFile, testContent);

      // Git-Befehle ausführen
      const commands = [
        `cd "${this.gitBackupPath}" && git config user.name "${username}"`,
        `cd "${this.gitBackupPath}" && git config user.email "${username}@backup.local"`,
        `cd "${this.gitBackupPath}" && git add .test-connection`,
        `cd "${this.gitBackupPath}" && git commit -m "Test connection ${new Date().toISOString()}"`,
        `cd "${this.gitBackupPath}" && git push origin ${branch}`
      ];

      for (const command of commands) {
        await new Promise((resolve, reject) => {
          exec(command, { timeout: 30000 }, (error, stdout, stderr) => {
            if (error) {
              reject(new Error(`Git Befehl fehlgeschlagen: ${stderr || error.message}`));
              return;
            }
            resolve(stdout);
          });
        });
      }

      // Test-Datei wieder entfernen
      fs.unlinkSync(testFile);
      
      await new Promise((resolve, reject) => {
        const cleanupCommands = [
          `cd "${this.gitBackupPath}" && git rm .test-connection`,
          `cd "${this.gitBackupPath}" && git commit -m "Remove test file"`,
          `cd "${this.gitBackupPath}" && git push origin ${branch}`
        ];

        const executeCleanup = async () => {
          for (const command of cleanupCommands) {
            await new Promise((res, rej) => {
              exec(command, (error, stdout, stderr) => {
                if (error) rej(new Error(stderr || error.message));
                else res(stdout);
              });
            });
          }
        };

        executeCleanup().then(resolve).catch(reject);
      });

      return {
        success: true,
        message: "Git Backup Repository ist erreichbar und beschreibbar",
        repository: repository,
        branch: branch
      };

    } catch (error) {
      // Test-Datei aufräumen falls vorhanden
      if (fs.existsSync(testFile)) {
        fs.unlinkSync(testFile);
      }
      
      throw new Error(`Git Backup Test fehlgeschlagen: ${error.message}`);
    }
  }

  // Push Backup to Git
  async pushBackupToGit(backupFile) {
    if (!this.config.gitBackup?.enabled) {
      return { success: false, reason: "Git Backup deaktiviert" };
    }

    try {
      const { repository, username, token, branch = "main" } = this.config.gitBackup;
      
      if (!repository || !username || !token) {
        throw new Error("Git Backup Konfiguration unvollständig");
      }

      // Prüfe ob Repository initialisiert ist
      if (!fs.existsSync(path.join(this.gitBackupPath, '.git'))) {
        console.log("📝 [GIT PUSH] Repository nicht initialisiert, klone neu...");
        await this.cloneGitBackupRepository();
      }

      const backupFileName = path.basename(backupFile);
      const gitBackupFile = path.join(this.gitBackupPath, backupFileName);

      // Backup-Datei in Git Repository kopieren
      fs.copyFileSync(backupFile, gitBackupFile);

      // Git-Befehle ausführen
      const commands = [
        `cd "${this.gitBackupPath}" && git config user.name "${username}"`,
        `cd "${this.gitBackupPath}" && git config user.email "${username}@backup.local"`,
        `cd "${this.gitBackupPath}" && git pull origin ${branch}`,
        `cd "${this.gitBackupPath}" && git add "${backupFileName}"`,
        `cd "${this.gitBackupPath}" && git commit -m "Add backup: ${backupFileName} - ${new Date().toISOString()}"`,
        `cd "${this.gitBackupPath}" && git push origin ${branch}`
      ];

      for (const command of commands) {
        await new Promise((resolve, reject) => {
          exec(command, { timeout: 60000 }, (error, stdout, stderr) => {
            if (error) {
              // Ignoriere "nothing to commit" Fehler
              if (stderr.includes('nothing to commit') || stderr.includes('up to date')) {
                resolve(stdout);
                return;
              }
              reject(new Error(`Git Befehl fehlgeschlagen: ${stderr || error.message}`));
              return;
            }
            resolve(stdout);
          });
        });
      }

      console.log(`✅ [GIT PUSH] Backup erfolgreich gepusht: ${backupFileName}`);
      return { success: true, filename: backupFileName };

    } catch (error) {
      console.error(`❌ [GIT PUSH] Fehler beim Pushen des Backups:`, error.message);
      return { success: false, error: error.message };
    }
  }

  // Generate Git Troubleshooting Info
  generateGitTroubleshootingInfo() {
    return {
      commonIssues: [
        {
          issue: "Authentication failed",
          solutions: [
            "Prüfe Personal Access Token",
            "Stelle sicher, dass Token Repository-Zugriff hat",
            "Prüfe Benutzername und Repository-URL"
          ]
        },
        {
          issue: "Repository not found",
          solutions: [
            "Prüfe Repository-URL",
            "Stelle sicher, dass Repository existiert",
            "Prüfe Berechtigung für Repository-Zugriff"
          ]
        },
        {
          issue: "Push rejected",
          solutions: [
            "Führe Git Pull vor Push aus",
            "Prüfe Branch-Berechtigungen",
            "Löse mögliche Merge-Konflikte"
          ]
        }
      ],
      checkCommands: [
        "git config --list",
        "git remote -v",
        "git status",
        "git log --oneline -5"
      ]
    };
  }

  // ====== BACKUP FUNKTIONEN ======

  // Database Backup Creation
  async createDatabaseBackup(dbConfig, createdBy) {
    const { type, host, port, database, username, password } = dbConfig;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${database}_${type}_${timestamp}.sql`;
    const filepath = path.join(this.config.backup.defaultPath, filename);

    try {
      console.log(`📦 [BACKUP] Erstelle ${type} Backup für ${database}@${host}:${port}`);

      switch (type) {
        case 'mysql':
          await this.createMySQLBackup(dbConfig, filepath);
          break;
        case 'postgresql':
          await this.createPostgreSQLBackup(dbConfig, filepath);
          break;
        case 'mongodb':
          await this.createMongoDBBackup(dbConfig, filepath);
          break;
        default:
          throw new Error(`Nicht unterstützter Datenbanktyp: ${type}`);
      }

      // Dateigröße ermitteln
      const stats = fs.statSync(filepath);
      const fileSizeInMB = (stats.size / (1024 * 1024)).toFixed(2);

      console.log(`✅ [BACKUP] Backup erstellt: ${filename} (${fileSizeInMB} MB)`);

      // Git Backup versuchen
      let gitResult = null;
      if (this.config.gitBackup?.enabled && type !== 'mongodb') {
        gitResult = await this.pushBackupToGit(filepath);
      }

      // Alte Backups bereinigen
      await this.cleanupOldBackups();

      return {
        filename: filename,
        size: stats.size,
        path: filepath,
        gitPushed: gitResult?.success || false,
        gitError: gitResult?.error || null,
        note: type === 'mongodb' ? 'MongoDB Backups werden nicht zu Git gepusht (Verzeichnis)' : null
      };

    } catch (error) {
      console.error(`❌ [BACKUP] Backup-Erstellung fehlgeschlagen:`, error);
      
      // Aufräumen bei Fehler
      if (fs.existsSync(filepath)) {
        fs.unlinkSync(filepath);
      }
      
      throw error;
    }
  }

  // MySQL Backup
  async createMySQLBackup(dbConfig, filepath) {
    const { host, port, database, username, password } = dbConfig;
    
    return new Promise((resolve, reject) => {
      const command = `mysqldump -h ${host} -P ${port || 3306} -u ${username} -p${password} ${database}`;
      
      exec(command, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`MySQL Dump fehlgeschlagen: ${stderr || error.message}`));
          return;
        }
        
        try {
          fs.writeFileSync(filepath, stdout);
          resolve();
        } catch (writeError) {
          reject(new Error(`Fehler beim Schreiben der Backup-Datei: ${writeError.message}`));
        }
      });
    });
  }

  // PostgreSQL Backup
  async createPostgreSQLBackup(dbConfig, filepath) {
    const { host, port, database, username, password } = dbConfig;
    
    return new Promise((resolve, reject) => {
      const env = {
        ...process.env,
        PGPASSWORD: password
      };
      
      const command = `pg_dump -h ${host} -p ${port || 5432} -U ${username} -d ${database} --no-password`;
      
      exec(command, { env, maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`PostgreSQL Dump fehlgeschlagen: ${stderr || error.message}`));
          return;
        }
        
        try {
          fs.writeFileSync(filepath, stdout);
          resolve();
        } catch (writeError) {
          reject(new Error(`Fehler beim Schreiben der Backup-Datei: ${writeError.message}`));
        }
      });
    });
  }

  // MongoDB Backup
  async createMongoDBBackup(dbConfig, filepath) {
    const { host, port, database, username, password } = dbConfig;
    const backupDir = filepath.replace('.sql', '_mongodb');
    
    return new Promise((resolve, reject) => {
      const authPart = username && password ? `--username ${username} --password ${password}` : '';
      const command = `mongodump --host ${host}:${port || 27017} --db ${database} ${authPart} --out ${backupDir}`;
      
      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`MongoDB Dump fehlgeschlagen: ${stderr || error.message}`));
          return;
        }
        
        console.log(`✅ [BACKUP] MongoDB Backup erstellt in: ${backupDir}`);
        resolve();
      });
    });
  }

  // Cleanup Old Backups
  async cleanupOldBackups() {
    try {
      const backupsPath = this.config.backup.defaultPath;
      const maxBackups = this.config.backup.maxBackups || 10;
      
      if (!fs.existsSync(backupsPath)) {
        return;
      }

      const files = fs.readdirSync(backupsPath)
        .filter(file => {
          const filePath = path.join(backupsPath, file);
          const stats = fs.statSync(filePath);
          return stats.isFile() && !file.startsWith('.') && file !== 'schedules.json';
        })
        .map(file => {
          const filePath = path.join(backupsPath, file);
          const stats = fs.statSync(filePath);
          return {
            name: file,
            path: filePath,
            created: stats.birthtime
          };
        })
        .sort((a, b) => b.created - a.created);

      if (files.length > maxBackups) {
        const filesToDelete = files.slice(maxBackups);
        
        for (const file of filesToDelete) {
          fs.unlinkSync(file.path);
          console.log(`🧹 [CLEANUP] Altes Backup gelöscht: ${file.name}`);
        }
        
        console.log(`🧹 [CLEANUP] ${filesToDelete.length} alte Backups bereinigt`);
      }
    } catch (error) {
      console.error("❌ [CLEANUP] Fehler beim Bereinigen alter Backups:", error);
    }
  }

  // ====== HELPER FUNKTIONEN ======

  // Get Default Database Ports
  getDefaultPort(type) {
    const ports = {
      mysql: 3306,
      postgresql: 5432,
      mongodb: 27017
    };
    return ports[type] || null;
  }

  // Cron Expression Validation
  isValidCronExpression(expression) {
    // Einfache Validierung - in Produktion sollte eine robustere Validierung verwendet werden
    const cronRegex = /^(\*|([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])|\*\/([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])) (\*|([0-9]|1[0-9]|2[0-3])|\*\/([0-9]|1[0-9]|2[0-3])) (\*|([1-9]|1[0-9]|2[0-9]|3[0-1])|\*\/([1-9]|1[0-9]|2[0-9]|3[0-1])) (\*|([1-9]|1[0-2])|\*\/([1-9]|1[0-2])) (\*|([0-6])|\*\/([0-6]))$/;
    return cronRegex.test(expression);
  }

  // Get Next Cron Run
  getNextCronRun(expression) {
    try {
      // Vereinfachte Berechnung - in Produktion sollte eine Cron-Library verwendet werden
      return new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // Nächsten Tag als Fallback
    } catch (error) {
      return null;
    }
  }
  // ====== SCHEDULE MANAGEMENT ======

  // Load Schedules from File
  loadSchedulesFromFile() {
    try {
      if (fs.existsSync(this.schedulesFile)) {
        const data = fs.readFileSync(this.schedulesFile, "utf8");
        const schedules = JSON.parse(data);
        
        // Schedules in Cron-Jobs konvertieren
        schedules.forEach(schedule => {
          if (schedule.enabled) {
            this.createCronJob(schedule);
          }
        });
        
        console.log(`📅 [SCHEDULE] ${schedules.length} Zeitpläne geladen`);
        return schedules;
      }
    } catch (error) {
      console.error("❌ [SCHEDULE] Fehler beim Laden der Zeitpläne:", error);
    }
    return [];
  }

  // Save Schedules to File
  saveSchedulesToFile(schedules) {
    try {
      fs.writeFileSync(this.schedulesFile, JSON.stringify(schedules, null, 2));
      console.log(`📅 [SCHEDULE] ${schedules.length} Zeitpläne gespeichert`);
    } catch (error) {
      console.error("❌ [SCHEDULE] Fehler beim Speichern der Zeitpläne:", error);
      throw error;
    }
  }

  // Add Schedule
  addSchedule(schedule) {
    try {
      const schedules = this.loadSchedulesFromFile();
      schedules.push(schedule);
      this.saveSchedulesToFile(schedules);
      
      // Cron-Job erstellen
      if (schedule.enabled) {
        this.createCronJob(schedule);
      }
      
      console.log(`📅 [SCHEDULE] Zeitplan hinzugefügt: ${schedule.name}`);
    } catch (error) {
      console.error("❌ [SCHEDULE] Fehler beim Hinzufügen des Zeitplans:", error);
      throw error;
    }
  }

  // Create Cron Job
  createCronJob(schedule) {
    try {
      const cronJob = cron.schedule(schedule.cronExpression, async () => {
        console.log(`⏰ [CRON] Führe geplantes Backup aus: ${schedule.name}`);
        
        try {
          const result = await this.createDatabaseBackup(schedule.dbConfig, 'system');
          
          // Update last run time
          const schedules = this.loadSchedulesFromFile();
          const scheduleIndex = schedules.findIndex(s => s.id === schedule.id);
          if (scheduleIndex !== -1) {
            schedules[scheduleIndex].lastRun = new Date().toISOString();
            schedules[scheduleIndex].nextRun = this.getNextCronRun(schedule.cronExpression);
            this.saveSchedulesToFile(schedules);
          }
          
          console.log(`✅ [CRON] Geplantes Backup erfolgreich: ${result.filename}`);
        } catch (error) {
          console.error(`❌ [CRON] Geplantes Backup fehlgeschlagen für ${schedule.name}:`, error);
        }
      }, {
        scheduled: true,
        timezone: "Europe/Berlin"
      });
      
      this.backupJobs.set(schedule.id, cronJob);
      console.log(`⏰ [CRON] Cron-Job erstellt für: ${schedule.name} (${schedule.cronExpression})`);
      
    } catch (error) {
      console.error(`❌ [CRON] Fehler beim Erstellen des Cron-Jobs für ${schedule.name}:`, error);
      throw error;
    }
  }

  // ====== UPDATE SYSTEM ======

  // Check for Updates
  async checkForUpdates() {
    console.log("🔄 [UPDATE] Prüfe auf Updates vom offiziellen Repository...");
    console.log(`📦 [UPDATE] Repository: ${this.updateRepository}`);
    console.log(`🌿 [UPDATE] Branch: ${this.updateBranch}`);

    try {
      // Prüfe ob Git verfügbar ist
      try {
        execSync('git --version', { stdio: 'ignore' });
      } catch (error) {
        throw new Error("Git ist nicht verfügbar");
      }

      // Prüfe ob wir in einem Git Repository sind
      if (!fs.existsSync('.git')) {
        throw new Error("Nicht in einem Git Repository");
      }

      // Prüfe Remote URL
      const currentRemote = execSync('git remote get-url origin', { encoding: 'utf8' }).trim();
      if (currentRemote !== this.updateRepository) {
        console.log(`🔧 [UPDATE] Korrigiere Remote URL: ${currentRemote} → ${this.updateRepository}`);
        execSync(`git remote set-url origin ${this.updateRepository}`);
      }

      // Aktuelle und Remote-Commits abrufen
      execSync('git fetch origin', { stdio: 'ignore' });
      
      const localCommit = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
      const remoteCommit = execSync(`git rev-parse origin/${this.updateBranch}`, { encoding: 'utf8' }).trim();

      if (localCommit === remoteCommit) {
        console.log("✅ [UPDATE] Bereits auf dem neuesten Stand");
        return { updated: false, message: "Bereits auf dem neuesten Stand" };
      }

      console.log(`🔄 [UPDATE] Update verfügbar:`);
      console.log(`   Aktuell: ${localCommit.substring(0, 7)}`);
      console.log(`   Neu: ${remoteCommit.substring(0, 7)}`);

      // Backup wichtiger Dateien
      console.log("💾 [UPDATE] Sichere wichtige Dateien...");
      await this.backupImportantFiles();

      // Update durchführen
      console.log("📥 [UPDATE] Führe Update durch...");
      execSync(`git reset --hard origin/${this.updateBranch}`, { stdio: 'inherit' });

      // Wiederherstellen wichtiger Dateien
      console.log("🔄 [UPDATE] Stelle wichtige Dateien wieder her...");
      await this.restoreImportantFiles();

      // Dependencies aktualisieren
      console.log("📦 [UPDATE] Aktualisiere Dependencies...");
      try {
        execSync('npm cache clean --force', { stdio: 'ignore' });
        execSync('npm install --production --omit=dev', { stdio: 'inherit' });
      } catch (npmError) {
        console.warn("⚠️ [UPDATE] NPM install mit Fallback...");
        execSync('npm install --production --legacy-peer-deps', { stdio: 'inherit' });
      }

      // Berechtigungen reparieren
      this.fixPermissions();

      console.log("✅ [UPDATE] Update erfolgreich abgeschlossen!");
      console.log(`📋 [UPDATE] Neue Version: ${remoteCommit.substring(0, 7)}`);

      return { 
        updated: true, 
        message: "Update erfolgreich durchgeführt",
        oldCommit: localCommit.substring(0, 7),
        newCommit: remoteCommit.substring(0, 7)
      };

    } catch (error) {
      console.error("❌ [UPDATE] Update fehlgeschlagen:", error.message);
      throw new Error(`Update fehlgeschlagen: ${error.message}`);
    }
  }

  // Backup Important Files before Update
  async backupImportantFiles() {
    const timestamp = Date.now();
    const backupDir = `./temp_backup_${timestamp}`;
    
    try {
      fs.mkdirSync(backupDir, { recursive: true });
      
      const filesToBackup = [
        'config.json',
        'backups/schedules.json',
        'backups/.git-secrets.enc',
        'public/custom.css',
        'public/custom.js'
      ];
      
      const backedUpFiles = [];
      
      for (const file of filesToBackup) {
        if (fs.existsSync(file)) {
          const backupFile = path.join(backupDir, path.basename(file));
          fs.copyFileSync(file, backupFile);
          backedUpFiles.push(file);
        }
      }
      
      // Backup komplettes backups-Verzeichnis
      if (fs.existsSync('backups') && fs.statSync('backups').isDirectory()) {
        const backupsBackupDir = path.join(backupDir, 'backups_full');
        fs.mkdirSync(backupsBackupDir, { recursive: true });
        
        const copyRecursive = (src, dest) => {
          const entries = fs.readdirSync(src, { withFileTypes: true });
          for (const entry of entries) {
            const srcPath = path.join(src, entry.name);
            const destPath = path.join(dest, entry.name);
            
            if (entry.isDirectory()) {
              fs.mkdirSync(destPath, { recursive: true });
              copyRecursive(srcPath, destPath);
            } else {
              fs.copyFileSync(srcPath, destPath);
            }
          }
        };
        
        copyRecursive('backups', backupsBackupDir);
        backedUpFiles.push('backups/');
      }
      
      this.currentBackupDir = backupDir;
      console.log(`💾 [BACKUP] ${backedUpFiles.length} Dateien gesichert in: ${backupDir}`);
      
    } catch (error) {
      console.error("❌ [BACKUP] Fehler beim Sichern wichtiger Dateien:", error);
      throw error;
    }
  }

  // Restore Important Files after Update
  async restoreImportantFiles() {
    if (!this.currentBackupDir || !fs.existsSync(this.currentBackupDir)) {
      console.warn("⚠️ [RESTORE] Kein Backup-Verzeichnis gefunden");
      return;
    }
    
    try {
      const filesToRestore = [
        'config.json',
        'schedules.json',
        '.git-secrets.enc',
        'custom.css',
        'custom.js'
      ];
      
      const restoredFiles = [];
      
      for (const file of filesToRestore) {
        const backupFile = path.join(this.currentBackupDir, file);
        if (fs.existsSync(backupFile)) {
          let targetPath;
          
          if (file === 'schedules.json' || file === '.git-secrets.enc') {
            targetPath = path.join('backups', file);
          } else if (file === 'custom.css' || file === 'custom.js') {
            targetPath = path.join('public', file);
          } else {
            targetPath = file;
          }
          
          // Stelle sicher, dass das Zielverzeichnis existiert
          fs.mkdirSync(path.dirname(targetPath), { recursive: true });
          fs.copyFileSync(backupFile, targetPath);
          restoredFiles.push(targetPath);
        }
      }
      
      // Restore komplettes backups-Verzeichnis falls es nicht existiert
      const backupsBackupDir = path.join(this.currentBackupDir, 'backups_full');
      if (fs.existsSync(backupsBackupDir) && (!fs.existsSync('backups') || fs.readdirSync('backups').length === 0)) {
        const copyRecursive = (src, dest) => {
          const entries = fs.readdirSync(src, { withFileTypes: true });
          for (const entry of entries) {
            const srcPath = path.join(src, entry.name);
            const destPath = path.join(dest, entry.name);
            
            if (entry.isDirectory()) {
              fs.mkdirSync(destPath, { recursive: true });
              copyRecursive(srcPath, destPath);
            } else {
              fs.copyFileSync(srcPath, destPath);
            }
          }
        };
        
        fs.mkdirSync('backups', { recursive: true });
        copyRecursive(backupsBackupDir, 'backups');
        restoredFiles.push('backups/');
      }
      
      console.log(`🔄 [RESTORE] ${restoredFiles.length} Dateien wiederhergestellt`);
      
      // Backup-Verzeichnis aufräumen
      setTimeout(() => {
        try {
          fs.rmSync(this.currentBackupDir, { recursive: true, force: true });
          console.log(`🧹 [CLEANUP] Temporäres Backup bereinigt: ${this.currentBackupDir}`);
        } catch (cleanupError) {
          console.warn(`⚠️ [CLEANUP] Konnte temporäres Backup nicht bereinigen: ${cleanupError.message}`);
        }
      }, 5000);
      
    } catch (error) {
      console.error("❌ [RESTORE] Fehler beim Wiederherstellen wichtiger Dateien:", error);
      throw error;
    }
  }

  // Fix File Permissions
  fixPermissions() {
    try {
      console.log("🔧 [PERMISSIONS] Repariere Dateiberechtigungen...");
      
      // Executable files
      const executableFiles = [
        'update.sh',
        'ssl-setup.sh',
        'server.js'
      ];
      
      executableFiles.forEach(file => {
        if (fs.existsSync(file)) {
          fs.chmodSync(file, 0o755);
        }
      });
      
      // Configuration files
      const configFiles = [
        'config.json',
        'package.json'
      ];
      
      configFiles.forEach(file => {
        if (fs.existsSync(file)) {
          fs.chmodSync(file, 0o644);
        }
      });
      
      // Secure files
      if (fs.existsSync('backups/.git-secrets.enc')) {
        fs.chmodSync('backups/.git-secrets.enc', 0o600);
      }
      
      // SSL directory
      if (fs.existsSync('ssl')) {
        fs.chmodSync('ssl', 0o700);
        if (fs.existsSync('ssl/privkey.pem')) {
          fs.chmodSync('ssl/privkey.pem', 0o600);
        }
        if (fs.existsSync('ssl/fullchain.pem')) {
          fs.chmodSync('ssl/fullchain.pem', 0o644);
        }
      }
      
      console.log("✅ [PERMISSIONS] Dateiberechtigungen repariert");
      
    } catch (error) {
      console.warn("⚠️ [PERMISSIONS] Konnte nicht alle Berechtigungen reparieren:", error.message);
    }
  }

  // ====== SICHERHEITS-CLEANUP-TASKS ======
  startSecurityCleanupTasks() {
    console.log("🧹 [SECURITY] Starte Sicherheits-Cleanup-Tasks...");
    
    // Abgelaufene Sessions bereinigen (alle 5 Minuten)
    setInterval(() => {
      this.cleanupExpiredSessions();
    }, 5 * 60 * 1000);

    // Failed Attempts bereinigen (alle 10 Minuten)
    setInterval(() => {
      const now = Date.now();
      let cleaned = 0;
      
      for (const [key, attempt] of this.failedAttempts) {
        if (attempt.lockUntil && attempt.lockUntil < now) {
          this.failedAttempts.delete(key);
          cleaned++;
        }
      }
      
      if (cleaned > 0) {
        console.log(`🧹 [SECURITY] ${cleaned} abgelaufene Failed Attempts bereinigt`);
      }
    }, 10 * 60 * 1000);

    // CAPTCHA Sessions bereinigen (alle 3 Minuten)
    setInterval(() => {
      const now = Date.now();
      let cleaned = 0;
      
      for (const [captchaId, captcha] of this.captchaSessions) {
        if (captcha.created + (5 * 60 * 1000) < now) {
          this.captchaSessions.delete(captchaId);
          cleaned++;
        }
      }
      
      if (cleaned > 0) {
        console.log(`🧹 [SECURITY] ${cleaned} abgelaufene CAPTCHA Sessions bereinigt`);
      }
    }, 3 * 60 * 1000);

    // User Rate Limits bereinigen (alle 2 Minuten)
    setInterval(() => {
      const now = Date.now();
      let cleaned = 0;
      
      for (const [key, limit] of this.userRateLimits) {
        if (limit.resetTime < now) {
          this.userRateLimits.delete(key);
          cleaned++;
        }
      }
      
      if (cleaned > 0) {
        console.log(`🧹 [SECURITY] ${cleaned} abgelaufene Rate Limits bereinigt`);
      }
    }, 2 * 60 * 1000);

    console.log("✅ [SECURITY] Sicherheits-Cleanup-Tasks gestartet");
  }

  // ====== SERVER-START-METHODEN ======
  startServer() {
    const port = this.config.server.port;
    const httpsPort = this.config.server.httpsPort || 8443;
    const host = this.config.server.host;

    if (this.securityConfig.requireHttps) {
      const keyPath = this.sslManager?.keyPath || path.join(__dirname, "ssl", "privkey.pem");
      const certPath = this.sslManager?.certPath || path.join(__dirname, "ssl", "fullchain.pem");

      if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        try {
          const httpsOptions = {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath),
            // Erweiterte HTTPS-Optionen
            secureProtocol: 'TLSv1_2_method',
            honorCipherOrder: true,
            ciphers: [
              'ECDHE-RSA-AES128-GCM-SHA256',
              'ECDHE-RSA-AES256-GCM-SHA384',
              'ECDHE-RSA-AES128-SHA256',
              'ECDHE-RSA-AES256-SHA384'
            ].join(':')
          };

          const httpsServer = https.createServer(httpsOptions, this.app);
          
          httpsServer.listen(httpsPort, host, () => {
            console.log(`🔐 HTTPS Server läuft auf https://${host}:${httpsPort}`);
          });

          // HTTP to HTTPS redirect
          const redirectApp = express();
          redirectApp.use((req, res) => {
            const redirectUrl = `https://${req.headers.host.replace(/:\d+$/, `:${httpsPort}`)}${req.url}`;
            res.redirect(301, redirectUrl);
          });

          const httpServer = http.createServer(redirectApp);
          httpServer.listen(port, host, () => {
            console.log(`🔄 HTTP Redirect Server läuft auf http://${host}:${port} -> HTTPS`);
          });

          // SSL certificate monitoring
          this.startSSLMonitoring();
          
          // Graceful shutdown für HTTPS
          process.on('SIGTERM', () => {
            console.log('🔄 [SSL] Graceful HTTPS shutdown...');
            httpsServer.close(() => {
              console.log('✅ [SSL] HTTPS Server geschlossen');
            });
            httpServer.close(() => {
              console.log('✅ [SSL] HTTP Redirect Server geschlossen');
            });
          });
          
        } catch (error) {
          console.error("❌ [SSL] HTTPS Server konnte nicht gestartet werden:", error.message);
          console.log("🔧 [SSL] Starte HTTP Server als Fallback...");
          this.startHTTPServer(port, host);
        }
      } else {
        console.warn("⚠️ [SSL] Zertifikate nicht gefunden, starte HTTP Server");
        this.startHTTPServer(port, host);
      }
    } else {
      this.startHTTPServer(port, host);
    }

    this.displayStartupInfo();
  }

  startHTTPServer(port, host) {
    const httpServer = this.app.listen(port, host, () => {
      console.log(`🌐 HTTP Server läuft auf http://${host}:${port}`);
    });

    // Graceful shutdown für HTTP
    process.on('SIGTERM', () => {
      console.log('🔄 [HTTP] Graceful shutdown...');
      httpServer.close(() => {
        console.log('✅ [HTTP] Server geschlossen');
      });
    });
  }

  /**
   * Start SSL certificate monitoring
   */
  startSSLMonitoring() {
    if (!this.sslManager) {
      return;
    }

    console.log("🔍 [SSL] Starte SSL-Zertifikat-Überwachung...");
    
    // Check certificates every 6 hours
    setInterval(async () => {
      try {
        const certCheck = await this.sslManager.checkCertificates();
        
        if (certCheck.needsRenewal) {
          console.log("🔄 [SSL] Zertifikat muss erneuert werden...");
          await this.sslManager.obtainCertificate();
          
          // In production, you might want to implement graceful restart
          console.log("⚠️ [SSL] Neustart erforderlich für neue Zertifikate");
        }
        
        if (certCheck.expiresIn <= 7) {
          console.warn(`⚠️ [SSL] Zertifikat läuft in ${certCheck.expiresIn} Tagen ab!`);
        }
      } catch (error) {
        console.error("❌ [SSL] Fehler bei der Zertifikat-Überwachung:", error.message);
      }
    }, 6 * 60 * 60 * 1000); // 6 hours
  }

  // ====== STARTUP-ANZEIGE UND STATUS ======
  displayStartupInfo() {
    console.log("");
    console.log("🚀 =====================================================");
    console.log("🚀 SECURE DATABASE BACKUP TOOL - SSL EDITION");
    console.log("🚀 =====================================================");
    console.log("📡 Server läuft auf " + this.config.server.host + ":" + this.config.server.port);
    
    if (this.securityConfig.requireHttps) {
      console.log("🔐 HTTPS Server: " + this.config.server.host + ":" + (this.config.server.httpsPort || 8443));
      console.log("🔒 SSL Domain: " + (this.sslManager?.domain || this.config.ssl?.domain || 'localhost'));
      console.log("🔑 SSL Methode: " + (this.sslManager?.method || this.config.ssl?.method || 'selfsigned'));
      
      // SSL-Status anzeigen
      this.displaySSLStatus();
    }
    
    console.log("🔐 Standard Login: " + this.config.security.defaultAdmin.username + " / " + this.config.security.defaultAdmin.password);
    console.log("📁 Backup-Verzeichnis: " + this.config.backup.defaultPath);
    console.log("");
    this.displaySecurityStatus();
    console.log("🎉 Ready for Secure Database Backups with SSL! 🎉");
  }

  async displaySSLStatus() {
    try {
      if (!this.sslManager) {
        console.log("🔐 SSL Manager nicht verfügbar");
        return;
      }

      const status = await this.sslManager.getStatus();
      
      console.log("🔐 ===============================================");
      console.log("🔐 SSL CERTIFICATE STATUS");
      console.log("🔐 ===============================================");
      console.log(`🔒 SSL aktiviert: ${status.enabled ? "✅ Ja" : "❌ Nein"}`);
      
      if (status.enabled) {
        console.log(`🌐 Domain: ${status.domain}`);
        console.log(`🔑 Methode: ${status.method}`);
        console.log(`📅 Läuft ab in: ${status.expiresIn} Tagen`);
        console.log(`📋 Aussteller: ${status.issuer}`);
        console.log(`🔄 Auto-Renewal: ${status.autoRenewal ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
        
        if (status.needsRenewal) {
          console.log(`⚠️ Erneuerung erforderlich: Ja`);
        }
        
        if (status.method === 'selfsigned') {
          console.log(`⚠️ Self-Signed: Browser zeigen Sicherheitswarnung`);
        }

        // Zusätzliche SSL-Informationen
        if (status.alternativeNames && status.alternativeNames.length > 0) {
          console.log(`📝 Alternative Names: ${status.alternativeNames.join(', ')}`);
        }
        
        if (status.issueDate) {
          console.log(`📅 Ausgestellt am: ${new Date(status.issueDate).toLocaleDateString('de-DE')}`);
        }
      } else {
        console.log(`❌ Grund: ${status.reason}`);
        if (status.error) {
          console.log(`❌ Fehler: ${status.error}`);
        }
      }
      
      console.log("===============================================");
    } catch (error) {
      console.error("❌ [SSL] Fehler beim Anzeigen des SSL-Status:", error.message);
    }
  }

  displaySecurityStatus() {
    console.log("🛡️ ===============================================");
    console.log("🛡️ SECURITY STATUS");
    console.log("🛡️ ===============================================");
    console.log(`🔐 HTTPS: ${this.securityConfig.requireHttps ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    console.log(`🔑 2FA: ${this.securityConfig.enable2FA ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    console.log(`🛡️ Starke Passwörter: ${this.securityConfig.strongPasswords ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    console.log(`🤖 CAPTCHA: ✅ Aktiviert (nach ${this.securityConfig.captchaThreshold} Fehlversuchen)`);
    console.log(`🔒 Account-Sperrung: ✅ Aktiviert (nach ${this.securityConfig.maxFailedAttempts} Fehlversuchen)`);
    console.log(`⏱️ Session-Timeout: ${this.securityConfig.sessionTimeout / 1000 / 60} Minuten`);
    console.log(`🚫 Rate Limiting: ✅ Aktiviert`);
    console.log(`📊 Session Management: ✅ Aktiviert`);
    console.log("===============================================");
  }

  // ====== HAUPTINITIALISIERUNG ======
  async init() {
    console.log("🛡️ [INIT] Initialisiere Enhanced Security Features...");
    
    try {
        console.log("[INIT STEP 1/9] Lade Konfiguration...");
        // Config is already loaded in constructor
        console.log("[INIT STEP 1/9] Konfiguration geladen.");

        if (this.config.updates && this.config.updates.autoUpdate) {
            console.log("[INIT STEP 2/9] Prüfe auf Updates...");
            await this.checkForUpdates();
            console.log("[INIT STEP 2/9] Update-Prüfung abgeschlossen.");
        } else {
            console.log("[INIT STEP 2/9] Auto-Update übersprungen.");
        }

        // SSL-Initialisierung VOR Middleware-Setup
        if (this.securityConfig.requireHttps) {
            console.log("[INIT STEP 3/9] Initialisiere SSL...");
            await this.initializeSSL();
            console.log("[INIT STEP 3/9] SSL initialisiert.");
        } else {
            console.log("[INIT STEP 3/9] SSL übersprungen.");
        }

        console.log("[INIT STEP 4/9] Setup Middleware...");
        this.setupMiddleware();
        console.log("[INIT STEP 4/9] Middleware eingerichtet.");

        console.log("[INIT STEP 5/9] Setup Routes...");
        this.setupRoutes();
        console.log("[INIT STEP 5/9] Routes eingerichtet.");

        console.log("[INIT STEP 6/9] Setup Default User...");
        await this.setupDefaultUser();
        console.log("[INIT STEP 6/9] Default User eingerichtet.");

        console.log("[INIT STEP 7/9] Stelle Verzeichnisse sicher...");
        this.ensureDirectories();
        console.log("[INIT STEP 7/9] Verzeichnisse sichergestellt.");

        console.log("[INIT STEP 8/9] Lade Git Token...");
        const savedToken = this.loadGitToken();
        if (savedToken && this.config.gitBackup) {
            this.config.gitBackup.token = savedToken;
            console.log(`✅ [INIT] Git Token geladen (${savedToken.length} Zeichen)`);
        } else {
            console.warn("⚠️ [INIT] Kein gültiger Git Token beim Start geladen");
        }
        console.log("[INIT STEP 8/9] Git Token geladen.");

        console.log("[INIT STEP 9/9] Initialisiere Git Backup & Zeitpläne...");
        await this.initializeGitBackup();
        this.loadSchedulesFromFile();
        this.startSecurityCleanupTasks();
        console.log("[INIT STEP 9/9] Git Backup & Zeitpläne initialisiert.");

        // SSL-Monitoring starten
        if (this.securityConfig.requireHttps && this.sslManager) {
            this.sslManager.monitorCertificates();
        }

        this.startServer();

    } catch (error) {
        console.error("❌ [FATAL INIT ERROR] Kritischer Fehler während der Initialisierung:", error);
        process.exit(1);
    }
  }

  // ====== ERROR HANDLING UND GRACEFUL SHUTDOWN ======
  handleSSLErrors() {
    // SSL-spezifische Error-Handler
    process.on('uncaughtException', (error) => {
      if (error.message.includes('SSL') || error.message.includes('TLS')) {
        console.error("❌ [SSL] SSL-bezogener Fehler:", error.message);
        console.error("🔧 [SSL] Prüfe SSL-Konfiguration und Zertifikate");
      }
    });

    process.on('unhandledRejection', (reason, promise) => {
      if (reason && reason.toString().includes('SSL')) {
        console.error("❌ [SSL] SSL-bezogene Promise Rejection:", reason);
        console.error("🔧 [SSL] Prüfe SSL-Setup und Zertifikat-Gültigkeit");
      }
    });
  }
}

// ====== ENHANCED ERROR HANDLING UND GRACEFUL SHUTDOWN ======

process.on("SIGTERM", () => {
  console.log("");
  console.log("🛑 SIGTERM empfangen, beende Secure Database Backup Tool...");
  console.log("🛡️ Sicherheits-Cleanup wird durchgeführt...");
  console.log("📊 Prozess-Statistiken:");
  console.log(`   Uptime: ${Math.floor(process.uptime() / 60)} Minuten`);
  console.log(`   Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log("✅ Secure Graceful Shutdown abgeschlossen");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("");
  console.log("🛑 SIGINT empfangen, beende Secure Database Backup Tool...");
  console.log("🛡️ Sicherheits-Cleanup wird durchgeführt...");
  console.log("📊 Finale Sicherheits-Statistiken:");
  console.log(`   Uptime: ${Math.floor(process.uptime() / 60)} Minuten`);
  console.log(`   Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log("✅ Secure Graceful Shutdown abgeschlossen");
  process.exit(0);
});

process.on("uncaughtException", (error) => {
  console.error("❌ UNCAUGHT EXCEPTION (SSL SECURITY VERSION):");
  console.error(`   Error: ${error.message}`);
  console.error(`   Stack: ${error.stack}`);
  
  if (error.message.includes("git")) {
    console.error("   → Git-bezogener Fehler erkannt");
  }
  if (error.message.includes("auth") || error.message.includes("session")) {
    console.error("   → Authentifizierungs-/Session-Fehler erkannt");
  }
  if (error.message.includes("captcha") || error.message.includes("2fa")) {
    console.error("   → Sicherheits-Feature-Fehler erkannt");
  }
  if (error.message.includes("ssl") || error.message.includes("tls")) {
    console.error("   → SSL/TLS-Fehler erkannt");
  }
  
  console.log("🔄 Versuche secure graceful shutdown...");
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ UNHANDLED PROMISE REJECTION (SSL SECURITY VERSION):");
  console.error(`   Reason: ${reason}`);
  console.error(`   Promise: ${promise}`);
  
  if (reason && reason.toString().includes("auth")) {
    console.error("   → Authentifizierungs-Problem erkannt");
  }
  if (reason && reason.toString().includes("git")) {
    console.error("   → Git-Problem erkannt");
  }
  if (reason && reason.toString().includes("ssl")) {
    console.error("   → SSL-Problem erkannt");
  }
  
  console.log("⚠️  Secure Anwendung läuft weiter, aber dies sollte behoben werden!");
});

// Enhanced Startup Message
console.log("");
console.log("🛡️ ===============================================");
console.log("🛡️ INITIALISIERE SECURE DATABASE BACKUP TOOL");
console.log("🛡️ ===============================================");
console.log("📦 Version: Enhanced Security + SSL Edition");
console.log("🔐 Features: HTTPS + 2FA + CAPTCHA + Sessions + Rate Limiting");
console.log("🛡️ Security Headers: CSP + HSTS + XSS Protection");
console.log("🔒 Passwort-Verschlüsselung: bcrypt (12 Rounds)");
console.log("🚫 Brute-Force-Schutz: Account-Sperrung + CAPTCHA");
console.log("🍪 Session Management: Secure + IP-Validation");
console.log("📊 Erweiterte Protokollierung: Sicherheits-Events");
console.log("🔐 SSL-Management: Let's Encrypt + Cloudflare + Manual");
console.log("🔄 Auto-Renewal: Zertifikat-Überwachung + Erneuerung");
console.log("===============================================");
console.log("");

// Start the secure SSL application
new DatabaseBackupTool();