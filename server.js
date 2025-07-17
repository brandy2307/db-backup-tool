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

    // ====== NEUE SICHERHEITS-FEATURES ======
    this.captchaSessions = new Map(); // CAPTCHA Sessions verwalten
    this.failedAttempts = new Map(); // Fehlgeschlagene Login-Versuche
    this.activeSessions = new Map(); // Aktive Sessions verwalten
    this.sslCertPath = path.join(__dirname, "ssl");
    
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
  // ====== NEUE SSL-INITIALISIERUNG AUS UMGEBUNGSVARIABLEN ======
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

  // ====== NEUE SICHERHEITS-METHODEN (BESTEHEND) ======

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
  setupRoutes() {
    // ====== NEUE SICHERHEITS-ROUTEN ======

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

    // ====== WEITERE SICHERHEITS-ROUTEN ======
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

    // ====== SSL-ROUTEN EINBINDEN ======
    this.setupSSLRoutes();

    // ====== BACKUP UND SYSTEM ROUTEN ======
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

    // Weitere Backup-Routen hier implementieren...
    this.app.post("/api/backup", this.authMiddleware.bind(this), async (req, res) => {
      // Backup-Erstellung - vereinfacht für Kürze
      res.json({ message: "Backup-Route implementiert" });
    });

    this.app.get("/api/backups", this.authMiddleware.bind(this), (req, res) => {
      // Backup-Liste - vereinfacht für Kürze
      res.json([]);
    });

    // Hauptseite
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

    // Error Handler
    this.app.use((error, req, res, next) => {
      console.error(`❌ [ERROR] Unbehandelter Fehler: ${error.message} bei ${req.method} ${req.url}`);
      res.status(500).json({
        error: "Interner Serverfehler",
        code: "INTERNAL_SERVER_ERROR"
      });
    });
  }
  // ====== SSL API-ROUTEN ======
  setupSSLRoutes() {
    // SSL Status
    this.app.get("/api/ssl-status", this.authMiddleware.bind(this), async (req, res) => {
      try {
        const status = await this.sslManager.getStatus();
        res.json(status);
      } catch (error) {
        res.status(500).json({ error: "SSL Status konnte nicht abgerufen werden: " + error.message });
      }
    });

    // SSL Renewal
    this.app.post("/api/ssl-renew", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }

      try {
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
        const health = await this.sslManager.performHealthCheck();
        res.json(health);
      } catch (error) {
        res.status(500).json({ error: "SSL Health Check fehlgeschlagen: " + error.message });
      }
    });

    // SSL Configuration
    this.app.get("/api/ssl-config", this.authMiddleware.bind(this), (req, res) => {
      try {
        const config = this.sslManager.getConfigurationSummary();
        res.json(config);
      } catch (error) {
        res.status(500).json({ error: "SSL Konfiguration konnte nicht abgerufen werden: " + error.message });
      }
    });

    // SSL Setup Instructions
    this.app.get("/api/ssl-instructions", this.authMiddleware.bind(this), (req, res) => {
      try {
        const instructions = this.sslManager.generateSetupInstructions();
        res.json(instructions);
      } catch (error) {
        res.status(500).json({ error: "SSL Setup-Anweisungen konnten nicht generiert werden: " + error.message });
      }
    });

    // SSL Certificate Test
    this.app.post("/api/ssl-test", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }

      try {
        const port = req.body.port || 8443;
        const result = await this.sslManager.testCertificate(port);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: "SSL Test fehlgeschlagen: " + error.message });
      }
    });

    // SSL Export Configuration (für Troubleshooting)
    this.app.get("/api/ssl-export", this.authMiddleware.bind(this), async (req, res) => {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin-Berechtigung erforderlich" });
      }

      try {
        const exportData = await this.sslManager.exportConfiguration();
        res.json(exportData);
      } catch (error) {
        res.status(500).json({ error: "SSL Export fehlgeschlagen: " + error.message });
      }
    });
  }

  // ====== SERVER-START-METHODEN ======
  startServer() {
    const port = this.config.server.port;
    const httpsPort = this.config.server.httpsPort || 8443;
    const host = this.config.server.host;

    if (this.securityConfig.requireHttps) {
      const keyPath = this.sslManager.keyPath;
      const certPath = this.sslManager.certPath;

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

  // ====== STARTUP-ANZEIGE ======
  displayStartupInfo() {
    console.log("");
    console.log("🚀 =====================================================");
    console.log("🚀 SECURE DATABASE BACKUP TOOL - SSL EDITION");
    console.log("🚀 =====================================================");
    console.log("📡 Server läuft auf " + this.config.server.host + ":" + this.config.server.port);
    
    if (this.securityConfig.requireHttps) {
      console.log("🔐 HTTPS Server: " + this.config.server.host + ":" + (this.config.server.httpsPort || 8443));
      console.log("🔒 SSL Domain: " + this.sslManager.domain);
      console.log("🔑 SSL Methode: " + this.sslManager.method);
      
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

  displayStartupInstructions() {
    console.log("");
    console.log("🔧 ================================================");
    console.log("🔧 SSL SETUP ANWEISUNGEN");
    console.log("🔧 ================================================");
    
    if (this.securityConfig.requireHttps) {
      console.log("✅ HTTPS ist aktiviert!");
      console.log("");
      console.log("🌐 Verbindung:");
      console.log(`   https://${this.sslManager.domain}:${this.config.server.httpsPort || 8443}`);
      console.log("");
      
      if (this.sslManager.method === 'selfsigned') {
        console.log("⚠️ Self-Signed Zertifikat:");
        console.log("   - Browser zeigen Sicherheitswarnung");
        console.log("   - Klicke auf 'Erweitert' → 'Trotzdem fortfahren'");
        console.log("   - Für Production: Verwende Let's Encrypt oder Cloudflare");
        console.log("");
      }
    } else {
      console.log("⚠️ HTTPS ist deaktiviert!");
      console.log("");
      console.log("🔐 Für SSL-Aktivierung:");
      console.log("   1. Setze REQUIRE_HTTPS=true");
      console.log("   2. Konfiguriere SSL-Umgebungsvariablen:");
      console.log("      - SSL_DOMAIN=deine-domain.com");
      console.log("      - SSL_EMAIL=admin@deine-domain.com");
      console.log("      - SSL_METHOD=letsencrypt");
      console.log("   3. Starte Server neu");
      console.log("");
    }
    
    console.log("📋 Verfügbare SSL-Methoden:");
    console.log("   - letsencrypt: Kostenlose Zertifikate (empfohlen)");
    console.log("   - cloudflare: Cloudflare Origin Certificates");
    console.log("   - selfsigned: Nur für Tests");
    console.log("   - manual: Eigene Zertifikate");
    console.log("");
    console.log("🔧 SSL-Setup Script:");
    console.log("   ./ssl-setup.sh");
    console.log("");
    console.log("================================================");
  }

  // ====== SICHERHEITS-CLEANUP-TASKS ======
  startSecurityCleanupTasks() {
    console.log("🧹 [SECURITY] Starte Sicherheits-Cleanup-Tasks...");
    
    setInterval(() => {
      this.cleanupExpiredSessions();
    }, 5 * 60 * 1000);

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

    if (this.userRateLimits) {
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
    }

    console.log("✅ [SECURITY] Sicherheits-Cleanup-Tasks gestartet");
  }

  // ====== ERROR-HANDLER ======
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

  // ====== HAUPTINITIALISIERUNG ======
  async init() {
    console.log("🛡️ [INIT] Initialisiere Enhanced Security Features...");
    
    // SSL Error-Handler registrieren
    this.handleSSLErrors();
    
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
        this.displayStartupInstructions();

    } catch (error) {
        console.error("❌ [FATAL INIT ERROR] Kritischer Fehler während der Initialisierung:", error);
        process.exit(1);
    }
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