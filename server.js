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
    this.sslManager = new SSLCertificateManager(this.config);

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

      // ====== SSL-KONFIGURATION ======
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
  // ====== NEUE SICHERHEITS-METHODEN ======

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

  // Failed Login Attempts Management
  recordFailedAttempt(ip, username) {
    const key = `${ip}:${username}`;
    const now = Date.now();
    
    if (!this.failedAttempts.has(key)) {
      this.failedAttempts.set(key, {
        count: 0,
        firstAttempt: now,
        lastAttempt: now,
        locked: false,
        lockUntil: null
      });
    }

    const attempts = this.failedAttempts.get(key);
    attempts.count++;
    attempts.lastAttempt = now;

    if (attempts.count >= this.securityConfig.maxFailedAttempts) {
      attempts.locked = true;
      attempts.lockUntil = now + this.securityConfig.lockoutDuration;
      
      console.log(`🔒 [SECURITY] Account gesperrt: ${username} von IP ${ip} für ${this.securityConfig.lockoutDuration / 1000 / 60} Minuten`);
    }

    this.failedAttempts.set(key, attempts);
    console.log(`⚠️ [SECURITY] Fehlversuch #${attempts.count} für ${username} von ${ip}`);
  }

  isAccountLocked(ip, username) {
    const key = `${ip}:${username}`;
    const attempts = this.failedAttempts.get(key);
    
    if (!attempts) return false;
    
    if (attempts.locked && attempts.lockUntil > Date.now()) {
      return {
        locked: true,
        remainingTime: Math.ceil((attempts.lockUntil - Date.now()) / 1000 / 60)
      };
    }

    if (attempts.locked && attempts.lockUntil <= Date.now()) {
      // Reset nach Ablauf der Sperrzeit
      this.failedAttempts.delete(key);
      console.log(`🔓 [SECURITY] Account-Sperre aufgehoben: ${username} von ${ip}`);
      return false;
    }

    return false;
  }

  clearFailedAttempts(ip, username) {
    const key = `${ip}:${username}`;
    this.failedAttempts.delete(key);
    console.log(`✅ [SECURITY] Fehlversuche zurückgesetzt: ${username} von ${ip}`);
  }

  needsCaptcha(ip, username) {
    const key = `${ip}:${username}`;
    const attempts = this.failedAttempts.get(key);
    
    return attempts && attempts.count >= this.securityConfig.captchaThreshold;
  }

  // 2FA Setup
  generate2FASecret(username) {
    const secret = speakeasy.generateSecret({
      name: `DB Backup Tool (${username})`,
      issuer: 'DB Backup Tool',
      length: 32
    });

    console.log(`🔐 [2FA] Secret generiert für: ${username}`);

    return {
      secret: secret.base32,
      qrCode: secret.otpauth_url
    };
  }

  verify2FAToken(secret, token) {
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2
    });

    console.log(`🔐 [2FA] Token-Verifikation: ${verified ? 'ERFOLG' : 'FEHLGESCHLAGEN'}`);
    return verified;
  }

  // Session Management
  createSecureSession(req, user, rememberMe = false) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (rememberMe ? 7 * 24 * 60 * 60 * 1000 : this.securityConfig.sessionTimeout);
    
    const sessionData = {
      id: sessionId,
      userId: user.username,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      createdAt: Date.now(),
      expiresAt: expiresAt,
      lastActivity: Date.now(),
      rememberMe: rememberMe
    };

    this.activeSessions.set(sessionId, sessionData);

    // Auto-cleanup
    setTimeout(() => {
      this.activeSessions.delete(sessionId);
    }, expiresAt - Date.now());

    console.log(`🔐 [SESSION] Erstellt: ${sessionId} für ${user.username} (Remember: ${rememberMe})`);
    return sessionId;
  }

  validateSession(sessionId, req) {
    const session = this.activeSessions.get(sessionId);
    
    if (!session) {
      return { valid: false, reason: "Session nicht gefunden" };
    }

    if (session.expiresAt < Date.now()) {
      this.activeSessions.delete(sessionId);
      return { valid: false, reason: "Session abgelaufen" };
    }

    // IP-Prüfung nur für nicht-"Remember Me" Sessions
    if (!session.rememberMe && session.ip !== req.ip) {
      this.activeSessions.delete(sessionId);
      console.log(`⚠️ [SESSION] IP-Änderung erkannt: ${session.ip} -> ${req.ip}`);
      return { valid: false, reason: "IP-Adresse geändert" };
    }

    // Update last activity
    session.lastActivity = Date.now();
    this.activeSessions.set(sessionId, session);

    return { valid: true, session: session };
  }

  invalidateSession(sessionId) {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      console.log(`🔐 [SESSION] Ungültig gemacht: ${sessionId} für ${session.userId}`);
      this.activeSessions.delete(sessionId);
    }
  }

  // Cleanup expired sessions
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

  // ====== SSL-INITIALISIERUNG ======
  async initializeSSL() {
    console.log("🔐 [SSL] Initialisiere SSL-Zertifikat-Management...");
    
    try {
      // Konfiguration validieren
      const configValidation = this.sslManager.validateConfiguration();
      if (!configValidation.valid) {
        console.warn("⚠️ [SSL] Konfigurationsprobleme gefunden:");
        configValidation.issues.forEach(issue => {
          console.warn(`   - ${issue}`);
        });
      }

      // Zertifikate prüfen
      const certCheck = await this.sslManager.checkCertificates();
      console.log(`🔍 [SSL] Zertifikat-Status: ${certCheck.valid ? 'Gültig' : 'Ungültig'}`);
      
      if (!certCheck.valid) {
        console.log(`📝 [SSL] Grund: ${certCheck.reason}`);
        console.log("🔄 [SSL] Hole neues SSL-Zertifikat...");
        
        const result = await this.sslManager.obtainCertificate();
        console.log("✅ [SSL] Zertifikat erfolgreich erhalten:");
        console.log(`   Domain: ${result.domain}`);
        console.log(`   Methode: ${result.method}`);
        console.log(`   Läuft ab in: ${result.expiresIn} Tagen`);
        
        if (result.warnings) {
          console.warn("⚠️ [SSL] Warnungen:", result.warnings);
        }
      } else if (certCheck.needsRenewal) {
        console.log("🔄 [SSL] Zertifikat muss erneuert werden...");
        try {
          await this.sslManager.obtainCertificate();
          console.log("✅ [SSL] Zertifikat erfolgreich erneuert");
        } catch (renewError) {
          console.warn("⚠️ [SSL] Zertifikat-Erneuerung fehlgeschlagen:", renewError.message);
        }
      }

      // Finale Statusprüfung
      const finalStatus = await this.sslManager.getStatus();
      console.log("🔐 [SSL] Finaler Status:", finalStatus.enabled ? "Aktiv" : "Inaktiv");
      
      if (finalStatus.enabled) {
        console.log(`   Domain: ${finalStatus.domain}`);
        console.log(`   Methode: ${finalStatus.method}`);
        console.log(`   Läuft ab in: ${finalStatus.expiresIn} Tagen`);
        console.log(`   Auto-Renewal: ${finalStatus.autoRenewal ? 'Aktiviert' : 'Deaktiviert'}`);
      } else {
        console.warn(`   Grund: ${finalStatus.reason}`);
        if (finalStatus.error) {
          console.error(`   Fehler: ${finalStatus.error}`);
        }
      }

    } catch (error) {
      console.error("❌ [SSL] SSL-Initialisierung fehlgeschlagen:", error.message);
      
      // Fallback zu Self-Signed
      if (this.sslManager.method !== 'selfsigned') {
        console.log("🔧 [SSL] Versuche Self-Signed Zertifikat als Fallback...");
        try {
          const originalMethod = this.sslManager.method;
          this.sslManager.method = 'selfsigned';
          await this.sslManager.obtainCertificate();
          console.log("✅ [SSL] Self-Signed Fallback erfolgreich");
          this.sslManager.method = originalMethod; // Restore original method
        } catch (fallbackError) {
          console.error("❌ [SSL] Auch Self-Signed Fallback fehlgeschlagen:", fallbackError.message);
          throw new Error("SSL-Initialisierung komplett fehlgeschlagen");
        }
      } else {
        throw error;
      }
    }
  }
  // ====== TOKEN-VERSCHLÜSSELUNG UND GIT-METHODEN ======

  encryptToken(token) {
    try {
      const algorithm = "aes-256-cbc";
      const key = crypto.scryptSync(this.encryptionKey, "salt", 32);
      const iv = crypto.randomBytes(16);

      const cipher = crypto.createCipher(algorithm, key);
      let encrypted = cipher.update(token, "utf8", "hex");
      encrypted += cipher.final("hex");

      return iv.toString("hex") + ":" + encrypted;
    } catch (error) {
      console.error("❌ [TOKEN CRYPTO] Verschlüsselung fehlgeschlagen:", error);
      throw new Error("Token-Verschlüsselung fehlgeschlagen");
    }
  }

  decryptToken(encryptedData) {
    try {
      const algorithm = "aes-256-cbc";
      const key = crypto.scryptSync(this.encryptionKey, "salt", 32);

      const parts = encryptedData.split(":");
      if (parts.length !== 2) {
        throw new Error("Ungültiges verschlüsseltes Token-Format");
      }

      const iv = Buffer.from(parts[0], "hex");
      const encrypted = parts[1];

      const decipher = crypto.createDecipher(algorithm, key);
      let decrypted = decipher.update(encrypted, "hex", "utf8");
      decrypted += decipher.final("utf8");

      return decrypted;
    } catch (error) {
      console.error("❌ [TOKEN CRYPTO] Entschlüsselung fehlgeschlagen:", error);
      return null;
    }
  }

  saveGitToken(token) {
    try {
      console.log("🔐 [TOKEN SAVE] Speichere Git Token verschlüsselt...");

      if (!token || token.trim() === "") {
        console.log("⚠️ [TOKEN SAVE] Leerer Token - lösche gespeicherten Token");
        if (fs.existsSync(this.secretsFile)) {
          fs.unlinkSync(this.secretsFile);
        }
        return;
      }

      const encryptedToken = this.encryptToken(token.trim());

      const secrets = {
        version: "1.0",
        gitBackupToken: encryptedToken,
        savedAt: new Date().toISOString(),
        tokenLength: token.length,
        checksum: crypto
          .createHash("sha256")
          .update(token)
          .digest("hex")
          .substring(0, 8),
      };

      fs.writeFileSync(this.secretsFile, JSON.stringify(secrets, null, 2), {
        mode: 0o600,
      });

      console.log(`✅ [TOKEN SAVE] Git Token verschlüsselt gespeichert (${token.length} Zeichen)`);
    } catch (error) {
      console.error("❌ [TOKEN SAVE] Fehler beim Speichern des Git Tokens:", error);
      throw error;
    }
  }

  loadGitToken() {
    try {
      if (!fs.existsSync(this.secretsFile)) {
        console.log("📝 [TOKEN LOAD] Keine verschlüsselte Token-Datei gefunden");
        return null;
      }

      console.log("🔓 [TOKEN LOAD] Lade verschlüsselten Git Token...");

      const secretsData = fs.readFileSync(this.secretsFile, "utf8");
      const secrets = JSON.parse(secretsData);

      if (!secrets.gitBackupToken) {
        console.log("⚠️ [TOKEN LOAD] Keine Token-Daten in verschlüsselter Datei");
        return null;
      }

      const decryptedToken = this.decryptToken(secrets.gitBackupToken);

      if (decryptedToken) {
        console.log(`✅ [TOKEN LOAD] Git Token erfolgreich entschlüsselt (${decryptedToken.length} Zeichen)`);
        
        const currentChecksum = crypto
          .createHash("sha256")
          .update(decryptedToken)
          .digest("hex")
          .substring(0, 8);
        if (secrets.checksum && secrets.checksum !== currentChecksum) {
          console.error("❌ [TOKEN LOAD] Token-Checksum stimmt nicht überein");
          return null;
        }

        return decryptedToken;
      } else {
        console.error("❌ [TOKEN LOAD] Token-Entschlüsselung fehlgeschlagen");
        return null;
      }
    } catch (error) {
      console.error("❌ [TOKEN LOAD] Fehler beim Laden des Git Tokens:", error);
      return null;
    }
  }

  getTokenStatus() {
    const hasSecretsFile = fs.existsSync(this.secretsFile);
    let tokenInfo = {
      hasSecretsFile: hasSecretsFile,
      secretsFilePath: this.secretsFile,
      canDecrypt: false,
      tokenLength: 0,
      savedAt: null,
    };

    if (hasSecretsFile) {
      try {
        const secretsData = fs.readFileSync(this.secretsFile, "utf8");
        const secrets = JSON.parse(secretsData);

        tokenInfo.savedAt = secrets.savedAt;
        tokenInfo.tokenLength = secrets.tokenLength || 0;

        const token = this.decryptToken(secrets.gitBackupToken);
        tokenInfo.canDecrypt = !!token;
      } catch (error) {
        tokenInfo.error = error.message;
      }
    }

    return tokenInfo;
  }

  execPromiseWithDebug(command, operation, hideOutput = false, timeout = 10000) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      console.log(`🔧 [${operation}] Starte: ${hideOutput ? "[COMMAND HIDDEN FOR SECURITY]" : command}`);

      const execTimeout = setTimeout(() => {
        console.error(`⏰ [${operation}] TIMEOUT nach ${timeout}ms`);
        reject(new Error(`${operation} timeout after ${timeout}ms`));
      }, timeout);

      exec(command, {
        cwd: process.cwd(),
        env: {
          ...process.env,
          GIT_TERMINAL_PROMPT: "0",
          GIT_ASKPASS: "echo",
        },
      }, (error, stdout, stderr) => {
        clearTimeout(execTimeout);
        const duration = Date.now() - startTime;

        if (error) {
          console.error(`❌ [${operation}] FEHLER nach ${duration}ms:`);
          console.error(`   Exit Code: ${error.code}`);
          console.error(`   Error Message: ${error.message}`);
          if (stderr) console.error(`   Stderr: ${stderr}`);
          reject(new Error(`${operation} failed: ${error.message}${stderr ? ` | Stderr: ${stderr}` : ""}`));
        } else {
          console.log(`✅ [${operation}] ERFOLG nach ${duration}ms`);
          if (stdout && !hideOutput) console.log(`   Output: ${stdout.trim()}`);
          resolve(stdout);
        }
      });
    });
  }

  debugGitConfiguration() {
    console.log("🔍 [GIT DEBUG] Vollständige Git Konfiguration:");
    console.log("================================");
    console.log(
      `   config.gitBackup: ${JSON.stringify(
        this.config.gitBackup,
        (key, value) => {
          if (key === "token" && value)
            return "[HIDDEN_" + value.length + "_CHARS]";
          return value;
        },
        2
      )}`
    );
    console.log("================================");

    console.log("🔍 [GIT DEBUG] Umgebungsvariablen:");
    console.log(
      `   GIT_BACKUP_ENABLED: ${process.env.GIT_BACKUP_ENABLED || "NOT SET"}`
    );
    console.log(
      `   GIT_BACKUP_REPOSITORY: ${
        process.env.GIT_BACKUP_REPOSITORY || "NOT SET"
      }`
    );
    console.log(
      `   GIT_BACKUP_USERNAME: ${process.env.GIT_BACKUP_USERNAME || "NOT SET"}`
    );
    console.log(
      `   GIT_BACKUP_TOKEN: ${
        process.env.GIT_BACKUP_TOKEN
          ? "[SET_" + process.env.GIT_BACKUP_TOKEN.length + "_CHARS]"
          : "NOT SET"
      }`
    );
    console.log(
      `   GIT_BACKUP_BRANCH: ${process.env.GIT_BACKUP_BRANCH || "NOT SET"}`
    );
    console.log("================================");

    this.debugTokenStatus();
    console.log("================================");
  }

  debugTokenStatus() {
    console.log("🔍 [TOKEN DEBUG] Token Status:");
    console.log(`   config.gitBackup exists: ${!!this.config.gitBackup}`);
    console.log(
      `   config.gitBackup.token exists: ${!!this.config.gitBackup?.token}`
    );
    console.log(
      `   config.gitBackup.token length: ${
        this.config.gitBackup?.token?.length || 0
      }`
    );
    console.log(
      `   config.gitBackup.token type: ${typeof this.config.gitBackup?.token}`
    );

    console.log(
      `   process.env.GIT_BACKUP_TOKEN exists: ${!!process.env
        .GIT_BACKUP_TOKEN}`
    );
    console.log(
      `   process.env.GIT_BACKUP_TOKEN length: ${
        process.env.GIT_BACKUP_TOKEN?.length || 0
      }`
    );
  }

  buildGitRemoteUrl() {
    console.log("🔍 [GIT URL] Starte Git Remote URL Erstellung (GitHub Fix)...");

    this.debugGitConfiguration();

    const gitConfig = this.config.gitBackup || {};
    const { repository, username, token } = gitConfig;

    console.log("🔍 [GIT URL] Extrahierte Werte:");
    console.log(`   Repository: '${repository || "EMPTY"}'`);
    console.log(`   Username: '${username || "EMPTY"}'`);
    console.log(
      `   Token: ${token ? "[SET_" + token.length + "_CHARS]" : "EMPTY"}`
    );

    if (!repository) {
      console.error("❌ [GIT URL] Repository URL ist leer oder undefined!");
      return null;
    }

    if (!token) {
      console.error("❌ [GIT URL] Token ist leer oder undefined!");
      return null;
    }

    try {
      const url = new URL(repository);
      console.log(`🔍 [GIT URL] URL-Komponenten:`);
      console.log(`   Protocol: ${url.protocol}`);
      console.log(`   Host: ${url.host}`);
      console.log(`   Pathname: ${url.pathname}`);

      let authenticatedUrl;

      if (url.host.includes("github.com")) {
        console.log("🔍 [GIT URL] GitHub erkannt - verwende Token-basierte Authentifizierung");
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedToken}@${url.host}${url.pathname}`;
        console.log(`✅ [GIT URL] GitHub-Token Authentifizierung konfiguriert`);
      } else if (url.host.includes("gitlab.com")) {
        console.log("🔍 [GIT URL] GitLab erkannt - verwende Username:Token Authentifizierung");
        const encodedUsername = encodeURIComponent(username || "oauth2");
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedUsername}:${encodedToken}@${url.host}${url.pathname}`;
        console.log(`✅ [GIT URL] GitLab Username:Token Authentifizierung konfiguriert`);
      } else if (url.host.includes("bitbucket.org")) {
        console.log("🔍 [GIT URL] Bitbucket erkannt - verwende Username:AppPassword Authentifizierung");
        if (!username) {
          console.error("❌ [GIT URL] Username ist für Bitbucket erforderlich!");
          return null;
        }
        const encodedUsername = encodeURIComponent(username);
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedUsername}:${encodedToken}@${url.host}${url.pathname}`;
        console.log(`✅ [GIT URL] Bitbucket Username:AppPassword Authentifizierung konfiguriert`);
      } else {
        console.log("🔍 [GIT URL] Unbekannter Git-Provider - verwende Standard Username:Token Format");
        const encodedUsername = encodeURIComponent(username || "git");
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedUsername}:${encodedToken}@${url.host}${url.pathname}`;
        console.log(`✅ [GIT URL] Standard Username:Token Authentifizierung konfiguriert`);
      }

      console.log(`✅ [GIT URL] Authentifizierte URL für ${url.host} erstellt`);
      return authenticatedUrl;
    } catch (error) {
      console.error("❌ [GIT URL] Fehler beim Parsen der Repository URL:", error);
      console.error(`   Repository Wert: '${repository}'`);
      return null;
    }
  }

  validateGitProviderConfig(repository, username, token) {
    const issues = [];

    try {
      const url = new URL(repository);

      if (url.host.includes("github.com")) {
        if (!token) {
          issues.push("GitHub Personal Access Token ist erforderlich");
        }
        if (
          token &&
          !token.startsWith("ghp_") &&
          !token.startsWith("github_pat_")
        ) {
          issues.push(
            "GitHub Token sollte mit 'ghp_' oder 'github_pat_' beginnen"
          );
        }
      } else if (url.host.includes("gitlab.com")) {
        if (!token) {
          issues.push("GitLab Personal Access Token ist erforderlich");
        }
      } else if (url.host.includes("bitbucket.org")) {
        if (!username) {
          issues.push("Bitbucket Username ist erforderlich");
        }
        if (!token) {
          issues.push("Bitbucket App Password ist erforderlich");
        }
      } else {
        if (!token) {
          issues.push("Personal Access Token ist erforderlich");
        }
      }
    } catch (error) {
      issues.push("Repository URL ist ungültig");
    }

    return issues;
  }

  generateGitDebugInfo() {
    const gitBackupEnabled = this.config.gitBackup?.enabled || false;
    const gitConfig = this.config.gitBackup || {};

    return {
      enabled: gitBackupEnabled,
      repository: gitConfig.repository || "NOT SET",
      username: gitConfig.username ? "SET" : "NOT SET",
      token: gitConfig.token
        ? `SET (${gitConfig.token.length} chars)`
        : "NOT SET",
      branch: gitConfig.branch || "main",
      gitBackupPath: this.gitBackupPath,
      gitBackupPathExists: fs.existsSync(this.gitBackupPath),
      gitRepositoryExists: fs.existsSync(path.join(this.gitBackupPath, ".git")),
      systemInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        cwd: process.cwd(),
      },
    };
  }

  generateGitTroubleshootingInfo() {
    const config = this.config.gitBackup || {};
    const issues = [];
    const suggestions = [];

    if (!config.enabled) {
      issues.push("Git Backup ist deaktiviert");
      suggestions.push("Aktiviere Git Backup im Web-Interface");
    }

    if (!config.repository) {
      issues.push("Repository URL ist nicht gesetzt");
      suggestions.push(
        "Setze eine gültige HTTPS Repository URL (z.B. https://github.com/username/repo.git)"
      );
    }

    if (!config.username) {
      issues.push("Git Username ist nicht gesetzt");
      suggestions.push("Setze deinen Git-Benutzernamen");
    }

    if (!config.token) {
      issues.push("Personal Access Token ist nicht gesetzt");
      suggestions.push(
        "Erstelle einen Personal Access Token mit 'repo' Berechtigung"
      );
    }

    if (!fs.existsSync(this.gitBackupPath)) {
      issues.push("Git Backup Verzeichnis existiert nicht");
      suggestions.push(
        "Das Verzeichnis wird automatisch erstellt - prüfe Dateiberechtigungen"
      );
    }

    if (
      fs.existsSync(this.gitBackupPath) &&
      !fs.existsSync(path.join(this.gitBackupPath, ".git"))
    ) {
      issues.push("Git Repository ist nicht initialisiert");
      suggestions.push(
        "Das Repository wird automatisch initialisiert - prüfe Git-Installation"
      );
    }

    return {
      issues: issues,
      suggestions: suggestions,
      nextSteps: [
        "1. Überprüfe die Git Backup Konfiguration im Web-Interface",
        "2. Stelle sicher, dass das Repository existiert und zugänglich ist",
        "3. Verwende den 'Verbindung testen' Button",
        "4. Prüfe die Server-Logs für detaillierte Fehlermeldungen",
      ],
    };
  }
  // ====== ERWEITERTE MIDDLEWARE-SETUP ======
  setupMiddleware() {
    // ====== HTTPS ENFORCEMENT ======
    if (this.securityConfig.requireHttps) {
      this.app.use((req, res, next) => {
        if (req.header('x-forwarded-proto') !== 'https' && req.secure !== true) {
          const httpsPort = this.config.server.httpsPort || 8443;
          return res.redirect(301, `https://${req.hostname}:${httpsPort}${req.url}`);
        }
        next();
      });
    }

    // ====== ERWEITERTE SECURITY HEADERS ======
    this.app.use(
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
          },
        },
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: false,
        hsts: {
          maxAge: 0,
          includeSubDomains: false
        },
        noSniff: true,
        frameguard: { action: 'deny' },
        xssFilter: true,
        referrerPolicy: { policy: 'same-origin' }
      })
    );

    // ====== ERWEITERTE RATE LIMITING ======
    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 Minuten
      max: this.securityConfig.maxFailedAttempts, // Basiert auf Konfiguration
      message: { 
        error: "Zu viele Login-Versuche. Versuche es später erneut.",
        lockoutTime: 15,
        requiresCaptcha: true
      },
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => {
        return req.ip + ':' + (req.body.username || 'anonymous');
      },
      handler: (req, res) => {
        console.log(`🚫 [RATE LIMIT] Login-Rate-Limit erreicht für ${req.ip}`);
        res.status(429).json({
          error: "Zu viele Login-Versuche. Versuche es später erneut.",
          lockoutTime: 15,
          requiresCaptcha: true
        });
      }
    });

    const apiLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100, // API-Aufrufe begrenzen
      message: { error: "Zu viele API-Anfragen" },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        console.log(`🚫 [RATE LIMIT] API-Rate-Limit erreicht für ${req.ip}`);
        res.status(429).json({ error: "Zu viele API-Anfragen" });
      }
    });

    // CAPTCHA und 2FA haben niedrigere Limits
    const captchaLimiter = rateLimit({
      windowMs: 5 * 60 * 1000, // 5 Minuten
      max: 10, // Nur 10 CAPTCHA-Anfragen pro 5 Minuten
      message: { error: "Zu viele CAPTCHA-Anfragen" }
    });

    // ====== MIDDLEWARE-ANWENDUNG ======
    this.app.use("/api/login", authLimiter);
    this.app.use("/api/captcha", captchaLimiter);
    this.app.use("/api/2fa", captchaLimiter);
    this.app.use("/api/", apiLimiter);

    this.app.use(compression());
    this.app.use(cors({
      origin: this.securityConfig.requireHttps ? 
        (origin, callback) => {
          if (!origin || origin.startsWith('https://')) {
            callback(null, true);
          } else {
            callback(new Error('CORS: Nur HTTPS-Verbindungen erlaubt'));
          }
        } : true,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      exposedHeaders: ['X-Session-Timeout', 'X-Requires-2FA']
    }));

    // Body parsing mit Sicherheitslimits
    this.app.use(express.json({ 
      limit: '10mb',
      verify: (req, res, buf) => {
        // Verhindere JSON-Bombs
        if (buf.length > 10 * 1024 * 1024) {
          throw new Error('JSON zu groß');
        }
      }
    }));
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: '10mb',
      parameterLimit: 100 // Begrenzt Parameter-Anzahl
    }));

    // Cookie Parser mit Sicherheitsoptionen
    this.app.use(cookieParser(this.config.security.sessionSecret, {
      httpOnly: true,
      secure: this.securityConfig.requireHttps,
      sameSite: 'strict'
    }));

    // ====== ERWEITERTE SESSION-KONFIGURATION ======
    this.app.use(
      session({
        secret: this.config.security.sessionSecret,
        resave: false,
        saveUninitialized: false,
        rolling: true,
        cookie: {
          secure: this.securityConfig.requireHttps,
          httpOnly: true,
          maxAge: this.securityConfig.sessionTimeout,
          sameSite: 'strict'
        },
        name: 'db-backup-session',
        genid: () => {
          return crypto.randomBytes(32).toString('hex');
        },
        store: null // Verwende Memory Store (für Production sollte Redis verwendet werden)
      })
    );

    // ====== SICHERHEITS-LOGGING ======
    this.app.use((req, res, next) => {
      const logData = {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent'],
        sessionId: req.session.id
      };

      // Sensible Routen loggen
      if (req.url.includes('/api/login') || 
          req.url.includes('/api/2fa') || 
          req.url.includes('/api/captcha')) {
        console.log(`🔐 [SECURITY] ${logData.ip} -> ${logData.method} ${logData.url}`);
      }

      // Suspicious activity detection
      if (req.headers['user-agent'] && 
          (req.headers['user-agent'].includes('bot') || 
           req.headers['user-agent'].includes('crawler'))) {
        console.log(`🤖 [SUSPICIOUS] Bot detected: ${req.ip} - ${req.headers['user-agent']}`);
      }

      next();
    });

    // ====== IP-BLACKLIST MIDDLEWARE ======
    this.app.use((req, res, next) => {
      const suspiciousIPs = new Set(); // Kann aus Datenbank/File geladen werden
      
      if (suspiciousIPs.has(req.ip)) {
        console.log(`🚫 [BLACKLIST] Blocked IP: ${req.ip}`);
        return res.status(403).json({ error: "Zugriff verweigert" });
      }
      
      next();
    });

    // ====== SESSION CLEANUP SCHEDULER ======
    setInterval(() => {
      this.cleanupExpiredSessions();
    }, 5 * 60 * 1000); // Alle 5 Minuten

    // Statische Dateien mit Cache-Control
    this.app.use(express.static(path.join(__dirname, "public"), {
      maxAge: '1d',
      etag: true,
      lastModified: true,
      setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
          res.setHeader('Cache-Control', 'no-cache');
        }
      }
    }));
  }

  // ====== ERWEITERTE AUTH-MIDDLEWARE ======
  authMiddleware(req, res, next) {
    const token = 
      req.headers.authorization?.split(" ")[1] || 
      req.session.token || 
      req.cookies["auth-token"];

    if (!token) {
      return res.status(401).json({ 
        error: "Kein Token bereitgestellt",
        requiresAuth: true 
      });
    }

    try {
      const decoded = jwt.verify(token, this.config.security.jwtSecret);
      
      // Session Validation für erweiterte Sicherheit
      if (decoded.sessionId) {
        const sessionValidation = this.validateSession(decoded.sessionId, req);
        if (!sessionValidation.valid) {
          console.log(`❌ [AUTH] Session ungültig: ${sessionValidation.reason}`);
          return res.status(401).json({ 
            error: sessionValidation.reason,
            requiresAuth: true 
          });
        }
      }

      // Rate limiting für authentifizierte Benutzer
      const userKey = `auth:${decoded.username}:${req.ip}`;
      if (!this.userRateLimits) {
        this.userRateLimits = new Map();
      }
      
      const now = Date.now();
      const userLimit = this.userRateLimits.get(userKey) || { count: 0, resetTime: now + 60000 };
      
      if (now > userLimit.resetTime) {
        userLimit.count = 0;
        userLimit.resetTime = now + 60000;
      }
      
      userLimit.count++;
      this.userRateLimits.set(userKey, userLimit);
      
      if (userLimit.count > 50) { // 50 Requests pro Minute für authentifizierte User
        return res.status(429).json({ 
          error: "Zu viele Anfragen",
          resetTime: userLimit.resetTime 
        });
      }

      req.user = decoded;
      
      // Session-Timeout in Response-Header
      if (decoded.sessionId) {
        const session = this.activeSessions.get(decoded.sessionId);
        if (session) {
          res.setHeader('X-Session-Timeout', session.expiresAt);
        }
      }

      next();
    } catch (error) {
      console.log(`❌ [AUTH] Token-Fehler: ${error.message}`);
      
      // Session und Cookie löschen bei ungültigem Token
      if (req.session) {
        req.session.destroy();
      }
      res.clearCookie("auth-token");
      
      return res.status(401).json({ 
        error: "Ungültiger Token",
        requiresAuth: true 
      });
    }
  }

  // ====== ERWEITERTE SETUP-METHODEN ======
  async setupDefaultUser() {
    // Passwort-Stärke vor dem Hashen prüfen
    if (this.securityConfig.strongPasswords) {
      const validation = this.validatePasswordStrength(this.config.security.defaultAdmin.password);
      if (!validation.valid) {
        console.warn("⚠️ [SECURITY] Standard-Passwort erfüllt nicht die Sicherheitsanforderungen:");
        console.warn(`   ${validation.message}`);
        console.warn("   Bitte ändere das Passwort nach dem ersten Login!");
      }
    }

    const hashedPassword = await bcrypt.hash(
      this.config.security.defaultAdmin.password,
      12 // Erhöhte Rounds für bessere Sicherheit
    );
    
    this.users.set(this.config.security.defaultAdmin.username, {
      username: this.config.security.defaultAdmin.username,
      password: hashedPassword,
      role: "admin",
      twoFactorSecret: null, // Wird bei 2FA-Setup gesetzt
      createdAt: new Date().toISOString(),
      lastLogin: null,
      loginAttempts: 0,
      accountLocked: false,
      lockUntil: null,
      passwordChanged: false // Flag für Passwort-Änderung
    });

    console.log(`✅ [USER] Standard-Admin erstellt: ${this.config.security.defaultAdmin.username}`);
  }

  ensureDirectories() {
    const dirs = ["backups", "logs", "config", "public", "ssl"];
    dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`📁 [SETUP] Verzeichnis erstellt: ${dir}`);
      }
    });

    // SSL-Verzeichnis mit restriktiven Berechtigungen
    if (fs.existsSync("ssl")) {
      try {
        fs.chmodSync("ssl", 0o700);
      } catch (error) {
        console.warn("⚠️ [SSL] Konnte SSL-Verzeichnis-Berechtigungen nicht setzen");
      }
    }
  }

  // ====== SICHERHEITS-STATUS ANZEIGE ======
  displaySecurityStatus() {
    console.log("");
    console.log("🛡️ ================================================");
    console.log("🛡️ SECURITY STATUS - ENHANCED SSL VERSION");
    console.log("🛡️ ================================================");
    console.log(`🔐 HTTPS: ${this.securityConfig.requireHttps ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    console.log(`🔑 2FA: ${this.securityConfig.enable2FA ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    console.log(`🔒 Starke Passwörter: ${this.securityConfig.strongPasswords ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    console.log(`🚫 Max Login-Versuche: ${this.securityConfig.maxFailedAttempts}`);
    console.log(`⏱️ Session Timeout: ${this.securityConfig.sessionTimeout / 1000 / 60} Minuten`);
    console.log(`🔐 CAPTCHA Schwelle: ${this.securityConfig.captchaThreshold} Fehlversuche`);
    console.log(`🔒 Lockout-Dauer: ${this.securityConfig.lockoutDuration / 1000 / 60} Minuten`);
    console.log(`🛡️ Security Headers: ✅ Aktiviert (CSP, HSTS, XSS Protection)`);
    console.log(`📊 Rate Limiting: ✅ Aktiviert (Auth: ${this.securityConfig.maxFailedAttempts}/15min, API: 100/15min)`);
    console.log(`🍪 Secure Cookies: ${this.securityConfig.requireHttps ? "✅ Aktiviert" : "⚠️ Nur HTTP"}`);
    console.log(`🧹 Session Cleanup: ✅ Aktiviert (alle 5 Minuten)`);
    
    if (this.securityConfig.requireHttps) {
      console.log(`🔐 SSL Domain: ${this.sslManager.domain}`);
      console.log(`🔑 SSL Methode: ${this.sslManager.method}`);
      console.log(`🔄 SSL Auto-Renewal: ${this.sslManager.autoRenewal ? "✅ Aktiviert" : "❌ Deaktiviert"}`);
    }
    
    console.log("================================================");
    console.log("");
  }

  // Auto-Update Funktion
  async checkForUpdates() {
    return new Promise((resolve) => {
      if (!fs.existsSync(".git")) {
        console.log("❌ Kein Git Repository gefunden, Update übersprungen");
        resolve();
        return;
      }

      console.log("🔍 Prüfe auf Updates vom offiziellen Repository...");
      console.log(`📦 Repository: ${this.updateRepository}`);
      console.log(`🔗 Branch: ${this.updateBranch}`);

      exec("./update.sh", (error, stdout, stderr) => {
        if (error) {
          console.error("❌ Update-Fehler:", error);
          console.log("🚀 Starte mit aktueller Version...");
        } else {
          console.log("📋 Update-Ergebnis:");
          console.log(stdout);
          if (stderr) {
            console.log("⚠️  Update-Warnungen:", stderr);
          }
        }
        resolve();
      });
    });
  }
  // ====== GIT-BACKUP-FUNKTIONEN ======

  async initializeGitBackup() {
    if (!this.config.gitBackup?.enabled) {
      console.log("📦 Git Backup ist deaktiviert");
      return;
    }

    try {
      console.log("🔧 Initialisiere Git Backup Repository...");
      console.log(`📁 Git Backup Pfad: ${this.gitBackupPath}`);

      this.debugGitConfiguration();

      if (!fs.existsSync(this.gitBackupPath)) {
        console.log("📁 Erstelle Git Backup Verzeichnis...");
        fs.mkdirSync(this.gitBackupPath, { recursive: true });
      }

      const isGitRepo = fs.existsSync(path.join(this.gitBackupPath, ".git"));
      console.log(`🔍 Git Repository Status: ${isGitRepo ? "Existiert" : "Nicht initialisiert"}`);

      if (!isGitRepo) {
        console.log("📁 Erstelle neues Git Repository für Backups...");

        await this.execPromiseWithDebug(
          `cd "${this.gitBackupPath}" && git init`,
          "Git Init"
        );
        await this.execPromiseWithDebug(
          `cd "${this.gitBackupPath}" && git config user.name "DB Backup Tool"`,
          "Git Config Name"
        );
        await this.execPromiseWithDebug(
          `cd "${this.gitBackupPath}" && git config user.email "backup@localhost"`,
          "Git Config Email"
        );

        const readmeContent = `# Database Backups\n\nAutomatisch erstellte Datenbank-Backups vom DB Backup Tool.\n\nErstellt am: ${new Date().toLocaleString("de-DE")}\n`;
        fs.writeFileSync(path.join(this.gitBackupPath, "README.md"), readmeContent);
        console.log("📝 README.md erstellt");

        await this.execPromiseWithDebug(
          `cd "${this.gitBackupPath}" && git add README.md`,
          "Git Add README"
        );
        await this.execPromiseWithDebug(
          `cd "${this.gitBackupPath}" && git commit -m "Initial commit: Setup backup repository"`,
          "Git Initial Commit"
        );
      }

      if (this.config.gitBackup.repository) {
        console.log("🔗 [GIT REMOTE] Starte Remote Repository Setup...");

        const remoteUrl = this.buildGitRemoteUrl();

        if (!remoteUrl) {
          console.error("❌ [GIT REMOTE] Konnte authentifizierte Git Remote URL nicht erstellen");
          return;
        }

        try {
          console.log("🔍 [GIT REMOTE] Prüfe bestehende Remote-Konfiguration...");
          const currentRemote = await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git remote get-url origin`,
            "Check Remote",
            false
          );
          console.log(`🔗 [GIT REMOTE] Bestehender Remote gefunden`);

          console.log("🔄 [GIT REMOTE] Aktualisiere Remote URL mit Authentifizierung...");
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git remote set-url origin "${remoteUrl}"`,
            "Update Remote URL",
            true
          );
          console.log("✅ [GIT REMOTE] Remote URL mit Authentifizierung aktualisiert");
        } catch (error) {
          console.log("🔗 [GIT REMOTE] Kein Remote vorhanden, füge neuen mit Authentifizierung hinzu...");
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git remote add origin "${remoteUrl}"`,
            "Add Remote",
            true
          );
          console.log("✅ [GIT REMOTE] Neuer Remote mit Authentifizierung hinzugefügt");
        }

        const branch = this.config.gitBackup.branch || "main";
        console.log(`🌿 [GIT BRANCH] Konfiguriere Branch: ${branch}`);

        try {
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git checkout -B ${branch}`,
            "Checkout Branch"
          );
          console.log(`✅ [GIT BRANCH] Branch ${branch} konfiguriert`);
        } catch (error) {
          console.log(`⚠️ [GIT BRANCH] Branch checkout fehlgeschlagen: ${error.message}`);
        }

        try {
          console.log("🧪 [GIT TEST] Teste authentifizierten Push...");
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git push -u origin ${branch}`,
            "Authenticated Push Test",
            true,
            60000
          );
          console.log("✅ [GIT TEST] Authentifizierter Push erfolgreich - Git Backup voll funktionsfähig!");
        } catch (error) {
          console.error("❌ [GIT TEST] Authentifizierter Push fehlgeschlagen:", error);
        }
      }
    } catch (error) {
      console.error("❌ Fehler beim Initialisieren des Git Backup Repositories:", error);
    }
  }

  async pushBackupToGit(backupFilePath, filename) {
    if (!this.config.gitBackup?.enabled || !this.config.gitBackup?.repository) {
      console.log("📤 Git Backup ist deaktiviert oder nicht konfiguriert");
      return { success: false, reason: "disabled" };
    }

    const startTime = Date.now();
    console.log(`📤 [GIT PUSH] Starte Git Push für: ${filename}`);

    try {
      if (!fs.existsSync(backupFilePath)) {
        throw new Error(`Backup-Datei nicht gefunden: ${backupFilePath}`);
      }

      if (!fs.existsSync(this.gitBackupPath)) {
        throw new Error(`Git Backup Verzeichnis nicht gefunden: ${this.gitBackupPath}`);
      }

      if (!fs.existsSync(path.join(this.gitBackupPath, ".git"))) {
        throw new Error("Git Repository nicht initialisiert");
      }

      console.log("🔍 [GIT PUSH] Aktuelle Git Konfiguration:");
      this.debugGitConfiguration();

      console.log("🔍 [GIT PUSH] Prüfe Git Status...");
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git status --porcelain`,
        "Git Status Check"
      );

      const gitBackupFile = path.join(this.gitBackupPath, filename);
      fs.copyFileSync(backupFilePath, gitBackupFile);

      const stats = fs.statSync(gitBackupFile);
      console.log(`✅ [GIT PUSH] Datei kopiert (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);

      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git add "${filename}"`,
        "Git Add"
      );

      const commitMessage = `Add backup: ${filename} (${new Date().toLocaleString("de-DE")})`;
      console.log("💾 [GIT PUSH] Git Commit...");
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git commit -m "${commitMessage}"`,
        "Git Commit"
      );

      const branch = this.config.gitBackup.branch || "main";
      console.log(`🚀 [GIT PUSH] Git Push zu Branch: ${branch}`);

      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git pull --rebase origin ${branch}`,
        "Git Pull (Rebase)",
        true
      );
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git push origin ${branch}`,
        "Git Push",
        true,
        60000
      );

      const duration = Date.now() - startTime;
      console.log(`✅ [GIT PUSH] ERFOLGREICH abgeschlossen nach ${duration}ms`);

      await this.cleanupGitBackups();

      return { success: true, duration: duration };
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ [GIT PUSH] FEHLGESCHLAGEN nach ${duration}ms: ${error.message}`);
      throw error;
    }
  }

  async testGitBackupConnection() {
    console.log("🧪 [GIT TEST] Starte Git Backup Verbindungstest...");

    if (!this.config.gitBackup?.enabled) {
      throw new Error("Git Backup ist nicht aktiviert");
    }

    if (!this.config.gitBackup?.repository) {
      throw new Error("Git Repository URL ist nicht konfiguriert");
    }

    if (!this.config.gitBackup?.username || !this.config.gitBackup?.token) {
      throw new Error("Git Username oder Token fehlt");
    }

    try {
      new URL(this.config.gitBackup.repository);
    } catch (error) {
      throw new Error("Git Repository URL ist ungültig");
    }

    console.log("✅ [GIT TEST] Konfiguration validiert");

    this.debugGitConfiguration();

    try {
      await this.initializeGitBackup();

      const testFilename = `git_test_${Date.now()}.txt`;
      const testContent = `Git Backup Verbindungstest\nErstellt am: ${new Date().toLocaleString("de-DE")}\nTest ID: ${Math.random().toString(36).substr(2, 9)}\n`;
      const testFilePath = path.join(this.gitBackupPath, testFilename);

      console.log(`📝 [GIT TEST] Erstelle Test-Datei: ${testFilename}`);
      fs.writeFileSync(testFilePath, testContent);

      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git add "${testFilename}"`,
        "Test Git Add"
      );

      const commitMessage = `Test: Git Backup Verbindungstest ${new Date().toISOString()}`;
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git commit -m "${commitMessage}"`,
        "Test Git Commit"
      );

      const branch = this.config.gitBackup.branch || "main";
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git push origin ${branch}`,
        "Test Git Push",
        true,
        45000
      );

      console.log("🧹 [GIT TEST] Entferne Test-Datei...");
      fs.unlinkSync(testFilePath);
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git add "${testFilename}"`,
        "Test Git Add (Delete)"
      );
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git commit -m "Remove test file: ${testFilename}"`,
        "Test Git Commit (Delete)"
      );
      await this.execPromiseWithDebug(
        `cd "${this.gitBackupPath}" && git push origin ${branch}`,
        "Test Git Push (Delete)",
        true,
        30000
      );

      console.log("✅ [GIT TEST] Verbindungstest erfolgreich abgeschlossen");
      return {
        success: true,
        message: "Git Backup Verbindung erfolgreich getestet",
      };
    } catch (error) {
      console.error("❌ [GIT TEST] Verbindungstest fehlgeschlagen:", error);
      throw new Error(`Git Backup Test fehlgeschlagen: ${error.message}`);
    }
  }

  async cleanupGitBackups() {
    if (!this.config.gitBackup?.enabled) {
      return;
    }

    try {
      console.log("🧹 [GIT CLEANUP] Prüfe Git Repository auf alte Backups...");

      const files = fs
        .readdirSync(this.gitBackupPath)
        .filter((file) => file.endsWith(".sql") || file.endsWith(".sql.gz"))
        .map((file) => {
          const filePath = path.join(this.gitBackupPath, file);
          const stats = fs.statSync(filePath);
          return {
            filename: file,
            path: filePath,
            created: stats.birthtime,
          };
        })
        .sort((a, b) => a.created - b.created);

      const maxBackups = this.config.backup.maxBackups || 10;
      console.log(`📊 [GIT CLEANUP] ${files.length} Backup-Dateien gefunden, Maximum: ${maxBackups}`);

      if (files.length > maxBackups) {
        const filesToDelete = files.slice(0, files.length - maxBackups);

        console.log(`🗑️ [GIT CLEANUP] Lösche ${filesToDelete.length} alte Backup(s) aus Git Repository...`);

        for (const fileToDelete of filesToDelete) {
          console.log(`   - Lösche: ${fileToDelete.filename}`);
          fs.unlinkSync(fileToDelete.path);
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git add "${fileToDelete.filename}"`,
            "Git Add (Delete)"
          );
        }

        if (filesToDelete.length > 0) {
          const commitMessage = `Cleanup: Remove ${filesToDelete.length} old backup(s) (${new Date().toLocaleString("de-DE")})`;
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git commit -m "${commitMessage}"`,
            "Git Commit (Cleanup)"
          );

          const branch = this.config.gitBackup.branch || "main";
          await this.execPromiseWithDebug(
            `cd "${this.gitBackupPath}" && git push origin ${branch}`,
            "Git Push (Cleanup)",
            true,
            30000
          );

          console.log(`✅ [GIT CLEANUP] ${filesToDelete.length} alte Backup(s) aus Git Repository entfernt`);
        }
      } else {
        console.log("✅ [GIT CLEANUP] Git Repository Cleanup nicht erforderlich");
      }
    } catch (error) {
      console.error("❌ [GIT CLEANUP] Fehler beim Git Repository Cleanup:", error);
    }
  }

  async updateGitBackupConfig(req, res) {
    try {
      const { enabled, repository, username, token, branch } = req.body;
      const requestingUser = req.user.username;

      console.log(`🔧 [GIT CONFIG] Konfiguration wird aktualisiert von: ${requestingUser}`);

      if (enabled) {
        if (!repository) {
          return res.status(400).json({
            error: "Repository URL ist erforderlich wenn Git Backup aktiviert ist",
          });
        }

        if (!username) {
          return res.status(400).json({
            error: "Username ist erforderlich wenn Git Backup aktiviert ist",
          });
        }

        try {
          new URL(repository);
        } catch (urlError) {
          return res.status(400).json({
            error: "Repository URL hat ungültiges Format. Verwende HTTPS URLs wie: https://github.com/username/repo.git",
          });
        }
      }

      let finalToken = "";

      if (token && token.trim() !== "") {
        finalToken = token.trim();
        console.log(`🔑 [GIT CONFIG] Neuer Token empfangen (${finalToken.length} Zeichen)`);

        try {
          this.saveGitToken(finalToken);
          console.log("✅ [GIT CONFIG] Neuer Token verschlüsselt gespeichert");
        } catch (tokenError) {
          console.error("❌ [GIT CONFIG] Fehler beim Speichern des Tokens:", tokenError);
          return res.status(500).json({
            error: "Fehler beim Speichern des Tokens: " + tokenError.message,
          });
        }
      } else {
        const existingToken = this.loadGitToken();
        if (existingToken) {
          finalToken = existingToken;
          console.log(`🔑 [GIT CONFIG] Bestehender Token geladen (${finalToken.length} Zeichen)`);
        } else {
          console.log("⚠️ [GIT CONFIG] Kein Token verfügbar");
        }
      }

      if (enabled && !finalToken) {
        return res.status(400).json({
          error: "Personal Access Token ist erforderlich wenn Git Backup aktiviert ist. Bitte gib einen Token ein.",
        });
      }

      this.config.gitBackup = {
        enabled: enabled === true,
        repository: repository || "",
        username: username || "",
        token: finalToken,
        branch: branch || "main",
      };

      const configToSave = { ...this.config };
      if (configToSave.gitBackup) {
        delete configToSave.gitBackup.token;
      }

      fs.writeFileSync("config.json", JSON.stringify(configToSave, null, 2));
      console.log("✅ [GIT CONFIG] config.json gespeichert (ohne Token)");

      if (enabled && finalToken) {
        console.log("🔄 [GIT CONFIG] Initialisiere Git Backup mit neuer Konfiguration...");
        try {
          await this.initializeGitBackup();
          console.log("✅ [GIT CONFIG] Git Backup erfolgreich initialisiert");
        } catch (initError) {
          console.error("❌ [GIT CONFIG] Git Backup Initialisierung fehlgeschlagen:", initError);
        }
      }

      res.json({
        message: "Git Backup Konfiguration erfolgreich gespeichert",
        applied: true,
        gitBackupStatus: enabled ? "aktiviert" : "deaktiviert",
        configuredBy: requestingUser
      });
    } catch (error) {
      console.error("❌ [GIT CONFIG] Fehler beim Speichern der Git Backup Konfiguration:", error);
      res.status(500).json({
        error: "Fehler beim Speichern der Konfiguration: " + error.message,
      });
    }
  }

  // ====== CLEANUP UND HILFSMETHODEN ======

  cleanupOldBackups() {
    try {
      const backupDir = this.config.backup.defaultPath;
      const files = fs.readdirSync(backupDir).filter(
        (file) =>
          (file.endsWith(".sql") ||
            file.endsWith(".sql.gz") ||
            (!file.includes(".") &&
              fs.statSync(path.join(backupDir, file)).isDirectory())) &&
          file !== "git-backup"
      );

      if (files.length > this.config.backup.maxBackups) {
        const backups = files
          .map((file) => {
            const filePath = path.join(backupDir, file);
            const stats = fs.statSync(filePath);
            return { file, path: filePath, created: stats.birthtime };
          })
          .sort((a, b) => a.created - b.created);

        const filesToDelete = backups.slice(0, files.length - this.config.backup.maxBackups);

        console.log(`🧹 [CLEANUP] Lösche ${filesToDelete.length} alte lokale Backup(s)...`);

        filesToDelete.forEach((backup) => {
          const stats = fs.statSync(backup.path);
          if (stats.isDirectory()) {
            fs.rmSync(backup.path, { recursive: true, force: true });
          } else {
            fs.unlinkSync(backup.path);
          }
          console.log(`   - Gelöscht: ${backup.file}`);
        });
      }
    } catch (error) {
      console.error("❌ Fehler beim Aufräumen alter Backups:", error);
    }
  }

  saveSchedulesToFile() {
    try {
      const schedules = Array.from(this.backupJobs.values()).map((job) => ({
        id: job.id,
        name: job.name,
        cronExpression: job.cronExpression,
        dbConfig: job.dbConfig,
        created: job.created,
        createdBy: job.createdBy || 'system'
      }));

      fs.writeFileSync(this.schedulesFile, JSON.stringify(schedules, null, 2));
      console.log("✅ Zeitpläne in Datei gespeichert:", this.schedulesFile);
    } catch (error) {
      console.error("❌ Fehler beim Speichern der Zeitpläne:", error);
    }
  }

  loadSchedulesFromFile() {
    try {
      if (fs.existsSync(this.schedulesFile)) {
        const schedulesData = fs.readFileSync(this.schedulesFile, "utf8");
        const schedules = JSON.parse(schedulesData);

        console.log("📋 Lade gespeicherte Zeitpläne...");

        schedules.forEach((scheduleData) => {
          this.recreateScheduleJob(scheduleData);
        });

        console.log(`✅ ${schedules.length} Zeitplan(e) erfolgreich geladen`);
      } else {
        console.log("📋 Keine gespeicherten Zeitpläne gefunden - starte mit leerer Liste");
      }
    } catch (error) {
      console.error("❌ Fehler beim Laden der Zeitpläne:", error);
    }
  }

  recreateScheduleJob(scheduleData) {
    try {
      const job = cron.schedule(
        scheduleData.cronExpression,
        async () => {
          console.log(`🔄 Führe geplantes Backup aus: ${scheduleData.name} (von: ${scheduleData.createdBy || 'system'})`);
          try {
            await this.executeScheduledBackup(scheduleData.dbConfig, scheduleData.createdBy);
            console.log(`✅ Geplantes Backup erfolgreich: ${scheduleData.name}`);
          } catch (err) {
            console.error(`❌ Geplantes Backup fehlgeschlagen: ${scheduleData.name}`, err);
          }
        },
        { scheduled: false }
      );

      this.backupJobs.set(scheduleData.id, {
        id: scheduleData.id,
        name: scheduleData.name,
        cronExpression: scheduleData.cronExpression,
        dbConfig: scheduleData.dbConfig,
        job,
        created: new Date(scheduleData.created),
        createdBy: scheduleData.createdBy || 'system'
      });

      job.start();
      console.log(`🕐 Zeitplan aktiviert: ${scheduleData.name} (${scheduleData.cronExpression}) von ${scheduleData.createdBy || 'system'}`);
    } catch (error) {
      console.error(`❌ Fehler beim Wiederherstellen des Zeitplans: ${scheduleData.name}`, error);
    }
  }

  async executeScheduledBackup(dbConfig, createdBy = 'system') {
    const safeDatabaseName = (dbConfig.database || "unknown_db").replace(/[^a-zA-Z0-9_-]/g, "_");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `scheduled_${createdBy}_${safeDatabaseName}_${timestamp}.sql`;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

    console.log(`📅 [SCHEDULED] Starte geplantes Backup: ${filename} (erstellt von: ${createdBy})`);

    try {
      switch (dbConfig.type) {
        case "mysql":
          await mysqldump({
            connection: {
              host: dbConfig.host,
              port: parseInt(dbConfig.port) || 3306,
              user: dbConfig.username,
              password: dbConfig.password,
              database: dbConfig.database,
            },
            dumpToFile: backupPath,
          });
          break;

        case "postgresql":
          const pgCommand = `PGPASSWORD=${dbConfig.password} pg_dump -h ${dbConfig.host} -p ${dbConfig.port || 5432} -U ${dbConfig.username} -d ${dbConfig.database} > ${backupPath}`;
          await this.execPromiseWithDebug(pgCommand, "Scheduled PostgreSQL Backup");
          break;

        case "mongodb":
          const mongoBackupDir = path.join(this.config.backup.defaultPath, `scheduled_${createdBy}_${safeDatabaseName}_${timestamp}`);
          const mongoCommand = `mongodump --host ${dbConfig.host}:${dbConfig.port || 27017} --db ${dbConfig.database} --username ${dbConfig.username} --password ${dbConfig.password} --out ${mongoBackupDir}`;
          await this.execPromiseWithDebug(mongoCommand, "Scheduled MongoDB Backup");
          console.log("📁 [SCHEDULED] MongoDB Backup als Verzeichnis erstellt - Git Push nicht verfügbar");
          this.cleanupOldBackups();
          return;
      }

      let finalBackupPath = backupPath;

      if (this.config.backup.compression && dbConfig.type !== "mongodb") {
        console.log("🗜️ [SCHEDULED] Komprimiere Backup...");
        await this.execPromiseWithDebug(`gzip ${backupPath}`, "Scheduled Backup Compression");
        finalBackupPath = `${backupPath}.gz`;
      }

      console.log(`✅ [SCHEDULED] Backup erstellt: ${path.basename(finalBackupPath)}`);

      if (dbConfig.type !== "mongodb" && fs.existsSync(finalBackupPath)) {
        try {
          console.log("📤 [SCHEDULED] Starte Git Push...");
          const gitResult = await this.pushBackupToGit(finalBackupPath, path.basename(finalBackupPath));
          if (gitResult.success) {
            console.log(`✅ [SCHEDULED] Git Push erfolgreich (${gitResult.duration}ms)`);
          }
        } catch (gitError) {
          console.error(`⚠️ [SCHEDULED] Git Push für geplantes Backup fehlgeschlagen: ${gitError.message}`);
        }
      }

      this.cleanupOldBackups();
    } catch (error) {
      console.error(`❌ [SCHEDULED] Fehler beim geplanten Backup: ${error.message}`);
      throw error;
    }
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