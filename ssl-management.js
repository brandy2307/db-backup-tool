/**
 * SSL-Management Modul für Database Backup Tool
 * Datei: ssl-management.js
 * Platzierung: /home/container/db-backup-tool/ssl-management.js
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');

class SSLCertificateManager {
  constructor(config) {
    this.config = config;
    this.appDir = process.cwd();
    this.sslPath = path.join(this.appDir, "ssl");
    this.certPath = path.join(this.sslPath, "fullchain.pem");
    this.keyPath = path.join(this.sslPath, "privkey.pem");
    this.setupScriptPath = path.join(this.appDir, "ssl-setup.sh");
    
    // Konfiguration aus Umgebungsvariablen und Config
    this.domain = process.env.SSL_DOMAIN || config.ssl?.domain || "localhost";
    this.email = process.env.SSL_EMAIL || config.ssl?.email || "admin@localhost";
    this.method = process.env.SSL_METHOD || config.ssl?.method || "selfsigned";
    this.autoRenewal = (process.env.SSL_AUTO_RENEWAL || config.ssl?.autoRenewal || "true") === "true";
    
    console.log(`🔐 [SSL] SSL-Manager initialisiert:`);
    console.log(`   App-Verzeichnis: ${this.appDir}`);
    console.log(`   SSL-Verzeichnis: ${this.sslPath}`);
    console.log(`   Domain: ${this.domain}`);
    console.log(`   Methode: ${this.method}`);
    console.log(`   Auto-Renewal: ${this.autoRenewal}`);
    
    this.ensureSSLDirectory();
  }

  /**
   * Ensure SSL directory exists
   */
  ensureSSLDirectory() {
    if (!fs.existsSync(this.sslPath)) {
      fs.mkdirSync(this.sslPath, { recursive: true, mode: 0o700 });
      console.log(`📁 [SSL] SSL-Verzeichnis erstellt: ${this.sslPath}`);
    }
  }

  /**
   * Check if SSL setup script exists
   */
  checkSetupScript() {
    if (!fs.existsSync(this.setupScriptPath)) {
      console.error(`❌ [SSL] SSL-Setup Script nicht gefunden: ${this.setupScriptPath}`);
      return false;
    }
    
    // Prüfe Ausführbarkeit
    try {
      fs.accessSync(this.setupScriptPath, fs.constants.X_OK);
      return true;
    } catch (error) {
      console.log(`🔧 [SSL] Setze Ausführungsrechte für SSL-Setup Script`);
      fs.chmodSync(this.setupScriptPath, 0o755);
      return true;
    }
  }

  /**
   * Run SSL setup script
   */
  async runSetupScript() {
    if (!this.checkSetupScript()) {
      throw new Error("SSL-Setup Script nicht verfügbar");
    }

    console.log(`🔄 [SSL] Führe SSL-Setup Script aus...`);
    
    return new Promise((resolve, reject) => {
      const env = {
        ...process.env,
        SSL_DOMAIN: this.domain,
        SSL_EMAIL: this.email,
        SSL_METHOD: this.method,
        SSL_AUTO_RENEWAL: this.autoRenewal.toString()
      };

      exec(`cd "${this.appDir}" && ./ssl-setup.sh`, { 
        env: env,
        cwd: this.appDir,
        timeout: 300000 // 5 Minuten Timeout
      }, (error, stdout, stderr) => {
        if (error) {
          console.error(`❌ [SSL] SSL-Setup fehlgeschlagen:`, error);
          console.error(`❌ [SSL] Stderr:`, stderr);
          reject(new Error(`SSL-Setup fehlgeschlagen: ${error.message}`));
          return;
        }

        console.log(`✅ [SSL] SSL-Setup erfolgreich:`);
        console.log(stdout);
        
        if (stderr) {
          console.log(`⚠️ [SSL] Warnungen:`, stderr);
        }
        
        resolve({
          success: true,
          output: stdout,
          warnings: stderr || null
        });
      });
    });
  }

  /**
   * Check if certificates exist and are valid
   */
  async checkCertificates() {
    try {
      if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
        console.log("🔍 [SSL] Zertifikate nicht gefunden");
        return { 
          valid: false, 
          reason: "certificates_not_found",
          certPath: this.certPath,
          keyPath: this.keyPath
        };
      }

      // Prüfe Dateiberechtigungen
      const certStats = fs.statSync(this.certPath);
      const keyStats = fs.statSync(this.keyPath);
      
      if ((keyStats.mode & 0o077) !== 0) {
        console.log("🔧 [SSL] Repariere Private Key Berechtigungen");
        fs.chmodSync(this.keyPath, 0o600);
      }

      // Prüfe Zertifikat-Gültigkeit
      const certInfo = await this.getCertificateInfo();
      
      if (certInfo.expiresIn < 1) {
        console.log(`❌ [SSL] Zertifikat ist abgelaufen`);
        return { 
          valid: false, 
          reason: "certificate_expired",
          expiresIn: certInfo.expiresIn
        };
      }

      if (certInfo.expiresIn <= 30) {
        console.log(`⚠️ [SSL] Zertifikat läuft in ${certInfo.expiresIn} Tagen ab`);
        return { 
          valid: true, 
          needsRenewal: true, 
          expiresIn: certInfo.expiresIn,
          certInfo: certInfo
        };
      }

      console.log(`✅ [SSL] Zertifikat ist gültig (läuft ab in ${certInfo.expiresIn} Tagen)`);
      return { 
        valid: true, 
        needsRenewal: false, 
        expiresIn: certInfo.expiresIn,
        certInfo: certInfo
      };
    } catch (error) {
      console.error("❌ [SSL] Fehler beim Überprüfen der Zertifikate:", error);
      return { 
        valid: false, 
        reason: "certificate_check_failed", 
        error: error.message 
      };
    }
  }

  /**
   * Get certificate information using OpenSSL
   */
  async getCertificateInfo() {
    return new Promise((resolve, reject) => {
      exec(`openssl x509 -in "${this.certPath}" -text -noout`, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`OpenSSL Fehler: ${error.message}`));
          return;
        }

        try {
          // Parse Certificate Information
          const subjectMatch = stdout.match(/Subject: (.+)/);
          const issuerMatch = stdout.match(/Issuer: (.+)/);
          const notBeforeMatch = stdout.match(/Not Before: (.+)/);
          const notAfterMatch = stdout.match(/Not After : (.+)/);
          
          if (!notAfterMatch) {
            reject(new Error('Zertifikat-Ablaufdatum nicht gefunden'));
            return;
          }

          const expiryDate = new Date(notAfterMatch[1]);
          const now = new Date();
          const expiresIn = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
          
          // Parse Subject Alternative Names
          const sanMatch = stdout.match(/X509v3 Subject Alternative Name:\s*\n\s*(.+)/);
          const alternativeNames = sanMatch ? sanMatch[1].split(', ').map(name => name.replace('DNS:', '')) : [];

          resolve({
            expiresIn: expiresIn,
            expiryDate: expiryDate,
            issueDate: notBeforeMatch ? new Date(notBeforeMatch[1]) : null,
            subject: subjectMatch ? subjectMatch[1] : 'Unknown',
            issuer: issuerMatch ? issuerMatch[1] : 'Unknown',
            alternativeNames: alternativeNames,
            domain: this.domain
          });
        } catch (parseError) {
          reject(new Error(`Zertifikat-Parsing Fehler: ${parseError.message}`));
        }
      });
    });
  }

  /**
   * Obtain or renew SSL certificate
   */
  async obtainCertificate() {
    console.log(`🔄 [SSL] Hole SSL-Zertifikat mit Methode: ${this.method}`);
    
    try {
      const result = await this.runSetupScript();
      
      // Verify certificates were created
      const certCheck = await this.checkCertificates();
      
      if (!certCheck.valid) {
        throw new Error(`Zertifikat-Erstellung fehlgeschlagen: ${certCheck.reason}`);
      }

      return {
        success: true,
        method: this.method,
        domain: this.domain,
        expiresIn: certCheck.expiresIn,
        output: result.output,
        warnings: result.warnings
      };
    } catch (error) {
      console.error(`❌ [SSL] Zertifikat-Erstellung fehlgeschlagen: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get comprehensive SSL status
   */
  async getStatus() {
    try {
      const certCheck = await this.checkCertificates();
      
      if (!certCheck.valid) {
        return {
          enabled: false,
          reason: certCheck.reason,
          error: certCheck.error,
          domain: this.domain,
          method: this.method,
          autoRenewal: this.autoRenewal,
          setupScriptExists: this.checkSetupScript(),
          sslDirectory: this.sslPath,
          certPath: this.certPath,
          keyPath: this.keyPath
        };
      }

      return {
        enabled: true,
        domain: this.domain,
        method: this.method,
        expiresIn: certCheck.expiresIn,
        expiryDate: certCheck.certInfo.expiryDate,
        issueDate: certCheck.certInfo.issueDate,
        subject: certCheck.certInfo.subject,
        issuer: certCheck.certInfo.issuer,
        alternativeNames: certCheck.certInfo.alternativeNames,
        needsRenewal: certCheck.needsRenewal,
        autoRenewal: this.autoRenewal,
        setupScriptExists: this.checkSetupScript(),
        sslDirectory: this.sslPath,
        certPath: this.certPath,
        keyPath: this.keyPath,
        lastChecked: new Date().toISOString()
      };
    } catch (error) {
      return {
        enabled: false,
        error: error.message,
        domain: this.domain,
        method: this.method,
        setupScriptExists: this.checkSetupScript()
      };
    }
  }

  /**
   * Monitor certificates and auto-renew if needed
   */
  async monitorCertificates() {
    console.log("🔍 [SSL] Starte Zertifikat-Überwachung...");
    
    const checkInterval = 6 * 60 * 60 * 1000; // 6 Stunden
    
    const monitor = async () => {
      try {
        const certCheck = await this.checkCertificates();
        
        if (!certCheck.valid) {
          console.log(`⚠️ [SSL] Zertifikat ist ungültig: ${certCheck.reason}`);
          return;
        }
        
        // Warnung bei ablaufenden Zertifikaten
        if (certCheck.expiresIn <= 7) {
          console.warn(`⚠️ [SSL] Zertifikat läuft in ${certCheck.expiresIn} Tagen ab!`);
        }
        
        // Auto-Renewal
        if (certCheck.needsRenewal && this.autoRenewal) {
          console.log("🔄 [SSL] Auto-Renewal wird ausgeführt...");
          try {
            await this.obtainCertificate();
            console.log("✅ [SSL] Auto-Renewal erfolgreich");
          } catch (error) {
            console.error("❌ [SSL] Auto-Renewal fehlgeschlagen:", error.message);
          }
        }
      } catch (error) {
        console.error("❌ [SSL] Fehler bei der Zertifikat-Überwachung:", error.message);
      }
    };

    // Sofortige Überprüfung
    await monitor();
    
    // Periodische Überprüfung
    setInterval(monitor, checkInterval);
  }

  /**
   * Validate SSL configuration
   */
  validateConfiguration() {
    const issues = [];

    // Domain validation
    if (!this.domain || this.domain === 'localhost') {
      if (this.method === 'letsencrypt') {
        issues.push("Let's Encrypt funktioniert nicht mit localhost");
      }
    }

    // Email validation
    if (!this.email || !this.email.includes('@')) {
      issues.push("Ungültige Email-Adresse");
    }

    // Method validation
    const validMethods = ['letsencrypt', 'cloudflare', 'selfsigned', 'manual'];
    if (!validMethods.includes(this.method)) {
      issues.push(`Ungültige SSL-Methode: ${this.method}`);
    }

    // Cloudflare specific validation
    if (this.method === 'cloudflare') {
      if (!process.env.CLOUDFLARE_API_TOKEN) {
        issues.push("CLOUDFLARE_API_TOKEN ist erforderlich für Cloudflare-Methode");
      }
    }

    // Setup script validation
    if (!this.checkSetupScript()) {
      issues.push("SSL-Setup Script nicht verfügbar");
    }

    return {
      valid: issues.length === 0,
      issues: issues
    };
  }

  /**
   * Create SSL configuration summary
   */
  getConfigurationSummary() {
    return {
      domain: this.domain,
      email: this.email,
      method: this.method,
      autoRenewal: this.autoRenewal,
      sslPath: this.sslPath,
      certPath: this.certPath,
      keyPath: this.keyPath,
      setupScriptPath: this.setupScriptPath,
      hasSetupScript: this.checkSetupScript(),
      validation: this.validateConfiguration()
    };
  }

  /**
   * Test SSL certificate with actual HTTPS connection
   */
  async testCertificate(port = 8443) {
    return new Promise((resolve) => {
      const https = require('https');
      
      const options = {
        hostname: this.domain === 'localhost' ? 'localhost' : this.domain,
        port: port,
        path: '/',
        method: 'GET',
        rejectUnauthorized: false, // Für Self-Signed Zertifikate
        timeout: 5000
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        resolve({
          success: true,
          statusCode: res.statusCode,
          certificate: {
            subject: cert.subject,
            issuer: cert.issuer,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            fingerprint: cert.fingerprint,
            serialNumber: cert.serialNumber
          }
        });
      });

      req.on('error', (error) => {
        resolve({
          success: false,
          error: error.message
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          success: false,
          error: 'Connection timeout'
        });
      });

      req.end();
    });
  }

  /**
   * Generate SSL setup instructions
   */
  generateSetupInstructions() {
    const instructions = {
      letsencrypt: {
        title: "Let's Encrypt Setup",
        requirements: [
          "Öffentlich erreichbare Domain (nicht localhost)",
          "Port 80 muss verfügbar sein",
          "Gültige Email-Adresse"
        ],
        steps: [
          "Setze SSL_DOMAIN auf deine Domain",
          "Setze SSL_EMAIL auf deine Email",
          "Setze SSL_METHOD=letsencrypt",
          "Stelle sicher, dass Port 80 nicht blockiert ist",
          "Führe SSL-Setup aus"
        ]
      },
      cloudflare: {
        title: "Cloudflare Origin Certificate Setup",
        requirements: [
          "Cloudflare Account",
          "Domain muss über Cloudflare laufen",
          "API Token mit Zone:Read und Zone:DNS:Edit Berechtigung"
        ],
        steps: [
          "Erstelle API Token unter https://dash.cloudflare.com/profile/api-tokens",
          "Setze CLOUDFLARE_API_TOKEN",
          "Setze SSL_DOMAIN auf deine Domain",
          "Setze SSL_METHOD=cloudflare",
          "Führe SSL-Setup aus"
        ]
      },
      selfsigned: {
        title: "Self-Signed Certificate Setup",
        requirements: [
          "OpenSSL installiert",
          "Nur für Test-Umgebungen geeignet"
        ],
        steps: [
          "Setze SSL_DOMAIN (kann auch localhost sein)",
          "Setze SSL_METHOD=selfsigned",
          "Führe SSL-Setup aus",
          "Akzeptiere Browser-Sicherheitswarnungen"
        ]
      },
      manual: {
        title: "Manual Certificate Installation",
        requirements: [
          "Vorhandene SSL-Zertifikate",
          "Zugriff auf Private Key"
        ],
        steps: [
          "Platziere fullchain.pem im ssl/ Ordner",
          "Platziere privkey.pem im ssl/ Ordner",
          "Setze SSL_METHOD=manual",
          "Führe SSL-Setup aus"
        ]
      }
    };

    return instructions[this.method] || instructions.selfsigned;
  }

  /**
   * Force certificate renewal
   */
  async forceCertificateRenewal() {
    console.log("🔄 [SSL] Forciere Zertifikat-Erneuerung...");
    
    try {
      const result = await this.obtainCertificate();
      console.log("✅ [SSL] Forcierte Erneuerung erfolgreich");
      return result;
    } catch (error) {
      console.error("❌ [SSL] Forcierte Erneuerung fehlgeschlagen:", error.message);
      throw error;
    }
  }

  /**
   * Backup existing certificates
   */
  backupCertificates() {
    if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
      console.log("📋 [SSL] Keine Zertifikate zum Backup vorhanden");
      return false;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(this.sslPath, `backup-${timestamp}`);
    
    try {
      fs.mkdirSync(backupDir, { recursive: true });
      fs.copyFileSync(this.certPath, path.join(backupDir, 'fullchain.pem'));
      fs.copyFileSync(this.keyPath, path.join(backupDir, 'privkey.pem'));
      
      console.log(`📋 [SSL] Zertifikate gesichert in: ${backupDir}`);
      return backupDir;
    } catch (error) {
      console.error("❌ [SSL] Backup fehlgeschlagen:", error.message);
      return false;
    }
  }

  /**
   * Clean up old certificate backups
   */
  cleanupOldBackups(maxBackups = 5) {
    const backupPattern = /^backup-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/;
    
    try {
      const entries = fs.readdirSync(this.sslPath, { withFileTypes: true });
      const backupDirs = entries
        .filter(entry => entry.isDirectory() && backupPattern.test(entry.name))
        .map(entry => ({
          name: entry.name,
          path: path.join(this.sslPath, entry.name),
          created: fs.statSync(path.join(this.sslPath, entry.name)).birthtime
        }))
        .sort((a, b) => b.created - a.created);

      if (backupDirs.length > maxBackups) {
        const toDelete = backupDirs.slice(maxBackups);
        toDelete.forEach(backup => {
          fs.rmSync(backup.path, { recursive: true, force: true });
          console.log(`🗑️ [SSL] Altes Backup gelöscht: ${backup.name}`);
        });
      }
    } catch (error) {
      console.error("❌ [SSL] Backup-Cleanup fehlgeschlagen:", error.message);
    }
  }

  /**
   * Get certificate fingerprint
   */
  async getCertificateFingerprint() {
    if (!fs.existsSync(this.certPath)) {
      return null;
    }

    return new Promise((resolve, reject) => {
      exec(`openssl x509 -in "${this.certPath}" -fingerprint -sha256 -noout`, (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        
        const match = stdout.match(/SHA256 Fingerprint=(.+)/);
        resolve(match ? match[1] : null);
      });
    });
  }

  /**
   * Verify certificate chain
   */
  async verifyCertificateChain() {
    if (!fs.existsSync(this.certPath)) {
      return { valid: false, reason: 'Certificate file not found' };
    }

    return new Promise((resolve) => {
      exec(`openssl verify -CAfile "${this.certPath}" "${this.certPath}"`, (error, stdout, stderr) => {
        if (error) {
          resolve({
            valid: false,
            reason: error.message,
            output: stderr
          });
          return;
        }

        const isValid = stdout.includes('OK');
        resolve({
          valid: isValid,
          output: stdout,
          reason: isValid ? 'Certificate chain is valid' : 'Certificate chain validation failed'
        });
      });
    });
  }

  /**
   * Get certificate security level
   */
  async getCertificateSecurityLevel() {
    try {
      const certInfo = await this.getCertificateInfo();
      let score = 0;
      let issues = [];

      // Check expiry
      if (certInfo.expiresIn > 30) score += 25;
      else if (certInfo.expiresIn > 7) score += 15;
      else issues.push('Certificate expires soon');

      // Check issuer
      if (certInfo.issuer.includes("Let's Encrypt")) score += 25;
      else if (certInfo.issuer.includes("Cloudflare")) score += 25;
      else if (certInfo.issuer.includes(certInfo.subject)) {
        score += 5; // Self-signed
        issues.push('Self-signed certificate');
      } else score += 20;

      // Check key size (estimate from certificate)
      const keySize = await this.getKeySize();
      if (keySize >= 4096) score += 25;
      else if (keySize >= 2048) score += 20;
      else {
        score += 10;
        issues.push('Key size below 2048 bits');
      }

      // Check domain validation
      if (certInfo.alternativeNames.length > 0) score += 25;
      else score += 15;

      let level = 'LOW';
      if (score >= 90) level = 'HIGH';
      else if (score >= 70) level = 'MEDIUM';
      else if (score >= 50) level = 'BASIC';

      return {
        score: score,
        level: level,
        issues: issues,
        details: {
          expiresIn: certInfo.expiresIn,
          issuer: certInfo.issuer,
          keySize: keySize,
          alternativeNames: certInfo.alternativeNames
        }
      };
    } catch (error) {
      return {
        score: 0,
        level: 'UNKNOWN',
        issues: ['Cannot analyze certificate'],
        error: error.message
      };
    }
  }

  /**
   * Get private key size
   */
  async getKeySize() {
    if (!fs.existsSync(this.keyPath)) {
      return 0;
    }

    return new Promise((resolve) => {
      exec(`openssl rsa -in "${this.keyPath}" -text -noout | grep "Private-Key"`, (error, stdout) => {
        if (error) {
          resolve(0);
          return;
        }
        
        const match = stdout.match(/Private-Key: \((\d+) bit/);
        resolve(match ? parseInt(match[1]) : 0);
      });
    });
  }

  /**
   * Health check for SSL setup
   */
  async performHealthCheck() {
    const health = {
      timestamp: new Date().toISOString(),
      overall: 'HEALTHY',
      checks: [],
      score: 0,
      maxScore: 100
    };

    // Check 1: SSL directory exists
    const sslDirCheck = {
      name: 'SSL Directory',
      status: fs.existsSync(this.sslPath) ? 'PASS' : 'FAIL',
      weight: 10
    };
    health.checks.push(sslDirCheck);
    if (sslDirCheck.status === 'PASS') health.score += sslDirCheck.weight;

    // Check 2: Setup script exists
    const setupScriptCheck = {
      name: 'Setup Script',
      status: this.checkSetupScript() ? 'PASS' : 'FAIL',
      weight: 15
    };
    health.checks.push(setupScriptCheck);
    if (setupScriptCheck.status === 'PASS') health.score += setupScriptCheck.weight;

    // Check 3: Configuration validation
    const configValidation = this.validateConfiguration();
    const configCheck = {
      name: 'Configuration',
      status: configValidation.valid ? 'PASS' : 'FAIL',
      issues: configValidation.issues,
      weight: 20
    };
    health.checks.push(configCheck);
    if (configCheck.status === 'PASS') health.score += configCheck.weight;

    // Check 4: Certificate exists and is valid
    const certCheck = await this.checkCertificates();
    const certValidCheck = {
      name: 'Certificate Validity',
      status: certCheck.valid ? 'PASS' : 'FAIL',
      details: certCheck,
      weight: 25
    };
    health.checks.push(certValidCheck);
    if (certValidCheck.status === 'PASS') health.score += certValidCheck.weight;

    // Check 5: Certificate security level
    try {
      const securityLevel = await this.getCertificateSecurityLevel();
      const securityCheck = {
        name: 'Security Level',
        status: securityLevel.score >= 70 ? 'PASS' : securityLevel.score >= 50 ? 'WARN' : 'FAIL',
        details: securityLevel,
        weight: 30
      };
      health.checks.push(securityCheck);
      if (securityCheck.status === 'PASS') health.score += securityCheck.weight;
      else if (securityCheck.status === 'WARN') health.score += securityCheck.weight / 2;
    } catch (error) {
      health.checks.push({
        name: 'Security Level',
        status: 'ERROR',
        error: error.message,
        weight: 30
      });
    }

    // Overall health determination
    const percentage = (health.score / health.maxScore) * 100;
    if (percentage >= 90) health.overall = 'EXCELLENT';
    else if (percentage >= 75) health.overall = 'GOOD';
    else if (percentage >= 50) health.overall = 'FAIR';
    else if (percentage >= 25) health.overall = 'POOR';
    else health.overall = 'CRITICAL';

    return health;
  }

  /**
   * Export SSL configuration for troubleshooting
   */
  async exportConfiguration() {
    const config = this.getConfigurationSummary();
    const status = await this.getStatus();
    const health = await this.performHealthCheck();

    return {
      timestamp: new Date().toISOString(),
      version: '1.0',
      configuration: config,
      status: status,
      health: health,
      environment: {
        SSL_DOMAIN: process.env.SSL_DOMAIN,
        SSL_EMAIL: process.env.SSL_EMAIL,
        SSL_METHOD: process.env.SSL_METHOD,
        SSL_AUTO_RENEWAL: process.env.SSL_AUTO_RENEWAL,
        CLOUDFLARE_API_TOKEN: process.env.CLOUDFLARE_API_TOKEN ? '[SET]' : '[NOT SET]',
        REQUIRE_HTTPS: process.env.REQUIRE_HTTPS
      },
      system: {
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version,
        cwd: process.cwd()
      }
    };
  }

  /**
   * Get SSL troubleshooting guide
   */
  getTroubleshootingGuide() {
    return {
      commonIssues: [
        {
          issue: "Zertifikat nicht gefunden",
          solutions: [
            "Führe SSL-Setup aus: ./ssl-setup.sh",
            "Prüfe SSL-Verzeichnis: ls -la ssl/",
            "Setze korrekte Umgebungsvariablen (SSL_DOMAIN, SSL_EMAIL, SSL_METHOD)",
            "Prüfe Dateiberechtigungen: chmod 600 ssl/privkey.pem"
          ]
        },
        {
          issue: "Let's Encrypt Fehler",
          solutions: [
            "Prüfe ob Domain öffentlich erreichbar ist",
            "Stelle sicher, dass Port 80 nicht blockiert ist",
            "Verwende gültige Email-Adresse",
            "Prüfe DNS-Einstellungen der Domain"
          ]
        },
        {
          issue: "Cloudflare Fehler",
          solutions: [
            "Prüfe CLOUDFLARE_API_TOKEN",
            "Stelle sicher, dass Domain über Cloudflare läuft",
            "Prüfe API-Token Berechtigungen (Zone:Read, Zone:DNS:Edit)",
            "Verwende korrekte Zone-ID"
          ]
        },
        {
          issue: "Self-Signed Zertifikat wird nicht akzeptiert",
          solutions: [
            "Browser-Sicherheitswarnung akzeptieren",
            "Zertifikat manuell zum Browser hinzufügen",
            "Für Produktion: Wechsel zu Let's Encrypt oder Cloudflare"
          ]
        },
        {
          issue: "Zertifikat abgelaufen",
          solutions: [
            "Aktiviere Auto-Renewal: SSL_AUTO_RENEWAL=true",
            "Manuell erneuern: ./ssl-setup.sh",
            "Prüfe Cron-Jobs für automatische Erneuerung"
          ]
        }
      ],
      diagnosticCommands: [
        {
          command: "openssl x509 -in ssl/fullchain.pem -text -noout",
          description: "Zertifikat-Details anzeigen"
        },
        {
          command: "openssl x509 -in ssl/fullchain.pem -enddate -noout",
          description: "Ablaufdatum prüfen"
        },
        {
          command: "openssl rsa -in ssl/privkey.pem -check",
          description: "Private Key validieren"
        },
        {
          command: "openssl s_client -connect localhost:8443 -servername localhost",
          description: "SSL-Verbindung testen"
        }
      ],
      environmentVariables: {
        SSL_DOMAIN: "Domain für SSL-Zertifikat (z.B. example.com)",
        SSL_EMAIL: "Email für Let's Encrypt Registrierung",
        SSL_METHOD: "SSL-Methode: letsencrypt, cloudflare, selfsigned, manual",
        SSL_AUTO_RENEWAL: "Automatische Erneuerung aktivieren (true/false)",
        CLOUDFLARE_API_TOKEN: "API Token für Cloudflare (nur bei method=cloudflare)",
        REQUIRE_HTTPS: "HTTPS erzwingen (true/false)"
      }
    };
  }

  /**
   * Generate SSL setup script if missing
   */
  async generateSetupScript() {
    const scriptContent = `#!/bin/bash
# SSL-Setup Script für Database Backup Tool
# Automatisch generiert durch SSL Certificate Manager

set -e

# Konfiguration aus Umgebungsvariablen
SSL_DOMAIN="\${SSL_DOMAIN:-localhost}"
SSL_EMAIL="\${SSL_EMAIL:-admin@localhost}"
SSL_METHOD="\${SSL_METHOD:-selfsigned}"
SSL_AUTO_RENEWAL="\${SSL_AUTO_RENEWAL:-true}"

# Verzeichnisse
SSL_DIR="./ssl"
CERT_FILE="\${SSL_DIR}/fullchain.pem"
KEY_FILE="\${SSL_DIR}/privkey.pem"

echo "🔐 SSL-Setup wird gestartet..."
echo "Domain: \${SSL_DOMAIN}"
echo "Email: \${SSL_EMAIL}"
echo "Methode: \${SSL_METHOD}"
echo "Auto-Renewal: \${SSL_AUTO_RENEWAL}"

# SSL-Verzeichnis erstellen
mkdir -p "\${SSL_DIR}"
chmod 700 "\${SSL_DIR}"

case "\${SSL_METHOD}" in
    "letsencrypt")
        echo "🔄 Let's Encrypt Zertifikat wird geholt..."
        
        # Prüfe ob certbot verfügbar ist
        if ! command -v certbot &> /dev/null; then
            echo "📦 Installiere certbot..."
            apt-get update
            apt-get install -y certbot
        fi
        
        # Hole Zertifikat
        certbot certonly --standalone \\
            --non-interactive \\
            --agree-tos \\
            --email "\${SSL_EMAIL}" \\
            --domains "\${SSL_DOMAIN}" \\
            --cert-path "\${CERT_FILE}" \\
            --key-path "\${KEY_FILE}"
        
        echo "✅ Let's Encrypt Zertifikat erfolgreich geholt"
        ;;
    
    "cloudflare")
        echo "🔄 Cloudflare Origin Zertifikat wird erstellt..."
        
        if [ -z "\${CLOUDFLARE_API_TOKEN}" ]; then
            echo "❌ CLOUDFLARE_API_TOKEN ist erforderlich"
            exit 1
        fi
        
        # Cloudflare Origin Certificate erstellen
        # (Vereinfachte Version - in der Praxis würde hier die Cloudflare API verwendet)
        echo "⚠️ Cloudflare Origin Certificate Setup noch nicht implementiert"
        echo "Verwende vorerst Self-Signed Zertifikat als Fallback"
        SSL_METHOD="selfsigned"
        ;&
    
    "selfsigned")
        echo "🔄 Self-Signed Zertifikat wird erstellt..."
        
        # Erstelle Self-Signed Zertifikat
        openssl req -x509 -newkey rsa:4096 \\
            -keyout "\${KEY_FILE}" \\
            -out "\${CERT_FILE}" \\
            -days 365 \\
            -nodes \\
            -subj "/C=DE/ST=NRW/L=Sprockhovel/O=DB Backup Tool/CN=\${SSL_DOMAIN}"
        
        echo "✅ Self-Signed Zertifikat erfolgreich erstellt"
        ;;
    
    "manual")
        echo "🔄 Manuelle Zertifikat-Installation..."
        
        if [ ! -f "\${CERT_FILE}" ] || [ ! -f "\${KEY_FILE}" ]; then
            echo "❌ Zertifikat-Dateien nicht gefunden:"
            echo "   Benötigt: \${CERT_FILE}"
            echo "   Benötigt: \${KEY_FILE}"
            exit 1
        fi
        
        echo "✅ Manuelle Zertifikate gefunden und validiert"
        ;;
    
    *)
        echo "❌ Unbekannte SSL-Methode: \${SSL_METHOD}"
        exit 1
        ;;
esac

# Dateiberechtigungen setzen
chmod 644 "\${CERT_FILE}"
chmod 600 "\${KEY_FILE}"

# Validierung
echo "🔍 Validiere Zertifikat..."
if openssl x509 -in "\${CERT_FILE}" -text -noout > /dev/null 2>&1; then
    echo "✅ Zertifikat ist gültig"
else
    echo "❌ Zertifikat ist ungültig"
    exit 1
fi

if openssl rsa -in "\${KEY_FILE}" -check > /dev/null 2>&1; then
    echo "✅ Private Key ist gültig"
else
    echo "❌ Private Key ist ungültig"
    exit 1
fi

# Zertifikat-Informationen anzeigen
echo "📋 Zertifikat-Informationen:"
openssl x509 -in "\${CERT_FILE}" -subject -issuer -dates -noout

echo "🎉 SSL-Setup erfolgreich abgeschlossen!"
`;

    try {
      fs.writeFileSync(this.setupScriptPath, scriptContent, { mode: 0o755 });
      console.log(`✅ [SSL] SSL-Setup Script erstellt: ${this.setupScriptPath}`);
      return true;
    } catch (error) {
      console.error(`❌ [SSL] Fehler beim Erstellen des SSL-Setup Scripts: ${error.message}`);
      return false;
    }
  }

  /**
   * Schedule certificate monitoring
   */
  scheduleMonitoring() {
    console.log("⏰ [SSL] Plane Zertifikat-Überwachung...");
    
    // Sofortige Überwachung starten
    this.monitorCertificates();
    
    // Tägliche Überprüfung um 2:00 Uhr
    const dailyCheck = () => {
      const now = new Date();
      const target = new Date();
      target.setHours(2, 0, 0, 0);
      
      if (target <= now) {
        target.setDate(target.getDate() + 1);
      }
      
      const timeToTarget = target.getTime() - now.getTime();
      
      setTimeout(() => {
        this.monitorCertificates();
        // Plane nächste Überprüfung
        setInterval(() => {
          this.monitorCertificates();
        }, 24 * 60 * 60 * 1000); // Alle 24 Stunden
      }, timeToTarget);
    };
    
    dailyCheck();
  }

  /**
   * Create SSL status report
   */
  async createStatusReport() {
    const status = await this.getStatus();
    const health = await this.performHealthCheck();
    const config = this.getConfigurationSummary();
    
    let report = `
🔐 SSL CERTIFICATE STATUS REPORT
Generated: ${new Date().toISOString()}

📊 OVERVIEW
Status: ${status.enabled ? '✅ ENABLED' : '❌ DISABLED'}
Domain: ${status.domain}
Method: ${status.method}
Auto-Renewal: ${status.autoRenewal ? '✅ ENABLED' : '❌ DISABLED'}

`;

    if (status.enabled) {
      report += `📋 CERTIFICATE DETAILS
Subject: ${status.subject}
Issuer: ${status.issuer}
Expires: ${status.expiryDate}
Days Until Expiry: ${status.expiresIn}
Needs Renewal: ${status.needsRenewal ? '⚠️ YES' : '✅ NO'}

`;
    }

    report += `🔍 HEALTH CHECK
Overall: ${health.overall}
Score: ${health.score}/${health.maxScore}

`;

    health.checks.forEach(check => {
      const statusIcon = check.status === 'PASS' ? '✅' : check.status === 'WARN' ? '⚠️' : '❌';
      report += `${statusIcon} ${check.name}: ${check.status}\n`;
      if (check.issues && check.issues.length > 0) {
        check.issues.forEach(issue => {
          report += `   - ${issue}\n`;
        });
      }
    });

    report += `
📂 CONFIGURATION
SSL Directory: ${config.sslPath}
Certificate: ${config.certPath}
Private Key: ${config.keyPath}
Setup Script: ${config.setupScriptPath} ${config.hasSetupScript ? '✅' : '❌'}

`;

    if (!config.validation.valid) {
      report += `⚠️ CONFIGURATION ISSUES\n`;
      config.validation.issues.forEach(issue => {
        report += `   - ${issue}\n`;
      });
      report += `\n`;
    }

    return report;
  }

  /**
   * Setup SSL with interactive prompts (for CLI usage)
   */
  async interactiveSetup() {
    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (prompt) => new Promise((resolve) => {
      rl.question(prompt, resolve);
    });

    try {
      console.log("🔐 SSL Interactive Setup");
      console.log("========================");

      const domain = await question(`Domain (aktuell: ${this.domain}): `) || this.domain;
      const email = await question(`Email (aktuell: ${this.email}): `) || this.email;
      
      console.log("\nVerfügbare SSL-Methoden:");
      console.log("1. selfsigned - Self-Signed Certificate (für Tests)");
      console.log("2. letsencrypt - Let's Encrypt (für Produktion)");
      console.log("3. cloudflare - Cloudflare Origin Certificate");
      console.log("4. manual - Manuelle Installation");
      
      const methodChoice = await question(`Wähle Methode (1-4, aktuell: ${this.method}): `);
      const methods = ['selfsigned', 'letsencrypt', 'cloudflare', 'manual'];
      const method = methods[parseInt(methodChoice) - 1] || this.method;
      
      const autoRenewal = (await question(`Auto-Renewal aktivieren? (y/n, aktuell: ${this.autoRenewal}): `).toLowerCase() === 'y') || this.autoRenewal;

      // Update configuration
      process.env.SSL_DOMAIN = domain;
      process.env.SSL_EMAIL = email;
      process.env.SSL_METHOD = method;
      process.env.SSL_AUTO_RENEWAL = autoRenewal.toString();

      // Update instance properties
      this.domain = domain;
      this.email = email;
      this.method = method;
      this.autoRenewal = autoRenewal;

      console.log("\n🔄 Starte SSL-Setup mit neuen Einstellungen...");
      
      const result = await this.obtainCertificate();
      
      console.log("\n✅ SSL-Setup erfolgreich abgeschlossen!");
      console.log(`Domain: ${domain}`);
      console.log(`Methode: ${method}`);
      console.log(`Auto-Renewal: ${autoRenewal}`);
      
      return result;
    } catch (error) {
      console.error("❌ Interactive Setup fehlgeschlagen:", error.message);
      throw error;
    } finally {
      rl.close();
    }
  }

  /**
   * Cleanup SSL files and directories
   */
  async cleanup() {
    console.log("🧹 [SSL] Cleanup wird durchgeführt...");
    
    try {
      // Cleanup old backups
      this.cleanupOldBackups();
      
      // Remove temporary files
      const tempFiles = [
        path.join(this.sslPath, '*.tmp'),
        path.join(this.sslPath, '*.csr'),
        path.join(this.sslPath, '*.log')
      ];
      
      tempFiles.forEach(pattern => {
        const files = require('glob').sync(pattern);
        files.forEach(file => {
          try {
            fs.unlinkSync(file);
            console.log(`🗑️ [SSL] Temporäre Datei gelöscht: ${file}`);
          } catch (error) {
            console.warn(`⚠️ [SSL] Konnte Datei nicht löschen: ${file}`);
          }
        });
      });
      
      console.log("✅ [SSL] Cleanup abgeschlossen");
    } catch (error) {
      console.error("❌ [SSL] Cleanup fehlgeschlagen:", error.message);
    }
  }

  /**
   * Get SSL certificate chain information
   */
  async getCertificateChain() {
    if (!fs.existsSync(this.certPath)) {
      return null;
    }

    return new Promise((resolve, reject) => {
      exec(`openssl crl2pkcs7 -nocrl -certfile "${this.certPath}" | openssl pkcs7 -print_certs -text -noout`, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`Certificate chain analysis failed: ${error.message}`));
          return;
        }

        try {
          const certificates = [];
          const certBlocks = stdout.split('Certificate:');
          
          certBlocks.forEach((block, index) => {
            if (index === 0) return; // Skip first empty block
            
            const subjectMatch = block.match(/Subject: (.+)/);
            const issuerMatch = block.match(/Issuer: (.+)/);
            const serialMatch = block.match(/Serial Number:\s*(.+)/);
            
            if (subjectMatch && issuerMatch) {
              certificates.push({
                position: index,
                subject: subjectMatch[1].trim(),
                issuer: issuerMatch[1].trim(),
                serial: serialMatch ? serialMatch[1].trim() : 'Unknown',
                type: index === 1 ? 'End Entity' : 'Intermediate CA'
              });
            }
          });

          resolve({
            certificateCount: certificates.length,
            certificates: certificates,
            isComplete: certificates.length > 1
          });
        } catch (parseError) {
          reject(new Error(`Certificate chain parsing failed: ${parseError.message}`));
        }
      });
    });
  }

  /**
   * Initialize SSL manager with automatic setup
   */
  async initialize() {
    console.log("🔄 [SSL] SSL Manager wird initialisiert...");
    
    try {
      // Ensure setup script exists
      if (!this.checkSetupScript()) {
        console.log("📝 [SSL] SSL-Setup Script wird generiert...");
        await this.generateSetupScript();
      }
      
      // Check current certificate status
      const status = await this.getStatus();
      
      if (!status.enabled) {
        console.log("⚠️ [SSL] Keine gültigen Zertifikate gefunden");
        
        if (this.method === 'selfsigned') {
          console.log("🔄 [SSL] Erstelle Self-Signed Zertifikat...");
          await this.obtainCertificate();
        } else {
          console.log("ℹ️ [SSL] Manuelle SSL-Konfiguration erforderlich");
        }
      } else {
        console.log(`✅ [SSL] SSL ist aktiviert (läuft ab in ${status.expiresIn} Tagen)`);
      }
      
      // Start monitoring
      this.scheduleMonitoring();
      
      console.log("✅ [SSL] SSL Manager erfolgreich initialisiert");
      return status;
    } catch (error) {
      console.error("❌ [SSL] SSL Manager Initialisierung fehlgeschlagen:", error.message);
      throw error;
    }
  }
}

module.exports = SSLCertificateManager;