/**
 * SSL Health Check Modul für Database Backup Tool
 * Erweiterte SSL-Überwachung und Gesundheitsprüfung
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { exec } = require('child_process');
const crypto = require('crypto');

class SSLHealthCheck {
  constructor(sslManager) {
    this.sslManager = sslManager;
    this.healthHistory = [];
    this.alertThresholds = {
      expiryWarning: 30, // Tage
      expiryCritical: 7,  // Tage
      keyStrengthMin: 2048,
      securityScoreMin: 70
    };
    
    console.log('🔍 [SSL HEALTH] Health Check System initialisiert');
  }

  /**
   * Führe komplette SSL-Gesundheitsprüfung durch
   */
  async performComprehensiveHealthCheck() {
    const healthReport = {
      timestamp: new Date().toISOString(),
      overall: 'UNKNOWN',
      score: 0,
      maxScore: 100,
      checks: [],
      recommendations: [],
      alerts: []
    };

    console.log('🔍 [SSL HEALTH] Starte umfassende Gesundheitsprüfung...');

    try {
      // 1. Zertifikat-Existenz prüfen
      await this.checkCertificateExistence(healthReport);
      
      // 2. Zertifikat-Gültigkeit prüfen
      await this.checkCertificateValidity(healthReport);
      
      // 3. Zertifikat-Stärke prüfen
      await this.checkCertificateStrength(healthReport);
      
      // 4. Zertifikat-Kette prüfen
      await this.checkCertificateChain(healthReport);
      
      // 5. SSL-Konfiguration prüfen
      await this.checkSSLConfiguration(healthReport);
      
      // 6. Netzwerk-Konnektivität prüfen
      await this.checkNetworkConnectivity(healthReport);
      
      // 7. Auto-Renewal Status prüfen
      await this.checkAutoRenewalStatus(healthReport);
      
      // 8. Sicherheits-Bewertung
      await this.performSecurityAssessment(healthReport);
      
      // Gesamt-Score berechnen
      this.calculateOverallScore(healthReport);
      
      // Empfehlungen generieren
      this.generateRecommendations(healthReport);
      
      // History speichern
      this.saveHealthHistory(healthReport);
      
      console.log(`🔍 [SSL HEALTH] Gesundheitsprüfung abgeschlossen - Status: ${healthReport.overall} (${healthReport.score}/${healthReport.maxScore})`);
      
      return healthReport;
    } catch (error) {
      console.error('❌ [SSL HEALTH] Gesundheitsprüfung fehlgeschlagen:', error);
      healthReport.overall = 'ERROR';
      healthReport.error = error.message;
      return healthReport;
    }
  }

  /**
   * Prüfe Zertifikat-Existenz
   */
  async checkCertificateExistence(healthReport) {
    const check = {
      name: 'Certificate Existence',
      status: 'UNKNOWN',
      weight: 20,
      details: {}
    };

    try {
      const certExists = fs.existsSync(this.sslManager.certPath);
      const keyExists = fs.existsSync(this.sslManager.keyPath);
      
      check.details.certificateExists = certExists;
      check.details.privateKeyExists = keyExists;
      check.details.certificatePath = this.sslManager.certPath;
      check.details.privateKeyPath = this.sslManager.keyPath;
      
      if (certExists && keyExists) {
        check.status = 'PASS';
        healthReport.score += check.weight;
        
        // Dateiberechtigungen prüfen
        const certStats = fs.statSync(this.sslManager.certPath);
        const keyStats = fs.statSync(this.sslManager.keyPath);
        
        check.details.certificatePermissions = (certStats.mode & parseInt('777', 8)).toString(8);
        check.details.privateKeyPermissions = (keyStats.mode & parseInt('777', 8)).toString(8);
        
        // Warnung bei unsicheren Berechtigungen
        if ((keyStats.mode & 0o077) !== 0) {
          check.status = 'WARN';
          check.details.warning = 'Private Key hat unsichere Berechtigungen';
          healthReport.recommendations.push('Setze Private Key Berechtigungen auf 600: chmod 600 ' + this.sslManager.keyPath);
        }
      } else {
        check.status = 'FAIL';
        check.details.error = 'Zertifikat oder Private Key nicht gefunden';
        healthReport.alerts.push({
          level: 'CRITICAL',
          message: 'SSL-Zertifikat oder Private Key fehlt'
        });
      }
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Prüfe Zertifikat-Gültigkeit
   */
  async checkCertificateValidity(healthReport) {
    const check = {
      name: 'Certificate Validity',
      status: 'UNKNOWN',
      weight: 25,
      details: {}
    };

    try {
      if (!fs.existsSync(this.sslManager.certPath)) {
        check.status = 'FAIL';
        check.details.error = 'Zertifikat-Datei nicht gefunden';
        healthReport.checks.push(check);
        return;
      }

      const certInfo = await this.sslManager.getCertificateInfo();
      
      check.details.subject = certInfo.subject;
      check.details.issuer = certInfo.issuer;
      check.details.expiryDate = certInfo.expiryDate;
      check.details.issueDate = certInfo.issueDate;
      check.details.expiresIn = certInfo.expiresIn;
      check.details.alternativeNames = certInfo.alternativeNames;
      
      if (certInfo.expiresIn < 0) {
        check.status = 'FAIL';
        check.details.error = 'Zertifikat ist abgelaufen';
        healthReport.alerts.push({
          level: 'CRITICAL',
          message: `Zertifikat ist seit ${Math.abs(certInfo.expiresIn)} Tagen abgelaufen`
        });
      } else if (certInfo.expiresIn <= this.alertThresholds.expiryCritical) {
        check.status = 'CRITICAL';
        healthReport.score += check.weight * 0.3;
        healthReport.alerts.push({
          level: 'CRITICAL',
          message: `Zertifikat läuft in ${certInfo.expiresIn} Tagen ab`
        });
      } else if (certInfo.expiresIn <= this.alertThresholds.expiryWarning) {
        check.status = 'WARN';
        healthReport.score += check.weight * 0.7;
        healthReport.alerts.push({
          level: 'WARNING',
          message: `Zertifikat läuft in ${certInfo.expiresIn} Tagen ab`
        });
      } else {
        check.status = 'PASS';
        healthReport.score += check.weight;
      }
      
      // Domain-Validierung
      if (certInfo.alternativeNames && certInfo.alternativeNames.length > 0) {
        const domainMatches = certInfo.alternativeNames.some(name => 
          name === this.sslManager.domain || name === `*.${this.sslManager.domain}`
        );
        
        if (!domainMatches) {
          check.status = 'WARN';
          check.details.warning = 'Domain stimmt nicht mit Zertifikat überein';
          healthReport.recommendations.push('Erstelle neues Zertifikat für korrekte Domain');
        }
      }
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Prüfe Zertifikat-Stärke
   */
  async checkCertificateStrength(healthReport) {
    const check = {
      name: 'Certificate Strength',
      status: 'UNKNOWN',
      weight: 15,
      details: {}
    };

    try {
      if (!fs.existsSync(this.sslManager.keyPath)) {
        check.status = 'FAIL';
        check.details.error = 'Private Key nicht gefunden';
        healthReport.checks.push(check);
        return;
      }

      // Key-Größe ermitteln
      const keySize = await this.getPrivateKeySize();
      check.details.keySize = keySize;
      check.details.keyType = 'RSA'; // TODO: Erweitern für andere Key-Typen
      
      if (keySize >= 4096) {
        check.status = 'EXCELLENT';
        healthReport.score += check.weight;
        check.details.securityLevel = 'Sehr hoch';
      } else if (keySize >= 2048) {
        check.status = 'PASS';
        healthReport.score += check.weight * 0.8;
        check.details.securityLevel = 'Hoch';
      } else if (keySize >= 1024) {
        check.status = 'WARN';
        healthReport.score += check.weight * 0.4;
        check.details.securityLevel = 'Niedrig';
        healthReport.recommendations.push('Verwende mindestens 2048-bit RSA Schlüssel');
      } else {
        check.status = 'FAIL';
        check.details.securityLevel = 'Unsicher';
        healthReport.alerts.push({
          level: 'CRITICAL',
          message: `Private Key zu schwach: ${keySize} bits`
        });
      }

      // Algorithmus-Stärke prüfen
      const certContent = fs.readFileSync(this.sslManager.certPath, 'utf8');
      if (certContent.includes('sha256')) {
        check.details.signatureAlgorithm = 'SHA-256';
        check.details.algorithmStrength = 'Stark';
      } else if (certContent.includes('sha1')) {
        check.details.signatureAlgorithm = 'SHA-1';
        check.details.algorithmStrength = 'Schwach';
        check.status = 'WARN';
        healthReport.recommendations.push('Verwende SHA-256 statt SHA-1 Signatur');
      }
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Prüfe Zertifikat-Kette
   */
  async checkCertificateChain(healthReport) {
    const check = {
      name: 'Certificate Chain',
      status: 'UNKNOWN',
      weight: 10,
      details: {}
    };

    try {
      const chainInfo = await this.sslManager.getCertificateChain();
      
      if (chainInfo) {
        check.details.certificateCount = chainInfo.certificateCount;
        check.details.isComplete = chainInfo.isComplete;
        check.details.certificates = chainInfo.certificates;
        
        if (chainInfo.isComplete) {
          check.status = 'PASS';
          healthReport.score += check.weight;
        } else {
          check.status = 'WARN';
          healthReport.score += check.weight * 0.5;
          check.details.warning = 'Zertifikat-Kette unvollständig';
          healthReport.recommendations.push('Vervollständige die Zertifikat-Kette mit Intermediate-Zertifikaten');
        }
      } else {
        check.status = 'FAIL';
        check.details.error = 'Zertifikat-Kette konnte nicht analysiert werden';
      }
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Prüfe SSL-Konfiguration
   */
  async checkSSLConfiguration(healthReport) {
    const check = {
      name: 'SSL Configuration',
      status: 'UNKNOWN',
      weight: 10,
      details: {}
    };

    try {
      const config = this.sslManager.getConfigurationSummary();
      
      check.details.domain = config.domain;
      check.details.method = config.method;
      check.details.autoRenewal = config.autoRenewal;
      check.details.hasSetupScript = config.hasSetupScript;
      
      let score = 0;
      let maxScore = 10;
      
      // Konfiguration bewerten
      if (config.validation.valid) {
        score += 5;
        check.status = 'PASS';
      } else {
        check.status = 'WARN';
        check.details.issues = config.validation.issues;
        healthReport.recommendations.push('Behebe Konfigurationsprobleme: ' + config.validation.issues.join(', '));
      }
      
      // Auto-Renewal bewerten
      if (config.autoRenewal && config.method !== 'selfsigned') {
        score += 3;
      } else if (config.method !== 'selfsigned') {
        healthReport.recommendations.push('Aktiviere Auto-Renewal für automatische Zertifikat-Erneuerung');
      }
      
      // Setup-Script bewerten
      if (config.hasSetupScript) {
        score += 2;
      } else {
        healthReport.recommendations.push('SSL-Setup Script fehlt');
      }
      
      healthReport.score += (score / maxScore) * check.weight;
      check.details.configScore = score;
      check.details.configMaxScore = maxScore;
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Prüfe Netzwerk-Konnektivität
   */
  async checkNetworkConnectivity(healthReport) {
    const check = {
      name: 'Network Connectivity',
      status: 'UNKNOWN',
      weight: 10,
      details: {}
    };

    try {
      const port = 8443; // Standard HTTPS Port
      const connectTest = await this.testSSLConnection(this.sslManager.domain, port);
      
      check.details.host = this.sslManager.domain;
      check.details.port = port;
      check.details.connectionTest = connectTest;
      
      if (connectTest.success) {
        check.status = 'PASS';
        healthReport.score += check.weight;
        check.details.responseTime = connectTest.responseTime;
        check.details.certificateFingerprint = connectTest.certificateFingerprint;
      } else {
        check.status = 'WARN';
        check.details.error = connectTest.error;
        healthReport.recommendations.push('Prüfe SSL-Verbindung und Firewall-Einstellungen');
      }
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Prüfe Auto-Renewal Status
   */
  async checkAutoRenewalStatus(healthReport) {
    const check = {
      name: 'Auto-Renewal Status',
      status: 'UNKNOWN',
      weight: 5,
      details: {}
    };

    try {
      const renewalScriptPath = path.join(this.sslManager.sslPath, 'renewal.sh');
      const cronConfigPath = '/etc/cron.d/ssl-renewal-db-backup';
      
      check.details.renewalScriptExists = fs.existsSync(renewalScriptPath);
      check.details.cronConfigExists = fs.existsSync(cronConfigPath);
      check.details.autoRenewalEnabled = this.sslManager.autoRenewal;
      
      if (this.sslManager.autoRenewal && this.sslManager.method !== 'selfsigned' && this.sslManager.method !== 'manual') {
        if (check.details.renewalScriptExists && check.details.cronConfigExists) {
          check.status = 'PASS';
          healthReport.score += check.weight;
        } else {
          check.status = 'WARN';
          check.details.warning = 'Auto-Renewal konfiguriert aber Scripts fehlen';
          healthReport.recommendations.push('Führe SSL-Setup erneut aus um Auto-Renewal zu reparieren');
        }
      } else {
        check.status = 'INFO';
        check.details.info = 'Auto-Renewal nicht konfiguriert oder nicht anwendbar';
      }
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Führe Sicherheits-Bewertung durch
   */
  async performSecurityAssessment(healthReport) {
    const check = {
      name: 'Security Assessment',
      status: 'UNKNOWN',
      weight: 5,
      details: {}
    };

    try {
      const securityLevel = await this.sslManager.getCertificateSecurityLevel();
      
      check.details.securityScore = securityLevel.score;
      check.details.securityLevel = securityLevel.level;
      check.details.securityIssues = securityLevel.issues;
      check.details.securityDetails = securityLevel.details;
      
      if (securityLevel.score >= 90) {
        check.status = 'EXCELLENT';
        healthReport.score += check.weight;
      } else if (securityLevel.score >= 70) {
        check.status = 'PASS';
        healthReport.score += check.weight * 0.8;
      } else if (securityLevel.score >= 50) {
        check.status = 'WARN';
        healthReport.score += check.weight * 0.5;
      } else {
        check.status = 'FAIL';
        healthReport.alerts.push({
          level: 'WARNING',
          message: `Niedriger Sicherheitsscore: ${securityLevel.score}`
        });
      }
      
      // Sicherheits-Empfehlungen hinzufügen
      securityLevel.issues.forEach(issue => {
        healthReport.recommendations.push('Sicherheit: ' + issue);
      });
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
    }

    healthReport.checks.push(check);
  }

  /**
   * Berechne Gesamt-Score
   */
  calculateOverallScore(healthReport) {
    const percentage = (healthReport.score / healthReport.maxScore) * 100;
    
    if (percentage >= 95) {
      healthReport.overall = 'EXCELLENT';
    } else if (percentage >= 85) {
      healthReport.overall = 'GOOD';
    } else if (percentage >= 70) {
      healthReport.overall = 'FAIR';
    } else if (percentage >= 50) {
      healthReport.overall = 'POOR';
    } else {
      healthReport.overall = 'CRITICAL';
    }
    
    healthReport.percentage = Math.round(percentage);
  }

  /**
   * Generiere Empfehlungen
   */
  generateRecommendations(healthReport) {
    // Priorisiere Empfehlungen basierend auf Schweregrad
    const criticalIssues = healthReport.alerts.filter(alert => alert.level === 'CRITICAL');
    const warningIssues = healthReport.alerts.filter(alert => alert.level === 'WARNING');
    
    if (criticalIssues.length > 0) {
      healthReport.recommendations.unshift('🚨 KRITISCH: Behebe sofort alle kritischen SSL-Probleme');
    }
    
    if (warningIssues.length > 0) {
      healthReport.recommendations.push('⚠️ WARNUNG: Behebe SSL-Warnungen zeitnah');
    }
    
    // Allgemeine Empfehlungen basierend auf Score
    if (healthReport.percentage < 70) {
      healthReport.recommendations.push('💡 TIPP: Führe SSL-Setup erneut aus um Probleme zu beheben');
    }
    
    if (healthReport.percentage < 50) {
      healthReport.recommendations.push('🔄 EMPFEHLUNG: Erstelle SSL-Zertifikat komplett neu');
    }
  }

  /**
   * Speichere Health History
   */
  saveHealthHistory(healthReport) {
    try {
      const historyFile = path.join(this.sslManager.sslPath, 'health-history.json');
      
      // Lade bestehende History
      let history = [];
      if (fs.existsSync(historyFile)) {
        const historyData = fs.readFileSync(historyFile, 'utf8');
        history = JSON.parse(historyData);
      }
      
      // Füge neuen Report hinzu
      history.push({
        timestamp: healthReport.timestamp,
        overall: healthReport.overall,
        score: healthReport.score,
        percentage: healthReport.percentage,
        alertCount: healthReport.alerts.length,
        recommendationCount: healthReport.recommendations.length
      });
      
      // Begrenze History auf letzte 100 Einträge
      if (history.length > 100) {
        history = history.slice(-100);
      }
      
      // Speichere History
      fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
      
      this.healthHistory = history;
      console.log(`📊 [SSL HEALTH] Health History gespeichert (${history.length} Einträge)`);
    } catch (error) {
      console.error('❌ [SSL HEALTH] Fehler beim Speichern der Health History:', error);
    }
  }

  /**
   * Hilfsmethoden
   */
  async getPrivateKeySize() {
    return new Promise((resolve, reject) => {
      const command = `openssl rsa -in "${this.sslManager.keyPath}" -text -noout | grep "Private-Key"`;
      exec(command, (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        
        const match = stdout.match(/Private-Key: \((\d+) bit/);
        resolve(match ? parseInt(match[1]) : 0);
      });
    });
  }

  async testSSLConnection(hostname, port) {
    return new Promise((resolve) => {
      const startTime = Date.now();
      
      const options = {
        hostname: hostname === 'localhost' ? 'localhost' : hostname,
        port: port,
        method: 'GET',
        timeout: 5000,
        rejectUnauthorized: false
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        const responseTime = Date.now() - startTime;
        
        resolve({
          success: true,
          responseTime: responseTime,
          statusCode: res.statusCode,
          certificateFingerprint: cert.fingerprint,
          certificateSubject: cert.subject
        });
      });

      req.on('error', (error) => {
        resolve({
          success: false,
          error: error.message,
          responseTime: Date.now() - startTime
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          success: false,
          error: 'Connection timeout',
          responseTime: Date.now() - startTime
        });
      });

      req.end();
    });
  }

  /**
   * Generiere Health Report als Text
   */
  generateHealthReportText(healthReport) {
    let report = `
🔍 SSL HEALTH CHECK REPORT
==========================
Zeitpunkt: ${new Date(healthReport.timestamp).toLocaleString('de-DE')}
Gesamt-Status: ${healthReport.overall}
Score: ${healthReport.score}/${healthReport.maxScore} (${healthReport.percentage}%)

📊 PRÜFUNGEN:
`;

    healthReport.checks.forEach(check => {
      const statusIcon = {
        'PASS': '✅',
        'EXCELLENT': '🌟',
        'WARN': '⚠️',
        'FAIL': '❌',
        'ERROR': '🚨',
        'INFO': 'ℹ️',
        'CRITICAL': '🔥'
      }[check.status] || '❓';
      
      report += `${statusIcon} ${check.name}: ${check.status}\n`;
      
      if (check.details.error) {
        report += `   Fehler: ${check.details.error}\n`;
      }
      if (check.details.warning) {
        report += `   Warnung: ${check.details.warning}\n`;
      }
    });

    if (healthReport.alerts.length > 0) {
      report += `\n🚨 ALERTS:\n`;
      healthReport.alerts.forEach(alert => {
        const alertIcon = alert.level === 'CRITICAL' ? '🔥' : '⚠️';
        report += `${alertIcon} ${alert.level}: ${alert.message}\n`;
      });
    }

    if (healthReport.recommendations.length > 0) {
      report += `\n💡 EMPFEHLUNGEN:\n`;
      healthReport.recommendations.forEach((rec, index) => {
        report += `${index + 1}. ${rec}\n`;
      });
    }

    report += `\n==========================\n`;
    
    return report;
  }

  /**
   * Starte kontinuierliche Überwachung
   */
  startContinuousMonitoring(intervalMinutes = 60) {
    console.log(`🔍 [SSL HEALTH] Starte kontinuierliche Überwachung (alle ${intervalMinutes} Minuten)`);
    
    const runHealthCheck = async () => {
      try {
        const healthReport = await this.performComprehensiveHealthCheck();
        
        // Kritische Alerts loggen
        healthReport.alerts.forEach(alert => {
          if (alert.level === 'CRITICAL') {
            console.error(`🚨 [SSL HEALTH] KRITISCH: ${alert.message}`);
          }
        });
        
        // Status-Änderungen loggen
        if (this.lastHealthStatus && this.lastHealthStatus !== healthReport.overall) {
          console.log(`🔄 [SSL HEALTH] Status geändert: ${this.lastHealthStatus} → ${healthReport.overall}`);
        }
        
        this.lastHealthStatus = healthReport.overall;
        
        // Bei kritischen Problemen öfter prüfen
        if (healthReport.overall === 'CRITICAL' || healthReport.overall === 'POOR') {
          console.log('⚡ [SSL HEALTH] Kritische Probleme erkannt - erhöhe Prüffrequenz');
          setTimeout(runHealthCheck, 10 * 60 * 1000); // 10 Minuten
        }
      } catch (error) {
        console.error('❌ [SSL HEALTH] Monitoring-Fehler:', error);
      }
    };
    
    // Sofortige erste Prüfung
    runHealthCheck();
    
    // Regelmäßige Prüfungen
    setInterval(runHealthCheck, intervalMinutes * 60 * 1000);
  }

  /**
   * Exportiere Health Report
   */
  async exportHealthReport(format = 'json') {
    const healthReport = await this.performComprehensiveHealthCheck();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    switch (format.toLowerCase()) {
      case 'json':
        const jsonFile = path.join(this.sslManager.sslPath, `health-report-${timestamp}.json`);
        fs.writeFileSync(jsonFile, JSON.stringify(healthReport, null, 2));
        console.log(`📄 [SSL HEALTH] JSON Report exportiert: ${jsonFile}`);
        return jsonFile;
        
      case 'txt':
        const txtFile = path.join(this.sslManager.sslPath, `health-report-${timestamp}.txt`);
        const textReport = this.generateHealthReportText(healthReport);
        fs.writeFileSync(txtFile, textReport);
        console.log(`📄 [SSL HEALTH] Text Report exportiert: ${txtFile}`);
        return txtFile;
        
      default:
        throw new Error(`Unbekanntes Format: ${format}`);
    }
  }

  /**
   * Lade Health History
   */
  getHealthHistory() {
    return this.healthHistory;
  }

  /**
   * Bereinige alte Health Reports
   */
  cleanupOldReports(maxAge = 30) {
    try {
      const reportPattern = /^health-report-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/;
      const cutoffDate = new Date(Date.now() - maxAge * 24 * 60 * 60 * 1000);
      
      const files = fs.readdirSync(this.sslManager.sslPath);
      let cleanedCount = 0;
      
      files.forEach(file => {
        if (reportPattern.test(file)) {
          const filePath = path.join(this.sslManager.sslPath, file);
          const stats = fs.statSync(filePath);
          
          if (stats.mtime < cutoffDate) {
            fs.unlinkSync(filePath);
            cleanedCount++;
          }
        }
      });
      
      if (cleanedCount > 0) {
        console.log(`🧹 [SSL HEALTH] ${cleanedCount} alte Health Reports bereinigt`);
      }
    } catch (error) {
      console.error('❌ [SSL HEALTH] Fehler beim Bereinigen alter Reports:', error);
    }
  }
}

module.exports = SSLHealthCheck;