const express = require("express");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const cron = require("node-cron");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const mysqldump = require("mysqldump");

class DatabaseBackupTool {
  constructor() {
    this.app = express();
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
    this.gitBackupPath = path.join(this.config.backup.defaultPath, "git-backup");
    
    this.init();
  }

  loadConfig() {
    try {
      const config = JSON.parse(fs.readFileSync("config.json", "utf8"));

      // Umgebungsvariablen überschreiben Konfiguration
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
      if (process.env.GIT_BACKUP_TOKEN) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.token = process.env.GIT_BACKUP_TOKEN;
      }
      if (process.env.GIT_BACKUP_BRANCH) {
        config.gitBackup = config.gitBackup || {};
        config.gitBackup.branch = process.env.GIT_BACKUP_BRANCH;
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

  async init() {
    // Auto-Update beim Start ausführen
    if (this.config.updates && this.config.updates.autoUpdate) {
      console.log("🔄 Auto-Update ist aktiviert, prüfe auf Updates...");
      await this.checkForUpdates();
    }

    this.setupMiddleware();
    this.setupRoutes();
    this.setupDefaultUser();
    this.ensureDirectories();
    await this.initializeGitBackup();
    this.loadSchedulesFromFile();
    this.startServer();
  }

  // Enhanced execPromise mit detailliertem Debugging
  execPromiseWithDebug(command, operation, hideOutput = false, timeout = 10000) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      console.log(`🔧 [${operation}] Starte: ${hideOutput ? '[COMMAND HIDDEN FOR SECURITY]' : command}`);
      
      const execTimeout = setTimeout(() => {
        console.error(`⏰ [${operation}] TIMEOUT nach ${timeout}ms`);
        console.error(`   Command: ${hideOutput ? '[HIDDEN]' : command}`);
        reject(new Error(`${operation} timeout after ${timeout}ms`));
      }, timeout);
      
      exec(command, { 
        cwd: process.cwd(),
        env: { 
          ...process.env, 
          GIT_TERMINAL_PROMPT: '0',  // Verhindert interaktive Prompts
          GIT_ASKPASS: 'echo',       // Leere Antworten für Passwort-Prompts
        }
      }, (error, stdout, stderr) => {
        clearTimeout(execTimeout);
        const duration = Date.now() - startTime;
        
        if (error) {
          console.error(`❌ [${operation}] FEHLER nach ${duration}ms:`);
          console.error(`   Exit Code: ${error.code}`);
          console.error(`   Error Message: ${error.message}`);
          if (stderr) {
            console.error(`   Stderr: ${stderr}`);
          }
          if (stdout && !hideOutput) {
            console.error(`   Stdout: ${stdout}`);
          }
          reject(new Error(`${operation} failed: ${error.message}${stderr ? ` | Stderr: ${stderr}` : ''}`));
        } else {
          console.log(`✅ [${operation}] ERFOLG nach ${duration}ms`);
          if (stdout && !hideOutput) {
            console.log(`   Output: ${stdout.trim()}`);
          }
          if (stderr && !hideOutput) {
            console.log(`   Stderr (non-fatal): ${stderr.trim()}`);
          }
          resolve(stdout);
        }
      });
    });
  }

  // Debug: Git Konfiguration vollständig ausgeben
  debugGitConfiguration() {
    console.log("🔍 [GIT DEBUG] Vollständige Git Konfiguration:");
    console.log("================================");
    console.log(`   config.gitBackup: ${JSON.stringify(this.config.gitBackup, (key, value) => {
      if (key === 'token' && value) return '[HIDDEN_' + value.length + '_CHARS]';
      return value;
    }, 2)}`);
    console.log("================================");
    
    // Umgebungsvariablen prüfen
    console.log("🔍 [GIT DEBUG] Umgebungsvariablen:");
    console.log(`   GIT_BACKUP_ENABLED: ${process.env.GIT_BACKUP_ENABLED || 'NOT SET'}`);
    console.log(`   GIT_BACKUP_REPOSITORY: ${process.env.GIT_BACKUP_REPOSITORY || 'NOT SET'}`);
    console.log(`   GIT_BACKUP_USERNAME: ${process.env.GIT_BACKUP_USERNAME || 'NOT SET'}`);
    console.log(`   GIT_BACKUP_TOKEN: ${process.env.GIT_BACKUP_TOKEN ? '[SET_' + process.env.GIT_BACKUP_TOKEN.length + '_CHARS]' : 'NOT SET'}`);
    console.log(`   GIT_BACKUP_BRANCH: ${process.env.GIT_BACKUP_BRANCH || 'NOT SET'}`);
    console.log("================================");
    
    // Token-spezifisches Debugging
    this.debugTokenStatus();
    console.log("================================");
  }

  // NEU: Debug Token-Status - HIER EINFÜGEN!
  debugTokenStatus() {
    console.log("🔍 [TOKEN DEBUG] Token Status:");
    console.log(`   config.gitBackup exists: ${!!this.config.gitBackup}`);
    console.log(`   config.gitBackup.token exists: ${!!this.config.gitBackup?.token}`);
    console.log(`   config.gitBackup.token length: ${this.config.gitBackup?.token?.length || 0}`);
    console.log(`   config.gitBackup.token type: ${typeof this.config.gitBackup?.token}`);
    
    // Umgebungsvariable auch prüfen
    console.log(`   process.env.GIT_BACKUP_TOKEN exists: ${!!process.env.GIT_BACKUP_TOKEN}`);
    console.log(`   process.env.GIT_BACKUP_TOKEN length: ${process.env.GIT_BACKUP_TOKEN?.length || 0}`);
  }

  // Verbesserte buildGitRemoteUrl mit Debug
  buildGitRemoteUrl() {
    console.log("🔍 [GIT URL] Starte Git Remote URL Erstellung (GitHub Fix)...");
    
    // Debug: Komplette Konfiguration ausgeben
    this.debugGitConfiguration();
    
    const gitConfig = this.config.gitBackup || {};
    const { repository, username, token } = gitConfig;
    
    console.log("🔍 [GIT URL] Extrahierte Werte:");
    console.log(`   Repository: '${repository || 'EMPTY'}'`);
    console.log(`   Username: '${username || 'EMPTY'}'`);
    console.log(`   Token: ${token ? '[SET_' + token.length + '_CHARS]' : 'EMPTY'}`);
    
    // Validierung
    if (!repository) {
      console.error("❌ [GIT URL] Repository URL ist leer oder undefined!");
      return null;
    }
    
    if (!token) {
      console.error("❌ [GIT URL] Token ist leer oder undefined!");
      return null;
    }
    
    try {
      // URL parsen und validieren
      const url = new URL(repository);
      console.log(`🔍 [GIT URL] URL-Komponenten:`);
      console.log(`   Protocol: ${url.protocol}`);
      console.log(`   Host: ${url.host}`);
      console.log(`   Pathname: ${url.pathname}`);
      
      // GitHub-spezifische Authentifizierung
      let authenticatedUrl;
      
      if (url.host.includes('github.com')) {
        console.log("🔍 [GIT URL] GitHub erkannt - verwende Token-basierte Authentifizierung");
        
        // Für GitHub: Token als Username, kein Passwort
        // Format: https://TOKEN@github.com/user/repo.git
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedToken}@${url.host}${url.pathname}`;
        
        console.log(`✅ [GIT URL] GitHub-Token Authentifizierung konfiguriert`);
        console.log(`🔍 [GIT URL] URL Format: ${url.protocol}//[TOKEN]@${url.host}${url.pathname}`);
        
      } else if (url.host.includes('gitlab.com')) {
        console.log("🔍 [GIT URL] GitLab erkannt - verwende Username:Token Authentifizierung");
        
        // Für GitLab: Username:Token Format
        const encodedUsername = encodeURIComponent(username || 'oauth2');
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedUsername}:${encodedToken}@${url.host}${url.pathname}`;
        
        console.log(`✅ [GIT URL] GitLab Username:Token Authentifizierung konfiguriert`);
        console.log(`🔍 [GIT URL] URL Format: ${url.protocol}//[USERNAME]:[TOKEN]@${url.host}${url.pathname}`);
        
      } else if (url.host.includes('bitbucket.org')) {
        console.log("🔍 [GIT URL] Bitbucket erkannt - verwende Username:AppPassword Authentifizierung");
        
        // Für Bitbucket: Username:AppPassword Format
        if (!username) {
          console.error("❌ [GIT URL] Username ist für Bitbucket erforderlich!");
          return null;
        }
        
        const encodedUsername = encodeURIComponent(username);
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedUsername}:${encodedToken}@${url.host}${url.pathname}`;
        
        console.log(`✅ [GIT URL] Bitbucket Username:AppPassword Authentifizierung konfiguriert`);
        console.log(`🔍 [GIT URL] URL Format: ${url.protocol}//[USERNAME]:[APPPASSWORD]@${url.host}${url.pathname}`);
        
      } else {
        console.log("🔍 [GIT URL] Unbekannter Git-Provider - verwende Standard Username:Token Format");
        
        // Für andere Provider: Standard Username:Token
        const encodedUsername = encodeURIComponent(username || 'git');
        const encodedToken = encodeURIComponent(token);
        authenticatedUrl = `${url.protocol}//${encodedUsername}:${encodedToken}@${url.host}${url.pathname}`;
        
        console.log(`✅ [GIT URL] Standard Username:Token Authentifizierung konfiguriert`);
        console.log(`🔍 [GIT URL] URL Format: ${url.protocol}//[USERNAME]:[TOKEN]@${url.host}${url.pathname}`);
      }
      
      console.log(`✅ [GIT URL] Authentifizierte URL für ${url.host} erstellt`);
      return authenticatedUrl;
      
    } catch (error) {
      console.error("❌ [GIT URL] Fehler beim Parsen der Repository URL:", error);
      console.error(`   Repository Wert: '${repository}'`);
      return null;
    }
  }

// ZUSÄTZLICH: Erweiterte Validierung für Git-Provider
// Füge diese Methode auch hinzu:

  // Validiere Git-Provider spezifische Konfiguration
  validateGitProviderConfig(repository, username, token) {
    const issues = [];
    
    try {
      const url = new URL(repository);
      
      if (url.host.includes('github.com')) {
        // GitHub braucht nur Token
        if (!token) {
          issues.push("GitHub Personal Access Token ist erforderlich");
        }
        if (token && !token.startsWith('ghp_') && !token.startsWith('github_pat_')) {
          issues.push("GitHub Token sollte mit 'ghp_' oder 'github_pat_' beginnen");
        }
        
      } else if (url.host.includes('gitlab.com')) {
        // GitLab braucht Token, Username ist optional
        if (!token) {
          issues.push("GitLab Personal Access Token ist erforderlich");
        }
        
      } else if (url.host.includes('bitbucket.org')) {
        // Bitbucket braucht Username und App Password
        if (!username) {
          issues.push("Bitbucket Username ist erforderlich");
        }
        if (!token) {
          issues.push("Bitbucket App Password ist erforderlich");
        }
        
      } else {
        // Andere Provider
        if (!token) {
          issues.push("Personal Access Token ist erforderlich");
        }
      }
      
    } catch (error) {
      issues.push("Repository URL ist ungültig");
    }
    
    return issues;
  }

  // Hilfsmethode: Generate Git Debug Info
  generateGitDebugInfo() {
    const gitBackupEnabled = this.config.gitBackup?.enabled || false;
    const gitConfig = this.config.gitBackup || {};
    
    return {
      enabled: gitBackupEnabled,
      repository: gitConfig.repository || 'NOT SET',
      username: gitConfig.username ? 'SET' : 'NOT SET',
      token: gitConfig.token ? `SET (${gitConfig.token.length} chars)` : 'NOT SET',
      branch: gitConfig.branch || 'main',
      gitBackupPath: this.gitBackupPath,
      gitBackupPathExists: fs.existsSync(this.gitBackupPath),
      gitRepositoryExists: fs.existsSync(path.join(this.gitBackupPath, '.git')),
      systemInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        cwd: process.cwd()
      }
    };
  }

  // Hilfsmethode: Generate Git Troubleshooting Info
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
      suggestions.push("Setze eine gültige HTTPS Repository URL (z.B. https://github.com/username/repo.git)");
    }
    
    if (!config.username) {
      issues.push("Git Username ist nicht gesetzt");
      suggestions.push("Setze deinen Git-Benutzernamen");
    }
    
    if (!config.token) {
      issues.push("Personal Access Token ist nicht gesetzt");
      suggestions.push("Erstelle einen Personal Access Token mit 'repo' Berechtigung");
    }
    
    if (!fs.existsSync(this.gitBackupPath)) {
      issues.push("Git Backup Verzeichnis existiert nicht");
      suggestions.push("Das Verzeichnis wird automatisch erstellt - prüfe Dateiberechtigungen");
    }
    
    if (fs.existsSync(this.gitBackupPath) && !fs.existsSync(path.join(this.gitBackupPath, '.git'))) {
      issues.push("Git Repository ist nicht initialisiert");
      suggestions.push("Das Repository wird automatisch initialisiert - prüfe Git-Installation");
    }
    
    return {
      issues: issues,
      suggestions: suggestions,
      nextSteps: [
        "1. Überprüfe die Git Backup Konfiguration im Web-Interface",
        "2. Stelle sicher, dass das Repository existiert und zugänglich ist",
        "3. Verwende den 'Verbindung testen' Button",
        "4. Prüfe die Server-Logs für detaillierte Fehlermeldungen"
      ]
    };
  }
  // Verbesserte Git Repository Initialisierung mit robuster URL-Behandlung
  async initializeGitBackup() {
    if (!this.config.gitBackup?.enabled) {
      console.log("📦 Git Backup ist deaktiviert");
      return;
    }

    try {
      console.log("🔧 Initialisiere Git Backup Repository...");
      console.log(`📁 Git Backup Pfad: ${this.gitBackupPath}`);
      
      // Debug-Ausgabe der Konfiguration
      this.debugGitConfiguration();
      
      // Git Backup Verzeichnis erstellen falls nicht vorhanden
      if (!fs.existsSync(this.gitBackupPath)) {
        console.log("📁 Erstelle Git Backup Verzeichnis...");
        fs.mkdirSync(this.gitBackupPath, { recursive: true });
      }

      const isGitRepo = fs.existsSync(path.join(this.gitBackupPath, ".git"));
      console.log(`🔍 Git Repository Status: ${isGitRepo ? 'Existiert' : 'Nicht initialisiert'}`);
      
      if (!isGitRepo) {
        console.log("📁 Erstelle neues Git Repository für Backups...");
        
        // Git Repository initialisieren
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git init`, "Git Init");
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git config user.name "DB Backup Tool"`, "Git Config Name");
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git config user.email "backup@localhost"`, "Git Config Email");
        
        // README erstellen
        const readmeContent = `# Database Backups\n\nAutomatisch erstellte Datenbank-Backups vom DB Backup Tool.\n\nErstellt am: ${new Date().toLocaleString('de-DE')}\n`;
        fs.writeFileSync(path.join(this.gitBackupPath, "README.md"), readmeContent);
        console.log("📝 README.md erstellt");
        
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git add README.md`, "Git Add README");
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git commit -m "Initial commit: Setup backup repository"`, "Git Initial Commit");
      }

      // Remote Repository Setup - Der kritische Teil!
      if (this.config.gitBackup.repository) {
        console.log("🔗 [GIT REMOTE] Starte Remote Repository Setup...");
        
        const remoteUrl = this.buildGitRemoteUrl();
        
        if (!remoteUrl) {
          console.error("❌ [GIT REMOTE] Konnte authentifizierte Git Remote URL nicht erstellen");
          console.error("   Mögliche Ursachen:");
          console.error("   1. Repository URL fehlt oder ist ungültig");
          console.error("   2. Username ist nicht gesetzt");
          console.error("   3. Personal Access Token ist nicht gesetzt");
          return;
        }
        
        try {
          // Prüfe ob remote bereits existiert
          console.log("🔍 [GIT REMOTE] Prüfe bestehende Remote-Konfiguration...");
          const currentRemote = await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote get-url origin`, "Check Remote", false);
          console.log(`🔗 [GIT REMOTE] Bestehender Remote gefunden`);
          
          // Remote URL aktualisieren mit neuer authentifizierter URL
          console.log("🔄 [GIT REMOTE] Aktualisiere Remote URL mit Authentifizierung...");
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote set-url origin "${remoteUrl}"`, "Update Remote URL", true);
          console.log("✅ [GIT REMOTE] Remote URL mit Authentifizierung aktualisiert");
          
        } catch (error) {
          // Remote existiert nicht, füge hinzu
          console.log("🔗 [GIT REMOTE] Kein Remote vorhanden, füge neuen mit Authentifizierung hinzu...");
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote add origin "${remoteUrl}"`, "Add Remote", true);
          console.log("✅ [GIT REMOTE] Neuer Remote mit Authentifizierung hinzugefügt");
        }

        // Validiere Remote URL (ohne Token anzuzeigen)
        try {
          const finalRemoteCheck = await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote get-url origin`, "Final Remote Check", true);
          console.log("✅ [GIT REMOTE] Remote URL erfolgreich konfiguriert");
        } catch (remoteCheckError) {
          console.error("❌ [GIT REMOTE] Remote URL Validation fehlgeschlagen:", remoteCheckError);
        }

        // Branch konfigurieren
        const branch = this.config.gitBackup.branch || "main";
        console.log(`🌿 [GIT BRANCH] Konfiguriere Branch: ${branch}`);
        
        try {
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git checkout -B ${branch}`, "Checkout Branch");
          console.log(`✅ [GIT BRANCH] Branch ${branch} konfiguriert`);
        } catch (error) {
          console.log(`⚠️ [GIT BRANCH] Branch checkout fehlgeschlagen: ${error.message}`);
        }
        
        // KRITISCHER TEST: Erster Push mit authentifizierter URL
        try {
          console.log("🧪 [GIT TEST] Teste authentifizierten Push...");
          console.log("   WICHTIG: Dies ist der Test, ob die Authentifizierung funktioniert!");
          
          // Längerer Timeout für ersten Push
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git push -u origin ${branch}`, "Authenticated Push Test", true, 60000);
          console.log("✅ [GIT TEST] Authentifizierter Push erfolgreich - Git Backup voll funktionsfähig!");
          
        } catch (error) {
          console.error("❌ [GIT TEST] Authentifizierter Push fehlgeschlagen:");
          console.error(`   Fehler: ${error.message}`);
          console.error("   DIAGNOSE:");
          
          if (error.message.includes("Username for")) {
            console.error("   → Git fragt immer noch nach Username - Authentifizierung wurde nicht übernommen!");
            console.error("   → Mögliche Ursachen:");
            console.error("     1. Token ist ungültig oder abgelaufen");
            console.error("     2. Token hat nicht die richtige Berechtigung ('repo')");
            console.error("     3. Username ist falsch");
            console.error("     4. Repository existiert nicht oder ist nicht zugänglich");
          } else if (error.message.includes("timeout")) {
            console.error("   → Timeout - möglicherweise Netzwerkproblem oder Git Server langsam");
          } else if (error.message.includes("remote rejected")) {
            console.error("   → Remote hat Push abgelehnt - prüfe Repository-Berechtigungen");
          }
          
          // Versuche einen einfachen Push ohne -u Flag
          try {
            console.log("🔄 [GIT TEST] Versuche einfachen Push ohne -u Flag...");
            await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git push origin ${branch}`, "Simple Authenticated Push", true, 30000);
            console.log("✅ [GIT TEST] Einfacher authentifizierter Push erfolgreich!");
          } catch (simplePushError) {
            console.error("❌ [GIT TEST] Auch einfacher Push fehlgeschlagen:");
            console.error(`   Fehler: ${simplePushError.message}`);
            console.error("   → Git Backup wird nicht funktionieren bis das Problem behoben ist!");
          }
        }
      }

    } catch (error) {
      console.error("❌ Fehler beim Initialisieren des Git Backup Repositories:");
      console.error(`   Fehler: ${error.message}`);
      console.error(`   Stack: ${error.stack}`);
    }
  }

  // Enhanced Backup zu Git Repository pushen mit detailliertem Debug
  async pushBackupToGit(backupFilePath, filename) {
    if (!this.config.gitBackup?.enabled || !this.config.gitBackup?.repository) {
      console.log("📤 Git Backup ist deaktiviert oder nicht konfiguriert");
      return { success: false, reason: "disabled" };
    }

    const startTime = Date.now();
    console.log(`📤 [GIT PUSH] Starte Git Push für: ${filename}`);
    console.log(`   Backup Datei: ${backupFilePath}`);
    console.log(`   Git Verzeichnis: ${this.gitBackupPath}`);

    try {
      // Pre-Push Validierungen
      if (!fs.existsSync(backupFilePath)) {
        throw new Error(`Backup-Datei nicht gefunden: ${backupFilePath}`);
      }

      if (!fs.existsSync(this.gitBackupPath)) {
        throw new Error(`Git Backup Verzeichnis nicht gefunden: ${this.gitBackupPath}`);
      }

      if (!fs.existsSync(path.join(this.gitBackupPath, ".git"))) {
        throw new Error("Git Repository nicht initialisiert");
      }

      // Debug: Aktuelle Git Konfiguration vor Push
      console.log("🔍 [GIT PUSH] Aktuelle Git Konfiguration:");
      this.debugGitConfiguration();

      // Git Status prüfen
      console.log("🔍 [GIT PUSH] Prüfe Git Status...");
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git status --porcelain`, "Git Status Check");
      
      // Remote URL validieren (ohne Token anzuzeigen)
      console.log("🔗 [GIT PUSH] Validiere Remote URL...");
      try {
        const remoteUrl = await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote get-url origin`, "Get Remote URL", true);
        
        // Prüfe ob Remote URL Authentifizierung enthält
        if (remoteUrl.includes('@')) {
          console.log("✅ [GIT PUSH] Remote URL enthält Authentifizierung");
        } else {
          console.error("❌ [GIT PUSH] Remote URL enthält KEINE Authentifizierung!");
          console.error("   → Das ist wahrscheinlich die Ursache für den Username-Prompt!");
          
          // Versuche Remote URL zu reparieren
          console.log("🔄 [GIT PUSH] Versuche Remote URL zu reparieren...");
          const newRemoteUrl = this.buildGitRemoteUrl();
          if (newRemoteUrl) {
            await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote set-url origin "${newRemoteUrl}"`, "Fix Remote URL", true);
            console.log("✅ [GIT PUSH] Remote URL mit Authentifizierung repariert");
          } else {
            throw new Error("Konnte Remote URL nicht reparieren - Git Konfiguration ist unvollständig");
          }
        }
      } catch (remoteError) {
        console.error("❌ [GIT PUSH] Remote URL Validation fehlgeschlagen:", remoteError);
        throw new Error("Git Remote ist nicht korrekt konfiguriert");
      }

      // Backup-Datei ins Git Repository kopieren
      console.log("📁 [GIT PUSH] Kopiere Backup-Datei...");
      const gitBackupFile = path.join(this.gitBackupPath, filename);
      fs.copyFileSync(backupFilePath, gitBackupFile);
      
      const stats = fs.statSync(gitBackupFile);
      console.log(`✅ [GIT PUSH] Datei kopiert (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);
      
      // Git Add
      console.log("➕ [GIT PUSH] Git Add...");
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git add "${filename}"`, "Git Add");
      
      // Git Commit
      const commitMessage = `Add backup: ${filename} (${new Date().toLocaleString('de-DE')})`;
      console.log("💾 [GIT PUSH] Git Commit...");
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git commit -m "${commitMessage}"`, "Git Commit");
      
      // Git Push - Der kritische Teil!
      const branch = this.config.gitBackup.branch || "main";
      console.log(`🚀 [GIT PUSH] Git Push zu Branch: ${branch}`);
      console.log("   Dies ist der kritische Schritt - detailliertes Logging aktiv...");
      console.log("   Timeout: 60 Sekunden");
      
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git push origin ${branch}`, "Git Push", true, 60000);
      
      const duration = Date.now() - startTime;
      console.log(`✅ [GIT PUSH] ERFOLGREICH abgeschlossen nach ${duration}ms`);
      console.log(`   Datei: ${filename} erfolgreich zu Git gepusht`);
      
      // Cleanup alte Backups im Git Repository
      await this.cleanupGitBackups();
      
      return { success: true, duration: duration };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`❌ [GIT PUSH] FEHLGESCHLAGEN nach ${duration}ms`);
      console.error(`   Datei: ${filename}`);
      console.error(`   Fehler: ${error.message}`);
      console.error(`   Stack: ${error.stack}`);
      
      // Zusätzliche Diagnose-Informationen
      try {
        console.log("🔍 [GIT PUSH] Zusätzliche Diagnose...");
        const gitStatus = await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git status`, "Post-Error Git Status");
        console.log("📊 [GIT PUSH] Git Status nach Fehler:", gitStatus);
        
        // Prüfe Remote URL nach Fehler
        const remoteUrlAfterError = await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote get-url origin`, "Post-Error Remote Check", true);
        console.log("🔗 [GIT PUSH] Remote URL nach Fehler validiert");
        
      } catch (diagError) {
        console.error("❌ [GIT PUSH] Diagnose fehlgeschlagen:", diagError.message);
      }
      
      throw error;
    }
  }

  // Enhanced Git Test Methode
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
    
    // Repository URL validieren
    try {
      new URL(this.config.gitBackup.repository);
    } catch (error) {
      throw new Error("Git Repository URL ist ungültig");
    }
    
    console.log("✅ [GIT TEST] Konfiguration validiert");
    
    // Debug: Git Konfiguration vor Test
    this.debugGitConfiguration();
    
    try {
      // Stelle sicher, dass Git Repository initialisiert ist
      await this.initializeGitBackup();
      
      // Test-Datei erstellen
      const testFilename = `git_test_${Date.now()}.txt`;
      const testContent = `Git Backup Verbindungstest\nErstellt am: ${new Date().toLocaleString('de-DE')}\nTest ID: ${Math.random().toString(36).substr(2, 9)}\n`;
      const testFilePath = path.join(this.gitBackupPath, testFilename);
      
      console.log(`📝 [GIT TEST] Erstelle Test-Datei: ${testFilename}`);
      fs.writeFileSync(testFilePath, testContent);
      
      // Git operations testen
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git add "${testFilename}"`, "Test Git Add");
      
      const commitMessage = `Test: Git Backup Verbindungstest ${new Date().toISOString()}`;
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git commit -m "${commitMessage}"`, "Test Git Commit");
      
      const branch = this.config.gitBackup.branch || "main";
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git push origin ${branch}`, "Test Git Push", true, 45000);
      
      // Test-Datei wieder entfernen
      console.log("🧹 [GIT TEST] Entferne Test-Datei...");
      fs.unlinkSync(testFilePath);
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git add "${testFilename}"`, "Test Git Add (Delete)");
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git commit -m "Remove test file: ${testFilename}"`, "Test Git Commit (Delete)");
      await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git push origin ${branch}`, "Test Git Push (Delete)", true, 30000);
      
      console.log("✅ [GIT TEST] Verbindungstest erfolgreich abgeschlossen");
      return { success: true, message: "Git Backup Verbindung erfolgreich getestet" };
      
    } catch (error) {
      console.error("❌ [GIT TEST] Verbindungstest fehlgeschlagen:");
      console.error(`   Fehler: ${error.message}`);
      throw new Error(`Git Backup Test fehlgeschlagen: ${error.message}`);
    }
  }
  // Enhanced Git Backup Cleanup mit Debug
  async cleanupGitBackups() {
    if (!this.config.gitBackup?.enabled) {
      return;
    }

    try {
      console.log("🧹 [GIT CLEANUP] Prüfe Git Repository auf alte Backups...");
      
      // Liste aller Backup-Dateien im Git Repository
      const files = fs.readdirSync(this.gitBackupPath)
        .filter(file => file.endsWith('.sql') || file.endsWith('.sql.gz'))
        .map(file => {
          const filePath = path.join(this.gitBackupPath, file);
          const stats = fs.statSync(filePath);
          return {
            filename: file,
            path: filePath,
            created: stats.birthtime
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
          
          // Datei löschen
          fs.unlinkSync(fileToDelete.path);
          
          // Git Add für gelöschte Datei
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git add "${fileToDelete.filename}"`, "Git Add (Delete)");
        }
        
        if (filesToDelete.length > 0) {
          const commitMessage = `Cleanup: Remove ${filesToDelete.length} old backup(s) (${new Date().toLocaleString('de-DE')})`;
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git commit -m "${commitMessage}"`, "Git Commit (Cleanup)");
          
          const branch = this.config.gitBackup.branch || "main";
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git push origin ${branch}`, "Git Push (Cleanup)", true, 30000);
          
          console.log(`✅ [GIT CLEANUP] ${filesToDelete.length} alte Backup(s) aus Git Repository entfernt`);
        }
      } else {
        console.log("✅ [GIT CLEANUP] Git Repository Cleanup nicht erforderlich");
      }
      
    } catch (error) {
      console.error("❌ [GIT CLEANUP] Fehler beim Git Repository Cleanup:");
      console.error(`   Fehler: ${error.message}`);
    }
  }

  // Verbesserte Git Konfiguration API
  async updateGitBackupConfig(req, res) {
    try {
      const { enabled, repository, username, token, branch } = req.body;
      
      console.log("🔧 [CONFIG API] Git Backup Konfiguration wird aktualisiert...");
      console.log(`   Enabled: ${enabled}`);
      console.log(`   Repository: '${repository || 'NOT SET'}'`);
      console.log(`   Username: '${username || 'NOT SET'}'`);
      console.log(`   Token: ${token ? '[NEW_TOKEN_' + token.length + '_CHARS]' : 'NOT_PROVIDED'}`);
      console.log(`   Branch: '${branch || 'main'}'`);
      
      // Validierung der Eingaben
      if (enabled) {
        if (!repository) {
          return res.status(400).json({ 
            error: "Repository URL ist erforderlich wenn Git Backup aktiviert ist" 
          });
        }
        
        if (!username) {
          return res.status(400).json({ 
            error: "Username ist erforderlich wenn Git Backup aktiviert ist" 
          });
        }
        
        // Token-Validierung: Entweder neues Token oder bestehendes Token muss vorhanden sein
        const finalToken = token || this.config.gitBackup?.token || "";
        if (!finalToken) {
          return res.status(400).json({ 
            error: "Personal Access Token ist erforderlich wenn Git Backup aktiviert ist" 
          });
        }
        
        // Repository URL Format validieren
        try {
          new URL(repository);
        } catch (urlError) {
          return res.status(400).json({ 
            error: "Repository URL hat ungültiges Format. Verwende HTTPS URLs wie: https://github.com/username/repo.git" 
          });
        }
        
        console.log(`✅ [CONFIG API] Validierung erfolgreich, Final Token: ${finalToken ? '[SET_' + finalToken.length + '_CHARS]' : 'EMPTY'}`);
      }
      
      // Konfiguration aktualisieren - WICHTIG: Token korrekt übernehmen
      const previousConfig = this.config.gitBackup || {};
      
      this.config.gitBackup = {
        enabled: enabled === true,
        repository: repository || "",
        username: username || "",
        token: token || previousConfig.token || "", // HIER IST DER FIX!
        branch: branch || "main"
      };
      
      console.log("💾 [CONFIG API] Neue Konfiguration erstellt:");
      console.log(`   Enabled: ${this.config.gitBackup.enabled}`);
      console.log(`   Repository: ${this.config.gitBackup.repository}`);
      console.log(`   Username: ${this.config.gitBackup.username}`);
      console.log(`   Token: ${this.config.gitBackup.token ? '[FINAL_TOKEN_' + this.config.gitBackup.token.length + '_CHARS]' : 'EMPTY'}`);
      console.log(`   Branch: ${this.config.gitBackup.branch}`);
      
      // config.json aktualisieren (ohne Token für Sicherheit)
      const configToSave = { ...this.config };
      if (configToSave.gitBackup) {
        delete configToSave.gitBackup.token; // Token nicht in Datei speichern
      }
      
      fs.writeFileSync("config.json", JSON.stringify(configToSave, null, 2));
      console.log("✅ [CONFIG API] Konfiguration in config.json gespeichert (ohne Token)");
      
      // Git Backup neu initialisieren falls aktiviert
      if (enabled) {
        console.log("🔄 [CONFIG API] Initialisiere Git Backup mit neuer Konfiguration...");
        
        // Debug: Zeige finale Konfiguration vor Initialisierung
        console.log("🔍 [CONFIG API] Konfiguration vor Git Initialisierung:");
        console.log(`   this.config.gitBackup.token: ${this.config.gitBackup.token ? '[AVAILABLE_' + this.config.gitBackup.token.length + '_CHARS]' : 'MISSING'}`);
        
        await this.initializeGitBackup();
      }
      
      res.json({ 
        message: "Git Backup Konfiguration erfolgreich gespeichert und angewendet",
        applied: true,
        gitBackupStatus: enabled ? "aktiviert" : "deaktiviert",
        debug: {
          tokenReceived: !!token,
          tokenLength: token ? token.length : 0,
          finalTokenSet: !!this.config.gitBackup.token,
          finalTokenLength: this.config.gitBackup.token ? this.config.gitBackup.token.length : 0
        }
      });
      
    } catch (error) {
      console.error("❌ [CONFIG API] Fehler beim Speichern der Git Backup Konfiguration:", error);
      res.status(500).json({ 
        error: "Fehler beim Speichern der Konfiguration: " + error.message,
        details: error.stack
      });
    }
  }

  // Auto-Update Funktion
  async checkForUpdates() {
    return new Promise((resolve) => {
      // Prüfe ob wir in einem Git Repository sind
      if (!fs.existsSync(".git")) {
        console.log("❌ Kein Git Repository gefunden, Update übersprungen");
        resolve();
        return;
      }

      console.log("🔍 Prüfe auf Updates vom offiziellen Repository...");
      console.log(`📦 Repository: ${this.updateRepository}`);
      console.log(`🔗 Branch: ${this.updateBranch}`);

      // Führe das Update-Script aus
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

  setupMiddleware() {
    // Middleware für HTTP-erzwingung
    this.app.use((req, res, next) => {
      // HTTPS-Redirects verhindern
      res.setHeader("Strict-Transport-Security", "max-age=0");
      res.removeHeader("Cross-Origin-Opener-Policy");
      res.removeHeader("Cross-Origin-Embedder-Policy");
      next();
    });

    // Sicherheits-Middleware ohne strikte CSP
    this.app.use(
      helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: false,
        hsts: false,
      })
    );
    this.app.use(compression());
    this.app.use(
      cors({
        origin: true,
        credentials: true,
      })
    );

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 Minuten
      max: 100,
      message: "Zu viele Anfragen von dieser IP",
    });
    this.app.use("/api/", limiter);

    // Body parsing
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    // Session management
    this.app.use(
      session({
        secret: this.config.security.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
          secure: false,
          maxAge: 24 * 60 * 60 * 1000,
          sameSite: "lax",
        },
      })
    );

    // Statische Dateien aus public-Ordner
    this.app.use(express.static("public"));
  }

  async setupDefaultUser() {
    const hashedPassword = await bcrypt.hash(
      this.config.security.defaultAdmin.password,
      10
    );
    this.users.set(this.config.security.defaultAdmin.username, {
      username: this.config.security.defaultAdmin.username,
      password: hashedPassword,
      role: "admin",
    });
  }

  ensureDirectories() {
    const dirs = ["backups", "logs", "config", "public"];
    dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  // Zeitpläne in Datei speichern
  saveSchedulesToFile() {
    try {
      const schedules = Array.from(this.backupJobs.values()).map((job) => ({
        id: job.id,
        name: job.name,
        cronExpression: job.cronExpression,
        dbConfig: job.dbConfig,
        created: job.created,
      }));

      fs.writeFileSync(this.schedulesFile, JSON.stringify(schedules, null, 2));
      console.log("✅ Zeitpläne in Datei gespeichert:", this.schedulesFile);
    } catch (error) {
      console.error("❌ Fehler beim Speichern der Zeitpläne:", error);
    }
  }

  // Zeitpläne aus Datei laden
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
        console.log(
          "📋 Keine gespeicherten Zeitpläne gefunden - starte mit leerer Liste"
        );
      }
    } catch (error) {
      console.error("❌ Fehler beim Laden der Zeitpläne:", error);
    }
  }

  // Zeitplan-Job aus gespeicherten Daten wiederherstellen
  recreateScheduleJob(scheduleData) {
    try {
      const job = cron.schedule(
        scheduleData.cronExpression,
        async () => {
          console.log(`🔄 Führe geplantes Backup aus: ${scheduleData.name}`);
          try {
            await this.executeScheduledBackup(scheduleData.dbConfig);
            console.log(
              `✅ Geplantes Backup erfolgreich: ${scheduleData.name}`
            );
          } catch (err) {
            console.error(
              `❌ Geplantes Backup fehlgeschlagen: ${scheduleData.name}`,
              err
            );
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
      });

      job.start();
      console.log(
        `🕐 Zeitplan aktiviert: ${scheduleData.name} (${scheduleData.cronExpression})`
      );
    } catch (error) {
      console.error(
        `❌ Fehler beim Wiederherstellen des Zeitplans: ${scheduleData.name}`,
        error
      );
    }
  }
  
  // Enhanced Backup für geplante Aufgaben ausführen mit Git Push
  async executeScheduledBackup(dbConfig) {
    const safeDatabaseName = (dbConfig.database || "unknown_db").replace(
      /[^a-zA-Z0-9_-]/g,
      "_"
    );
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `scheduled_${safeDatabaseName}_${timestamp}.sql`;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

    console.log(`📅 [SCHEDULED] Starte geplantes Backup: ${filename}`);

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
          const pgCommand = `PGPASSWORD=${dbConfig.password} pg_dump -h ${
            dbConfig.host
          } -p ${dbConfig.port || 5432} -U ${dbConfig.username} -d ${
            dbConfig.database
          } > ${backupPath}`;
          await this.execPromiseWithDebug(pgCommand, "Scheduled PostgreSQL Backup");
          break;

        case "mongodb":
          const mongoBackupDir = path.join(
            this.config.backup.defaultPath,
            `scheduled_${safeDatabaseName}_${timestamp}`
          );
          const mongoCommand = `mongodump --host ${dbConfig.host}:${
            dbConfig.port || 27017
          } --db ${dbConfig.database} --username ${
            dbConfig.username
          } --password ${dbConfig.password} --out ${mongoBackupDir}`;
          await this.execPromiseWithDebug(mongoCommand, "Scheduled MongoDB Backup");
          
          // MongoDB Backups sind Verzeichnisse, können nicht direkt zu Git gepusht werden
          console.log("📁 [SCHEDULED] MongoDB Backup als Verzeichnis erstellt - Git Push nicht verfügbar");
          this.cleanupOldBackups();
          return;
      }

      let finalBackupPath = backupPath;

      // Komprimierung wenn aktiviert
      if (this.config.backup.compression && dbConfig.type !== "mongodb") {
        console.log("🗜️ [SCHEDULED] Komprimiere Backup...");
        await this.execPromiseWithDebug(`gzip ${backupPath}`, "Scheduled Backup Compression");
        finalBackupPath = `${backupPath}.gz`;
      }

      console.log(`✅ [SCHEDULED] Backup erstellt: ${path.basename(finalBackupPath)}`);

      // Git Push ausführen (nur für Dateien, nicht für MongoDB Verzeichnisse)
      if (dbConfig.type !== "mongodb" && fs.existsSync(finalBackupPath)) {
        try {
          console.log("📤 [SCHEDULED] Starte Git Push...");
          const gitResult = await this.pushBackupToGit(finalBackupPath, path.basename(finalBackupPath));
          if (gitResult.success) {
            console.log(`✅ [SCHEDULED] Git Push erfolgreich (${gitResult.duration}ms)`);
          }
        } catch (gitError) {
          console.error(`⚠️ [SCHEDULED] Git Push für geplantes Backup fehlgeschlagen: ${gitError.message}`);
          // Geplante Backups sollten nicht fehlschlagen nur wegen Git Push Problemen
        }
      }

      // Alte Backups aufräumen
      this.cleanupOldBackups();
      
    } catch (error) {
      console.error(`❌ [SCHEDULED] Fehler beim geplanten Backup: ${error.message}`);
      throw error;
    }
  }

  // Hilfsmethode: exec als Promise (Legacy Unterstützung)
  execPromise(command, timeout = 5000) {
    return new Promise((resolve, reject) => {
      const execTimeout = setTimeout(() => {
        reject(new Error(`Command timeout after ${timeout}ms: ${command}`));
      }, timeout);
      
      exec(command, (error, stdout, stderr) => {
        clearTimeout(execTimeout);
        if (error) {
          reject(new Error(`Command failed: ${command}\nError: ${error.message}\nStderr: ${stderr}`));
        } else {
          resolve(stdout);
        }
      });
    });
  }

  cleanupOldBackups() {
    try {
      const backupDir = this.config.backup.defaultPath;
      const files = fs
        .readdirSync(backupDir)
        .filter(
          (file) =>
            (file.endsWith(".sql") ||
            file.endsWith(".sql.gz") ||
            (!file.includes(".") &&
              fs.statSync(path.join(backupDir, file)).isDirectory())) &&
            file !== "git-backup" // Git-Backup Verzeichnis ausschließen
        );

      if (files.length > this.config.backup.maxBackups) {
        const backups = files
          .map((file) => {
            const filePath = path.join(backupDir, file);
            const stats = fs.statSync(filePath);
            return { file, path: filePath, created: stats.birthtime };
          })
          .sort((a, b) => a.created - b.created);

        const filesToDelete = backups.slice(
          0,
          files.length - this.config.backup.maxBackups
        );

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
  setupRoutes() {
    // Auth Middleware
    const authMiddleware = (req, res, next) => {
      const token =
        req.headers.authorization?.split(" ")[1] || req.session.token;

      if (!token) {
        return res.status(401).json({ error: "Kein Token bereitgestellt" });
      }

      try {
        const decoded = jwt.verify(token, this.config.security.jwtSecret);
        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).json({ error: "Ungültiger Token" });
      }
    };

    // Login Route
    this.app.post("/api/login", async (req, res) => {
      const { username, password } = req.body;

      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Benutzername und Passwort erforderlich" });
      }

      const user = this.users.get(username);
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Ungültige Anmeldedaten" });
      }

      const token = jwt.sign(
        { username: user.username, role: user.role },
        this.config.security.jwtSecret,
        { expiresIn: "24h" }
      );

      req.session.token = token;
      res.json({ token, username: user.username, role: user.role });
    });

    // Logout Route
    this.app.post("/api/logout", (req, res) => {
      req.session.destroy();
      res.json({ message: "Erfolgreich abgemeldet" });
    });

    // Update Route für manuelles Update
    this.app.post("/api/update", authMiddleware, async (req, res) => {
      try {
        console.log("🔄 Manuelles Update gestartet...");
        await this.checkForUpdates();
        res.json({ message: "Update erfolgreich durchgeführt" });
      } catch (error) {
        console.error("Update-Fehler:", error);
        res
          .status(500)
          .json({ error: "Update fehlgeschlagen: " + error.message });
      }
    });

    // Enhanced Git Backup Konfiguration Routes
    this.app.get("/api/git-backup/config", authMiddleware, (req, res) => {
      const config = {
        enabled: this.config.gitBackup?.enabled || false,
        repository: this.config.gitBackup?.repository || "",
        username: this.config.gitBackup?.username || "",
        hasToken: !!(this.config.gitBackup?.token),
        branch: this.config.gitBackup?.branch || "main"
      };
      res.json(config);
    });

    // Enhanced Git Backup Config Route (verwendet die neue updateGitBackupConfig Methode)
    this.app.post("/api/git-backup/config", authMiddleware, async (req, res) => {
      await this.updateGitBackupConfig(req, res);
    });

    // Enhanced Git Backup Test Route
    this.app.post("/api/git-backup/test", authMiddleware, async (req, res) => {
      try {
        console.log("🧪 [API] Git Backup Test angefordert");
        
        const result = await this.testGitBackupConnection();
        
        res.json({ 
          message: "✅ Git Backup Test erfolgreich! Repository ist erreichbar und beschreibbar.",
          details: result
        });
      } catch (error) {
        console.error("❌ [API] Git Backup Test fehlgeschlagen:", error);
        res.status(500).json({ 
          error: `Git Backup Test fehlgeschlagen: ${error.message}`,
          troubleshooting: this.generateGitTroubleshootingInfo()
        });
      }
    });

    // Git Configuration Debug Route
    this.app.get("/api/git-backup/debug-config", authMiddleware, (req, res) => {
      console.log("🔍 [DEBUG API] Git Konfiguration Debug angefordert");
      
      const debugInfo = {
        timestamp: new Date().toISOString(),
        configFile: {},
        environment: {},
        runtime: {},
        validation: {}
      };
      
      // Config File Werte
      debugInfo.configFile = {
        enabled: this.config.gitBackup?.enabled || false,
        repository: this.config.gitBackup?.repository || 'NOT SET',
        username: this.config.gitBackup?.username || 'NOT SET',
        hasToken: !!(this.config.gitBackup?.token),
        tokenLength: this.config.gitBackup?.token ? this.config.gitBackup.token.length : 0,
        branch: this.config.gitBackup?.branch || 'NOT SET'
      };
      
      // Environment Variables
      debugInfo.environment = {
        GIT_BACKUP_ENABLED: process.env.GIT_BACKUP_ENABLED || 'NOT SET',
        GIT_BACKUP_REPOSITORY: process.env.GIT_BACKUP_REPOSITORY || 'NOT SET',
        GIT_BACKUP_USERNAME: process.env.GIT_BACKUP_USERNAME || 'NOT SET',
        hasGIT_BACKUP_TOKEN: !!(process.env.GIT_BACKUP_TOKEN),
        GIT_BACKUP_TOKEN_LENGTH: process.env.GIT_BACKUP_TOKEN ? process.env.GIT_BACKUP_TOKEN.length : 0,
        GIT_BACKUP_BRANCH: process.env.GIT_BACKUP_BRANCH || 'NOT SET'
      };
      
      // Runtime Status
      debugInfo.runtime = {
        gitBackupPath: this.gitBackupPath,
        gitBackupPathExists: fs.existsSync(this.gitBackupPath),
        gitRepoExists: fs.existsSync(path.join(this.gitBackupPath, '.git')),
        configJsonExists: fs.existsSync('config.json'),
        nodeVersion: process.version,
        platform: process.platform
      };
      
      // Validation
      const validation = [];
      if (!debugInfo.configFile.enabled) {
        validation.push({ level: 'INFO', message: 'Git Backup ist deaktiviert' });
      } else {
        if (!debugInfo.configFile.repository || debugInfo.configFile.repository === 'NOT SET') {
          validation.push({ level: 'ERROR', message: 'Repository URL ist nicht gesetzt' });
        } else {
          try {
            new URL(debugInfo.configFile.repository);
            validation.push({ level: 'OK', message: 'Repository URL Format ist gültig' });
          } catch (e) {
            validation.push({ level: 'ERROR', message: 'Repository URL Format ist ungültig' });
          }
        }
        
        if (!debugInfo.configFile.username || debugInfo.configFile.username === 'NOT SET') {
          validation.push({ level: 'ERROR', message: 'Username ist nicht gesetzt' });
        } else {
          validation.push({ level: 'OK', message: 'Username ist gesetzt' });
        }
        
        if (!debugInfo.configFile.hasToken) {
          validation.push({ level: 'ERROR', message: 'Personal Access Token ist nicht gesetzt' });
        } else {
          validation.push({ level: 'OK', message: `Personal Access Token ist gesetzt (${debugInfo.configFile.tokenLength} Zeichen)` });
        }
        
        if (!debugInfo.runtime.gitBackupPathExists) {
          validation.push({ level: 'WARNING', message: 'Git Backup Verzeichnis existiert nicht' });
        } else if (!debugInfo.runtime.gitRepoExists) {
          validation.push({ level: 'WARNING', message: 'Git Repository ist nicht initialisiert' });
        } else {
          validation.push({ level: 'OK', message: 'Git Repository ist initialisiert' });
        }
      }
      
      debugInfo.validation = validation;
      
      res.json(debugInfo);
    });

    // Git Remote URL Test Route (ohne echten Push)
    this.app.post("/api/git-backup/test-url", authMiddleware, async (req, res) => {
      try {
        console.log("🧪 [URL TEST] Git Remote URL Test angefordert");
        
        if (!this.config.gitBackup?.enabled) {
          return res.status(400).json({ error: "Git Backup ist nicht aktiviert" });
        }
        
        // Debug Konfiguration ausgeben
        this.debugGitConfiguration();
        
        // URL erstellen und validieren
        const remoteUrl = this.buildGitRemoteUrl();
        
        if (!remoteUrl) {
          return res.status(400).json({ 
            error: "Konnte authentifizierte Git Remote URL nicht erstellen",
            troubleshooting: this.generateGitTroubleshootingInfo()
          });
        }
        
        // Git Repository initialisieren falls nötig
        if (!fs.existsSync(this.gitBackupPath)) {
          fs.mkdirSync(this.gitBackupPath, { recursive: true });
        }
        
        if (!fs.existsSync(path.join(this.gitBackupPath, ".git"))) {
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git init`, "Init for URL Test");
        }
        
        // Remote URL setzen
        try {
          await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote remove origin`, "Remove existing remote", false, 5000);
        } catch (e) {
          // Ignoriere Fehler wenn kein Remote existiert
        }
        
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git remote add origin "${remoteUrl}"`, "Add test remote", true);
        
        // Repository-Zugriff testen (ohne Push)
        await this.execPromiseWithDebug(`cd "${this.gitBackupPath}" && git ls-remote origin`, "Test remote access", true, 30000);
        
        res.json({ 
          message: "✅ Git Remote URL Test erfolgreich! Repository ist erreichbar.",
          status: "accessible",
          notes: [
            "Repository-Zugriff funktioniert",
            "Authentifizierung ist korrekt",
            "Bereit für echte Push-Operationen"
          ]
        });
        
      } catch (error) {
        console.error("❌ [URL TEST] Git Remote URL Test fehlgeschlagen:", error);
        
        let errorCategory = "unknown";
        let suggestions = [];
        
        if (error.message.includes("Authentication failed") || error.message.includes("Username for")) {
          errorCategory = "authentication";
          suggestions = [
            "Prüfe ob der Personal Access Token korrekt ist",
            "Stelle sicher, dass der Token 'repo' Berechtigung hat",
            "Überprüfe ob der Username korrekt ist"
          ];
        } else if (error.message.includes("Repository not found") || error.message.includes("not found")) {
          errorCategory = "repository";
          suggestions = [
            "Stelle sicher, dass das Repository existiert",
            "Prüfe ob die Repository URL korrekt ist",
            "Überprüfe die Repository-Berechtigungen"
          ];
        } else if (error.message.includes("timeout")) {
          errorCategory = "network";
          suggestions = [
            "Prüfe die Internetverbindung",
            "Git Server könnte langsam oder überlastet sein",
            "Versuche es später erneut"
          ];
        }
        
        res.status(500).json({ 
          error: `Git Remote URL Test fehlgeschlagen: ${error.message}`,
          category: errorCategory,
          suggestions: suggestions,
          troubleshooting: this.generateGitTroubleshootingInfo()
        });
      }
    });

    // Git Configuration Reload Route
    this.app.post("/api/git-backup/reload-config", authMiddleware, async (req, res) => {
      try {
        console.log("🔄 [RELOAD] Git Backup Konfiguration wird neu geladen...");
        
        // Konfiguration neu laden
        const originalConfig = this.config.gitBackup;
        this.config = this.loadConfig();
        
        console.log("📊 [RELOAD] Konfiguration Vergleich:");
        console.log(`   Vorher - Enabled: ${originalConfig?.enabled || false}`);
        console.log(`   Nachher - Enabled: ${this.config.gitBackup?.enabled || false}`);
        
        // Git Backup neu initialisieren wenn aktiviert
        if (this.config.gitBackup?.enabled) {
          await this.initializeGitBackup();
        }
        
        res.json({ 
          message: "Git Backup Konfiguration erfolgreich neu geladen",
          reloaded: true,
          status: {
            before: originalConfig,
            after: this.config.gitBackup
          }
        });
        
      } catch (error) {
        console.error("❌ [RELOAD] Fehler beim Neu-Laden der Git Konfiguration:", error);
        res.status(500).json({ 
          error: "Fehler beim Neu-Laden: " + error.message 
        });
      }
    });

    // Git Backup Debug Info Route
    this.app.get("/api/git-backup/debug", authMiddleware, (req, res) => {
      const debugInfo = this.generateGitDebugInfo();
      res.json(debugInfo);
    });

    // Enhanced System Info Route mit Git Backup Info
    this.app.get("/api/system", authMiddleware, (req, res) => {
      const packageInfo = JSON.parse(fs.readFileSync("package.json", "utf8"));

      // Git Info abrufen
      exec("git rev-parse HEAD", (error, stdout) => {
        const gitCommit = error ? "Unknown" : stdout.trim().substring(0, 7);

        exec("git log -1 --format=%ci", (error, stdout) => {
          const gitDate = error ? "Unknown" : stdout.trim();

          res.json({
            version: packageInfo.version,
            name: packageInfo.name,
            git: {
              commit: gitCommit,
              date: gitDate,
            },
            autoUpdate: this.config.updates?.autoUpdate || false,
            repository: this.updateRepository, // Fest integriert
            branch: this.updateBranch, // Fest integriert
            nodeVersion: process.version,
            uptime: process.uptime(),
            gitBackup: {
              enabled: this.config.gitBackup?.enabled || false,
              repository: this.config.gitBackup?.repository || "",
              hasCredentials: !!(this.config.gitBackup?.username && this.config.gitBackup?.token)
            }
          });
        });
      });
    });

    // Enhanced Backup Creation Route mit Git Push Debugging
    this.app.post("/api/backup", authMiddleware, async (req, res) => {
      const {
        type,
        host,
        port,
        database,
        username,
        password,
        options = {},
      } = req.body;

      console.log(`📤 [API] Backup angefordert für ${type} Database: ${database}`);

      if (!type || !host || !database || !username || !password) {
        return res.status(400).json({
          error: "Alle Datenbankverbindungsparameter sind erforderlich",
        });
      }

      const safeDatabaseName = (database || "unknown_db").replace(
        /[^a-zA-Z0-9_-]/g,
        "_"
      );
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = safeDatabaseName + "_" + timestamp + ".sql";
      const backupPath = path.join(this.config.backup.defaultPath, filename);

      try {
        console.log(`💾 [BACKUP] Erstelle ${type} Backup: ${filename}`);
        
        switch (type) {
          case "mysql":
            await mysqldump({
              connection: {
                host: host,
                port: parseInt(port) || 3306,
                user: username,
                password: password,
                database: database,
              },
              dumpToFile: backupPath,
            });

            let finalPath = backupPath;

            // Komprimierung wenn aktiviert
            if (this.config.backup.compression) {
              console.log("🗜️ [BACKUP] Komprimiere Backup...");
              const compressedPath = backupPath + ".gz";
              await this.execPromiseWithDebug(`gzip ${backupPath}`, "Backup Compression");
              finalPath = compressedPath;
            }

            console.log(`✅ [BACKUP] Backup erstellt: ${path.basename(finalPath)}`);

            // Git Push versuchen mit detailliertem Logging
            let gitPushResult = { success: false, reason: "not_attempted" };
            if (this.config.gitBackup?.enabled) {
              try {
                console.log("📤 [BACKUP] Starte Git Push...");
                gitPushResult = await this.pushBackupToGit(finalPath, path.basename(finalPath));
                console.log(`✅ [BACKUP] Git Push Result:`, gitPushResult);
              } catch (gitError) {
                console.error("❌ [BACKUP] Git Push fehlgeschlagen:", gitError);
                gitPushResult = { 
                  success: false, 
                  error: gitError.message,
                  troubleshooting: this.generateGitTroubleshootingInfo()
                };
              }
            }

            // Alte Backups aufräumen
            this.cleanupOldBackups();

            // Response mit detaillierter Git Info
            const response = {
              message: "Backup erfolgreich erstellt",
              filename: path.basename(finalPath),
              path: finalPath,
              gitPushed: gitPushResult.success
            };

            if (gitPushResult.success) {
              response.message += " und zu Git gepusht";
              response.gitDuration = gitPushResult.duration;
            } else if (this.config.gitBackup?.enabled) {
              response.message += " (Git Push fehlgeschlagen)";
              response.gitError = gitPushResult.error;
              response.gitTroubleshooting = gitPushResult.troubleshooting;
            }

            return res.json(response);

          case "postgresql":
            const pgCommand =
              "PGPASSWORD=" +
              password +
              " pg_dump -h " +
              host +
              " -p " +
              (port || 5432) +
              " -U " +
              username +
              " -d " +
              database +
              " > " +
              backupPath;

            exec(pgCommand, async (error, stdout, stderr) => {
              if (error) {
                console.error("❌ [BACKUP] PostgreSQL Backup Fehler:", error);
                console.error("stderr:", stderr);
                return res.status(500).json({ 
                  error: "Backup fehlgeschlagen: " + error.message 
                });
              }

              let finalPath = backupPath;

              if (this.config.backup.compression) {
                try {
                  await this.execPromiseWithDebug(`gzip ${backupPath}`, "PostgreSQL Backup Compression");
                  finalPath = backupPath + ".gz";
                } catch (compressError) {
                  console.error("❌ [BACKUP] Komprimierung fehlgeschlagen:", compressError);
                }
              }

              // Git Push für PostgreSQL
              let gitPushResult = { success: false, reason: "not_attempted" };
              if (this.config.gitBackup?.enabled) {
                try {
                  gitPushResult = await this.pushBackupToGit(finalPath, path.basename(finalPath));
                } catch (gitError) {
                  console.error("❌ [BACKUP] PostgreSQL Git Push fehlgeschlagen:", gitError);
                  gitPushResult = { 
                    success: false, 
                    error: gitError.message,
                    troubleshooting: this.generateGitTroubleshootingInfo()
                  };
                }
              }

              this.cleanupOldBackups();

              const response = {
                message: "Backup erfolgreich erstellt",
                filename: path.basename(finalPath),
                path: finalPath,
                gitPushed: gitPushResult.success
              };

              if (gitPushResult.success) {
                response.message += " und zu Git gepusht";
              } else if (this.config.gitBackup?.enabled) {
                response.message += " (Git Push fehlgeschlagen)";
                response.gitError = gitPushResult.error;
                response.gitTroubleshooting = gitPushResult.troubleshooting;
              }

              res.json(response);
            });
            break;

          case "mongodb":
            const mongoBackupDir = path.join(
              this.config.backup.defaultPath,
              database + "_" + timestamp
            );
            const mongoCommand =
              "mongodump --host " +
              host +
              ":" +
              (port || 27017) +
              " --db " +
              database +
              " --username " +
              username +
              " --password " +
              password +
              " --out " +
              mongoBackupDir;

            exec(mongoCommand, (error, stdout, stderr) => {
              if (error) {
                console.error("❌ [BACKUP] MongoDB Backup Fehler:", error);
                console.error("stderr:", stderr);
                return res.status(500).json({ 
                  error: "Backup fehlgeschlagen: " + error.message 
                });
              }

              // MongoDB Backups sind Verzeichnisse - Git Push momentan nicht unterstützt
              this.cleanupOldBackups();

              res.json({
                message: "Backup erfolgreich erstellt (MongoDB Verzeichnis - Git Push nicht verfügbar)",
                filename: path.basename(mongoBackupDir),
                path: mongoBackupDir,
                gitPushed: false,
                note: "MongoDB Backups werden als Verzeichnisse gespeichert und können derzeit nicht automatisch zu Git gepusht werden."
              });
            });
            break;

          default:
            return res.status(400).json({ 
              error: "Nicht unterstützter Datenbanktyp" 
            });
        }
      } catch (error) {
        console.error("❌ [BACKUP] Fehler beim Erstellen des Backups:", error);
        res.status(500).json({ 
          error: "Fehler beim Erstellen des Backups: " + error.message 
        });
      }
    });

    // Geschützte Routen (unverändert)
    this.app.get("/api/backups", authMiddleware, (req, res) => {
      this.getBackups(req, res);
    });

    this.app.delete("/api/backup/:filename", authMiddleware, (req, res) => {
      this.deleteBackup(req, res);
    });

    this.app.get(
      "/api/backup/:filename/download",
      authMiddleware,
      (req, res) => {
        this.downloadBackup(req, res);
      }
    );

    this.app.post("/api/schedule", authMiddleware, (req, res) => {
      this.scheduleBackup(req, res);
    });

    this.app.get("/api/schedules", authMiddleware, (req, res) => {
      this.getSchedules(req, res);
    });

    this.app.delete("/api/schedule/:id", authMiddleware, (req, res) => {
      this.deleteSchedule(req, res);
    });

    // Hauptseite - Leitet zur index.html weiter
    this.app.get("/", (req, res) => {
      res.sendFile(path.join(__dirname, "public", "index.html"));
    });

    // 404 Handler
    this.app.use((req, res) => {
      res.status(404).json({ error: "Endpunkt nicht gefunden" });
    });
  }
  async getBackups(req, res) {
    try {
      const backupDir = this.config.backup.defaultPath;
      const files = fs
        .readdirSync(backupDir)
        .filter(
          (file) =>
            file.endsWith(".sql") ||
            file.endsWith(".sql.gz") ||
            (!file.includes(".") &&
              fs.statSync(path.join(backupDir, file)).isDirectory() &&
              file !== "git-backup") // Git-Backup Verzeichnis ausschließen
        );

      const backups = files
        .map((file) => {
          const filePath = path.join(backupDir, file);
          const stats = fs.statSync(filePath);
          return {
            filename: file,
            size: stats.size,
            created: stats.birthtime,
            modified: stats.mtime,
            type: stats.isDirectory() ? "directory" : "file",
          };
        })
        .sort((a, b) => b.created - a.created);

      console.log(`📋 [API] Backup-Liste geladen: ${backups.length} Dateien`);
      res.json(backups);
    } catch (error) {
      console.error("❌ [API] Fehler beim Laden der Backups:", error);
      res
        .status(500)
        .json({ error: "Fehler beim Laden der Backups: " + error.message });
    }
  }

  async deleteBackup(req, res) {
    const { filename } = req.params;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

    console.log(`🗑️ [API] Backup-Löschung angefordert: ${filename}`);

    try {
      if (fs.existsSync(backupPath)) {
        const stats = fs.statSync(backupPath);
        if (stats.isDirectory()) {
          fs.rmSync(backupPath, { recursive: true, force: true });
          console.log(`✅ [API] Verzeichnis gelöscht: ${filename}`);
        } else {
          fs.unlinkSync(backupPath);
          console.log(`✅ [API] Datei gelöscht: ${filename}`);
        }
        res.json({ message: "Backup erfolgreich gelöscht" });
      } else {
        console.log(`❌ [API] Backup nicht gefunden: ${filename}`);
        res.status(404).json({ error: "Backup nicht gefunden" });
      }
    } catch (error) {
      console.error(`❌ [API] Fehler beim Löschen des Backups ${filename}:`, error);
      res
        .status(500)
        .json({ error: "Fehler beim Löschen des Backups: " + error.message });
    }
  }

  async downloadBackup(req, res) {
    const { filename } = req.params;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

    console.log(`📥 [API] Backup-Download angefordert: ${filename}`);

    try {
      if (fs.existsSync(backupPath)) {
        const stats = fs.statSync(backupPath);
        if (stats.isDirectory()) {
          console.log(`❌ [API] Verzeichnis-Download nicht unterstützt: ${filename}`);
          return res
            .status(400)
            .json({
              error:
                "Download von Verzeichnissen nicht unterstützt. Bitte verwende die Kommandozeile.",
            });
        }
        console.log(`✅ [API] Backup-Download gestartet: ${filename}`);
        res.download(backupPath, filename);
      } else {
        console.log(`❌ [API] Backup für Download nicht gefunden: ${filename}`);
        res.status(404).json({ error: "Backup nicht gefunden" });
      }
    } catch (error) {
      console.error(`❌ [API] Fehler beim Download von ${filename}:`, error);
      res.status(500).json({ error: "Fehler beim Download: " + error.message });
    }
  }

  async scheduleBackup(req, res) {
    const { name, cronExpression, dbConfig } = req.body;

    console.log(`📅 [API] Zeitplan-Erstellung angefordert: ${name}`);
    console.log(`   Cron: ${cronExpression}`);
    console.log(`   Database: ${dbConfig.type} - ${dbConfig.database}`);

    if (!name || !cronExpression || !dbConfig || !dbConfig.database) {
      return res
        .status(400)
        .json({
          error:
            "Name, Cron-Expression und gültige Datenbank-Konfiguration erforderlich",
        });
    }

    try {
      const jobId = Date.now().toString();

      const job = cron.schedule(
        cronExpression,
        async () => {
          console.log(`🔄 Führe geplantes Backup aus: ${name}`);
          try {
            await this.executeScheduledBackup(dbConfig);
            console.log(`✅ Geplantes Backup erfolgreich: ${name}`);
          } catch (err) {
            console.error(`❌ Geplantes Backup fehlgeschlagen: ${name}`, err);
          }
        },
        { scheduled: false }
      );

      this.backupJobs.set(jobId, {
        id: jobId,
        name,
        cronExpression,
        dbConfig,
        job,
        created: new Date(),
      });

      job.start();

      // Zeitpläne in Datei speichern
      this.saveSchedulesToFile();

      console.log(`✅ [API] Zeitplan erstellt: ${name} (ID: ${jobId})`);

      res.json({
        message: "Backup-Zeitplan erfolgreich erstellt",
        jobId,
      });
    } catch (error) {
      console.error(`❌ [API] Fehler beim Erstellen des Zeitplans ${name}:`, error);
      res
        .status(500)
        .json({
          error: "Fehler beim Erstellen des Zeitplans: " + error.message,
        });
    }
  }

  async getSchedules(req, res) {
    try {
      const schedules = Array.from(this.backupJobs.values()).map((job) => ({
        id: job.id,
        name: job.name,
        cronExpression: job.cronExpression,
        dbConfig: { ...job.dbConfig, password: "***" }, // Passwort verstecken
        created: job.created,
      }));

      console.log(`📋 [API] Zeitplan-Liste geladen: ${schedules.length} Zeitpläne`);
      res.json(schedules);
    } catch (error) {
      console.error("❌ [API] Fehler beim Laden der Zeitpläne:", error);
      res.status(500).json({ error: "Fehler beim Laden der Zeitpläne: " + error.message });
    }
  }

  async deleteSchedule(req, res) {
    const { id } = req.params;

    console.log(`🗑️ [API] Zeitplan-Löschung angefordert: ${id}`);

    try {
      if (this.backupJobs.has(id)) {
        const job = this.backupJobs.get(id);
        const jobName = job.name;
        
        job.job.stop();
        job.job.destroy();
        this.backupJobs.delete(id);

        // Zeitpläne in Datei speichern
        this.saveSchedulesToFile();

        console.log(`✅ [API] Zeitplan gelöscht: ${jobName} (ID: ${id})`);
        res.json({ message: "Zeitplan erfolgreich gelöscht" });
      } else {
        console.log(`❌ [API] Zeitplan nicht gefunden: ${id}`);
        res.status(404).json({ error: "Zeitplan nicht gefunden" });
      }
    } catch (error) {
      console.error(`❌ [API] Fehler beim Löschen des Zeitplans ${id}:`, error);
      res.status(500).json({ error: "Fehler beim Löschen des Zeitplans: " + error.message });
    }
  }

  startServer() {
    const port = this.config.server.port;
    const host = this.config.server.host;

    this.app.listen(port, host, () => {
      console.log("");
      console.log("🚀 =====================================================");
      console.log("🚀 DATABASE BACKUP TOOL - ENHANCED VERSION GESTARTET!");
      console.log("🚀 =====================================================");
      console.log("📡 Server läuft auf " + host + ":" + port);
      console.log(
        "🔐 Standard Login: " +
          this.config.security.defaultAdmin.username +
          " / " +
          this.config.security.defaultAdmin.password
      );
      console.log("📁 Backup-Verzeichnis: " + this.config.backup.defaultPath);
      console.log("📋 Zeitplan-Datei: " + this.schedulesFile);
      console.log(
        "🔄 Auto-Update: " +
          (this.config.updates?.autoUpdate ? "✅ Aktiviert" : "❌ Deaktiviert")
      );
      console.log("📦 Offizielles Repository: " + this.updateRepository);
      console.log("🔗 Branch: " + this.updateBranch);
      console.log("");
      
      // Enhanced Git Backup Status mit detaillierter Diagnose
      console.log("📤 =================== GIT BACKUP STATUS ===================");
      if (this.config.gitBackup?.enabled) {
        console.log("📤 Git Backup: ✅ AKTIVIERT");
        console.log("📦 Git Repository: " + (this.config.gitBackup.repository || "❌ Nicht konfiguriert"));
        console.log("👤 Git Username: " + (this.config.gitBackup.username || "❌ Nicht gesetzt"));
        console.log("🔑 Git Token: " + (this.config.gitBackup.token ? "✅ Gesetzt (" + this.config.gitBackup.token.length + " Zeichen)" : "❌ Nicht gesetzt"));
        console.log("🌿 Git Branch: " + (this.config.gitBackup.branch || "main"));
        console.log("📁 Git Backup Pfad: " + this.gitBackupPath);
        
        // Git Repository Status prüfen
        if (fs.existsSync(this.gitBackupPath)) {
          if (fs.existsSync(path.join(this.gitBackupPath, ".git"))) {
            console.log("🔧 Git Repository Status: ✅ Initialisiert");
            
            // Prüfe Remote-Konfiguration
            try {
              const { execSync } = require('child_process');
              const remoteUrl = execSync(`cd "${this.gitBackupPath}" && git remote get-url origin`, { encoding: 'utf8' }).trim();
              const hasAuth = remoteUrl.includes('@');
              console.log("🔗 Git Remote Status: " + (hasAuth ? "✅ Mit Authentifizierung konfiguriert" : "⚠️ Ohne Authentifizierung"));
            } catch (remoteError) {
              console.log("🔗 Git Remote Status: ❌ Nicht konfiguriert");
            }
          } else {
            console.log("🔧 Git Repository Status: ⚠️ Verzeichnis existiert, aber nicht als Git Repository");
          }
        } else {
          console.log("🔧 Git Repository Status: ❌ Verzeichnis existiert nicht");
        }
        
        // Git Backup Konfiguration Validierung
        console.log("");
        console.log("🔍 GIT BACKUP VALIDIERUNG:");
        const issues = [];
        if (!this.config.gitBackup.repository) {
          issues.push("❌ Repository URL nicht gesetzt");
        } else {
          try {
            new URL(this.config.gitBackup.repository);
            console.log("✅ Repository URL Format ist gültig");
          } catch (e) {
            issues.push("❌ Repository URL Format ist ungültig");
          }
        }
        
        if (!this.config.gitBackup.username) {
          issues.push("❌ Git Username nicht gesetzt");
        } else {
          console.log("✅ Git Username ist gesetzt");
        }
        
        if (!this.config.gitBackup.token) {
          issues.push("❌ Personal Access Token nicht gesetzt");
        } else {
          console.log("✅ Personal Access Token ist gesetzt");
        }
        
        if (issues.length > 0) {
          console.log("");
          console.log("⚠️  GIT BACKUP KONFIGURATIONSPROBLEME:");
          issues.forEach(issue => console.log("   " + issue));
          console.log("🔧 Bitte konfiguriere Git Backup über das Web-Interface!");
          console.log("🧪 Verwende die neuen Debug-APIs für detaillierte Diagnose:");
          console.log("   GET /api/git-backup/debug-config");
          console.log("   POST /api/git-backup/test-url");
        } else {
          console.log("✅ Git Backup Konfiguration ist vollständig");
          console.log("💡 Verwende 'Verbindung testen' im Web-Interface zur Validierung");
        }
      } else {
        console.log("📤 Git Backup: ❌ DEAKTIVIERT");
        console.log("💡 Aktiviere Git Backup im Web-Interface für automatische Repository-Synchronisation");
      }
      console.log("============================================================");
      console.log("");
      
      // Enhanced Features Liste
      console.log("🎯 =================== ERWEITERTE FUNKTIONEN ===================");
      console.log("├── 🔍 Detailliertes Git Push Debugging (60s Timeout)");
      console.log("├── ⏱️ Non-Interactive Git (GIT_TERMINAL_PROMPT=0)");
      console.log("├── 🚫 Authentifizierte Git URLs mit Token-Embedding");
      console.log("├── 📊 Umfassende Fehlerdiagnose und Post-Error Analysis");
      console.log("├── 🔧 Git Backup Troubleshooting APIs");
      console.log("├── 📋 Enhanced Logging für alle Git-Operationen");
      console.log("├── 🧪 URL-Test ohne echten Push");
      console.log("├── 🔄 Live-Konfiguration Reload");
      console.log("└── 📤 Modulares Frontend mit Custom-Anpassungen");
      console.log("================================================================");
      console.log("");
      
      // Debug Endpoints Overview
      console.log("🔧 =================== DEBUG ENDPOINTS ===================");
      console.log("├── GET  /api/git-backup/debug-config   - Vollständige Git Konfiguration");
      console.log("├── POST /api/git-backup/test-url       - URL-Authentifizierung testen");
      console.log("├── POST /api/git-backup/test           - Vollständiger Git Verbindungstest");
      console.log("├── POST /api/git-backup/reload-config  - Konfiguration neu laden");
      console.log("├── GET  /api/git-backup/debug          - Basis Debug-Informationen");
      console.log("└── GET  /api/system                    - Erweiterte Systeminfos");
      console.log("===========================================================");
      console.log("");
      
      // Troubleshooting Guide
      console.log("🚨 =================== TROUBLESHOOTING ===================");
      console.log("Bei Git Push Problemen ('Username for https://github.com'):");
      console.log("1. 🔍 Prüfe Konfiguration: GET /api/git-backup/debug-config");
      console.log("2. 🧪 Teste URL: POST /api/git-backup/test-url");
      console.log("3. 🔧 Vervollständige Konfiguration im Git Backup Tab");
      console.log("4. 🔄 Teste Verbindung mit 'Verbindung testen' Button");
      console.log("5. 📋 Prüfe Server-Logs für detaillierte Fehleranalyse");
      console.log("");
      console.log("Häufige Ursachen:");
      console.log("├── ❌ Personal Access Token fehlt oder ist ungültig");
      console.log("├── ❌ Token hat nicht die 'repo' Berechtigung");
      console.log("├── ❌ Username stimmt nicht mit Git-Provider überein");
      console.log("├── ❌ Repository URL ist falsch oder Repository existiert nicht");
      console.log("└── ❌ Umgebungsvariablen überschreiben Web-Interface Werte");
      console.log("===========================================================");
      console.log("");
      
      console.log(
        "⚠️  WICHTIG: Ändere die Standard-Passwörter nach dem ersten Login!"
      );
      console.log("");
      console.log("🌐 Web-Interface: http://" + host + ":" + port);
      console.log("📖 Logs: Verfolge diese Konsole für detaillierte Informationen");
      console.log("");
      console.log("🎉 Ready for Database Backups mit Enhanced Git Integration! 🎉");
    });
  }
}

// Enhanced Graceful shutdown mit Git Status
process.on("SIGTERM", () => {
  console.log("");
  console.log("🛑 SIGTERM empfangen, beende Database Backup Tool...");
  console.log("📊 Prozess-Statistiken:");
  console.log(`   Uptime: ${Math.floor(process.uptime() / 60)} Minuten`);
  console.log(`   Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log("✅ Graceful Shutdown abgeschlossen");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("");
  console.log("🛑 SIGINT empfangen, beende Database Backup Tool...");
  console.log("📊 Prozess-Statistiken:");
  console.log(`   Uptime: ${Math.floor(process.uptime() / 60)} Minuten`);
  console.log(`   Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log("✅ Graceful Shutdown abgeschlossen");
  process.exit(0);
});

// Enhanced Error Handling mit Git Context
process.on('uncaughtException', (error) => {
  console.error("❌ UNCAUGHT EXCEPTION:");
  console.error(`   Error: ${error.message}`);
  console.error(`   Stack: ${error.stack}`);
  if (error.message.includes('git')) {
    console.error("   → Dies könnte ein Git-bezogenes Problem sein");
    console.error("   → Prüfe Git Backup Konfiguration und Logs");
  }
  console.log("🔄 Versuche graceful shutdown...");
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error("❌ UNHANDLED PROMISE REJECTION:");
  console.error(`   Reason: ${reason}`);
  console.error(`   Promise: ${promise}`);
  if (reason && reason.toString().includes('git')) {
    console.error("   → Dies könnte ein Git-bezogenes Problem sein");
    console.error("   → Verwende Debug-APIs für detaillierte Diagnose");
  }
  console.log("⚠️  Anwendung läuft weiter, aber dies sollte behoben werden!");
});

// Enhanced Startup Message
console.log("");
console.log("🚀 ===============================================");
console.log("🚀 INITIALISIERE DATABASE BACKUP TOOL");
console.log("🚀 ===============================================");
console.log("📦 Version: Enhanced mit Git Debug System");
console.log("🔧 Features: Git Backup + Advanced Debugging");
console.log("⏱️  Git Push Timeout: 60 Sekunden");
console.log("📋 Detailliertes Logging: Aktiviert");
console.log("🔍 Debug APIs: Verfügbar");
console.log("===============================================");
console.log("");

// Start the application
new DatabaseBackupTool();