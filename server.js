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
    this.loadSchedulesFromFile();
    this.startServer();
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

    // System Info Route
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
          });
        });
      });
    });

    // Geschützte Routen
    this.app.get("/api/backups", authMiddleware, (req, res) => {
      this.getBackups(req, res);
    });

    this.app.post("/api/backup", authMiddleware, (req, res) => {
      this.createBackup(req, res);
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
  
  // Backup für geplante Aufgaben ausführen
  async executeScheduledBackup(dbConfig) {
    const safeDatabaseName = (dbConfig.database || "unknown_db").replace(
      /[^a-zA-Z0-9_-]/g,
      "_"
    );
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `scheduled_${safeDatabaseName}_${timestamp}.sql`;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

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
        await this.execPromise(pgCommand);
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
        await this.execPromise(mongoCommand);
        break;
    }

    // Komprimierung wenn aktiviert
    if (this.config.backup.compression && dbConfig.type !== "mongodb") {
      await this.execPromise(`gzip ${backupPath}`);
    }

    // Alte Backups aufräumen
    this.cleanupOldBackups();
  }

  // Hilfsmethode: exec als Promise
  execPromise(command) {
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout);
        }
      });
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
              fs.statSync(path.join(backupDir, file)).isDirectory())
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

      res.json(backups);
    } catch (error) {
      res
        .status(500)
        .json({ error: "Fehler beim Laden der Backups: " + error.message });
    }
  }

  async createBackup(req, res) {
    const {
      type,
      host,
      port,
      database,
      username,
      password,
      options = {},
    } = req.body;

    if (!type || !host || !database || !username || !password) {
      return res
        .status(400)
        .json({
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

          // Komprimierung wenn aktiviert
          if (this.config.backup.compression) {
            const compressedPath = backupPath + ".gz";
            exec("/bin/gzip " + backupPath, (compressError) => {
              if (compressError) {
                console.error("Komprimierung fehlgeschlagen:", compressError);
              }
            });
          }

          // Alte Backups aufräumen
          this.cleanupOldBackups();

          return res.json({
            message: "Backup erfolgreich erstellt",
            filename: path.basename(backupPath),
            path: backupPath,
          });

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

          exec(pgCommand, (error, stdout, stderr) => {
            if (error) {
              console.error("Backup Fehler:", error);
              console.error("stderr:", stderr);
              return res
                .status(500)
                .json({ error: "Backup fehlgeschlagen: " + error.message });
            }

            if (this.config.backup.compression) {
              exec("/bin/gzip " + backupPath, (compressError) => {
                if (compressError) {
                  console.error("Komprimierung fehlgeschlagen:", compressError);
                }
              });
            }

            this.cleanupOldBackups();

            res.json({
              message: "Backup erfolgreich erstellt",
              filename: filename,
              path: backupPath,
            });
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
              console.error("Backup Fehler:", error);
              console.error("stderr:", stderr);
              return res
                .status(500)
                .json({ error: "Backup fehlgeschlagen: " + error.message });
            }

            // Kompression nicht erforderlich – MongoDB speichert als Verzeichnis
            this.cleanupOldBackups();

            res.json({
              message: "Backup erfolgreich erstellt",
              filename: path.basename(mongoBackupDir),
              path: mongoBackupDir,
            });
          });
          break;

        default:
          return res
            .status(400)
            .json({ error: "Nicht unterstützter Datenbanktyp" });
      }
    } catch (error) {
      console.error("Fehler beim Erstellen des Backups:", error);
      res
        .status(500)
        .json({ error: "Fehler beim Erstellen des Backups: " + error.message });
    }
  }

  async deleteBackup(req, res) {
    const { filename } = req.params;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

    try {
      if (fs.existsSync(backupPath)) {
        const stats = fs.statSync(backupPath);
        if (stats.isDirectory()) {
          fs.rmSync(backupPath, { recursive: true, force: true });
        } else {
          fs.unlinkSync(backupPath);
        }
        res.json({ message: "Backup erfolgreich gelöscht" });
      } else {
        res.status(404).json({ error: "Backup nicht gefunden" });
      }
    } catch (error) {
      res
        .status(500)
        .json({ error: "Fehler beim Löschen des Backups: " + error.message });
    }
  }

  async downloadBackup(req, res) {
    const { filename } = req.params;
    const backupPath = path.join(this.config.backup.defaultPath, filename);

    try {
      if (fs.existsSync(backupPath)) {
        const stats = fs.statSync(backupPath);
        if (stats.isDirectory()) {
          // Für Verzeichnisse (MongoDB) könnten wir sie als ZIP komprimieren
          return res
            .status(400)
            .json({
              error:
                "Download von Verzeichnissen nicht unterstützt. Bitte verwende die Kommandozeile.",
            });
        }
        res.download(backupPath, filename);
      } else {
        res.status(404).json({ error: "Backup nicht gefunden" });
      }
    } catch (error) {
      res.status(500).json({ error: "Fehler beim Download: " + error.message });
    }
  }

  async scheduleBackup(req, res) {
    const { name, cronExpression, dbConfig } = req.body;

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

      res.json({
        message: "Backup-Zeitplan erfolgreich erstellt",
        jobId,
      });
    } catch (error) {
      console.error("Fehler beim Erstellen des Zeitplans:", error);
      res
        .status(500)
        .json({
          error: "Fehler beim Erstellen des Zeitplans: " + error.message,
        });
    }
  }

  async getSchedules(req, res) {
    const schedules = Array.from(this.backupJobs.values()).map((job) => ({
      id: job.id,
      name: job.name,
      cronExpression: job.cronExpression,
      dbConfig: { ...job.dbConfig, password: "***" }, // Passwort verstecken
      created: job.created,
    }));

    res.json(schedules);
  }

  async deleteSchedule(req, res) {
    const { id } = req.params;

    if (this.backupJobs.has(id)) {
      const job = this.backupJobs.get(id);
      job.job.stop();
      job.job.destroy();
      this.backupJobs.delete(id);

      // Zeitpläne in Datei speichern
      this.saveSchedulesToFile();

      res.json({ message: "Zeitplan erfolgreich gelöscht" });
    } else {
      res.status(404).json({ error: "Zeitplan nicht gefunden" });
    }
  }

  cleanupOldBackups() {
    try {
      const backupDir = this.config.backup.defaultPath;
      const files = fs
        .readdirSync(backupDir)
        .filter(
          (file) =>
            file.endsWith(".sql") ||
            file.endsWith(".sql.gz") ||
            (!file.includes(".") &&
              fs.statSync(path.join(backupDir, file)).isDirectory())
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

        filesToDelete.forEach((backup) => {
          const stats = fs.statSync(backup.path);
          if (stats.isDirectory()) {
            fs.rmSync(backup.path, { recursive: true, force: true });
          } else {
            fs.unlinkSync(backup.path);
          }
          console.log("Altes Backup gelöscht: " + backup.file);
        });
      }
    } catch (error) {
      console.error("Fehler beim Aufräumen alter Backups:", error);
    }
  }

  startServer() {
    const port = this.config.server.port;
    const host = this.config.server.host;

    this.app.listen(port, host, () => {
      console.log("");
      console.log("🚀 Database Backup Tool gestartet!");
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
          (this.config.updates?.autoUpdate ? "Aktiviert" : "Deaktiviert")
      );
      console.log("📦 Offizielles Repository: " + this.updateRepository);
      console.log("🔗 Branch: " + this.updateBranch);
      console.log("");
      console.log(
        "⚠️  WICHTIG: Ändere die Standard-Passwörter nach dem ersten Login!"
      );
    });
  }
}

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM empfangen, beende Anwendung...");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("SIGINT empfangen, beende Anwendung...");
  process.exit(0);
});

// Start the application
new DatabaseBackupTool();