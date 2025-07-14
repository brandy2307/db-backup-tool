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

    // Statische Dateien
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

    // Hauptseite
    this.app.get("/", (req, res) => {
      res.send(this.getMainPage());
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
    const dirs = ["backups", "logs", "config"];
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
  getMainPage() {
    return `<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Backup Tool</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .login-form { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; margin: 50px auto; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #3498db; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background: #2980b9; }
        .main-content { display: none; }
        .tabs { display: flex; background: white; border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
        .tab { flex: 1; padding: 15px; background: #ecf0f1; border: none; cursor: pointer; }
        .tab.active { background: #3498db; color: white; }
        .tab-content { display: none; background: white; padding: 20px; border-radius: 8px; }
        .tab-content.active { display: block; }
        .backup-form { display: grid; gap: 15px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .backup-list { margin-top: 20px; }
        .backup-item { display: flex; justify-content: space-between; align-items: center; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 10px; }
        .error { color: red; margin-top: 10px; }
        .success { color: green; margin-top: 10px; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 10px; }
        .status-active { background: #27ae60; }
        .status-inactive { background: #e74c3c; }
        .schedule-info { font-size: 0.9em; color: #666; }
        .system-info { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .system-info h3 { margin-bottom: 10px; }
        .system-info p { margin: 5px 0; font-size: 0.9em; }
        .update-button { background: #27ae60; margin-left: 10px; }
        .update-button:hover { background: #219a52; }
        .repo-info { background: #e8f5e8; padding: 10px; border-radius: 4px; border-left: 4px solid #27ae60; margin-bottom: 15px; }
        .repo-info h4 { color: #27ae60; margin-bottom: 5px; }
        .repo-info p { font-size: 0.9em; color: #555; margin: 2px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Database Backup Tool</h1>
        <p>Automatisierte Datenbank-Backups für MySQL, PostgreSQL und MongoDB</p>
    </div>

    <div class="container">
        <div id="login-section">
            <div class="login-form">
                <h2>Anmeldung</h2>
                <form id="loginForm">
                    <div class="form-group">
                        <label for="username">Benutzername:</label>
                        <input type="text" id="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Passwort:</label>
                        <input type="password" id="password" required>
                    </div>
                    <button type="submit">Anmelden</button>
                </form>
                <div id="loginError" class="error"></div>
            </div>
        </div>

        <div id="main-content" class="main-content">
            <div class="tabs">
                <button class="tab active" onclick="showTab('backup')">Backup erstellen</button>
                <button class="tab" onclick="showTab('backups')">Backups verwalten</button>
                <button class="tab" onclick="showTab('schedule')">Zeitplan</button>
                <button class="tab" onclick="showTab('system')">System</button>
            </div>

            <div id="backup-content" class="tab-content active">
                <h2>Neues Backup erstellen</h2>
                <form id="backupForm" class="backup-form">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="dbType">Datenbanktyp:</label>
                            <select id="dbType" required>
                                <option value="">Wähle Typ...</option>
                                <option value="mysql">MySQL</option>
                                <option value="postgresql">PostgreSQL</option>
                                <option value="mongodb">MongoDB</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="dbHost">Host:</label>
                            <input type="text" id="dbHost" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="dbPort">Port:</label>
                            <input type="number" id="dbPort">
                        </div>
                        <div class="form-group">
                            <label for="dbName">Datenbankname:</label>
                            <input type="text" id="dbName" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="dbUsername">Benutzername:</label>
                            <input type="text" id="dbUsername" required>
                        </div>
                        <div class="form-group">
                            <label for="dbPassword">Passwort:</label>
                            <input type="password" id="dbPassword" required>
                        </div>
                    </div>
                    <button type="submit">Backup erstellen</button>
                </form>
                <div id="backupResult"></div>
            </div>

            <div id="backups-content" class="tab-content">
                <h2>Backup-Verwaltung</h2>
                <button onclick="loadBackups()">Aktualisieren</button>
                <div id="backupsList" class="backup-list"></div>
            </div>

            <div id="schedule-content" class="tab-content">
                <h2>Backup-Zeitpläne</h2>
                <form id="scheduleForm" class="backup-form">
                    <div class="form-group">
                        <label for="scheduleName">Name:</label>
                        <input type="text" id="scheduleName" required>
                    </div>
                    <div class="form-group">
                        <label for="cronExpression">Cron-Expression:</label>
                        <input type="text" id="cronExpression" placeholder="0 2 * * *" required>
                        <small>Beispiel: "0 2 * * *" = täglich um 2:00 Uhr</small>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="scheduleDbType">Datenbanktyp:</label>
                            <select id="scheduleDbType" required>
                                <option value="">Wähle Typ...</option>
                                <option value="mysql">MySQL</option>
                                <option value="postgresql">PostgreSQL</option>
                                <option value="mongodb">MongoDB</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="scheduleDbHost">Host:</label>
                            <input type="text" id="scheduleDbHost" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="scheduleDbPort">Port:</label>
                            <input type="number" id="scheduleDbPort">
                        </div>
                        <div class="form-group">
                            <label for="scheduleDbName">Datenbankname:</label>
                            <input type="text" id="scheduleDbName" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="scheduleDbUsername">Benutzername:</label>
                            <input type="text" id="scheduleDbUsername" required>
                        </div>
                        <div class="form-group">
                            <label for="scheduleDbPassword">Passwort:</label>
                            <input type="password" id="scheduleDbPassword" required>
                        </div>
                    </div>
                    <button type="submit">Zeitplan erstellen</button>
                </form>
                <div id="scheduleResult"></div>
                <div id="schedulesList" class="backup-list"></div>
            </div>

            <div id="system-content" class="tab-content">
                <h2>System-Informationen</h2>
                
                <div class="repo-info">
                    <h4>🔄 Offizielles Update-Repository</h4>
                    <p><strong>Repository:</strong> ${this.updateRepository}</p>
                    <p><strong>Branch:</strong> ${this.updateBranch}</p>
                    <p><strong>Updates:</strong> Automatisch vom offiziellen Repository</p>
                </div>
                
                <div id="systemInfo" class="system-info">
                    <h3>Lädt System-Informationen...</h3>
                </div>
                <button onclick="manualUpdate()" class="update-button">Manuelles Update</button>
                <div id="updateResult"></div>
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <button onclick="logout()">Abmelden</button>
            </div>
        </div>
    </div>

    <script>
        console.log('JavaScript wird geladen...');
        
        let authToken = null;

        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM geladen, initialisiere Event Listener...');
            
            const loginForm = document.getElementById('loginForm');
            if (loginForm) {
                console.log('Login Form gefunden, füge Event Listener hinzu...');
                loginForm.addEventListener('submit', handleLogin);
            } else {
                console.error('Login Form nicht gefunden!');
            }

            const backupForm = document.getElementById('backupForm');
            if (backupForm) {
                backupForm.addEventListener('submit', handleBackupSubmit);
            }

            const scheduleForm = document.getElementById('scheduleForm');
            if (scheduleForm) {
                scheduleForm.addEventListener('submit', handleScheduleSubmit);
            }

            const dbType = document.getElementById('dbType');
            if (dbType) {
                dbType.addEventListener('change', handleDbTypeChange);
            }

            const scheduleDbType = document.getElementById('scheduleDbType');
            if (scheduleDbType) {
                scheduleDbType.addEventListener('change', handleScheduleDbTypeChange);
            }
        });

        async function handleLogin(e) {
            console.log('Login Form submitted!');
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            console.log('Login attempt for user:', username);

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                console.log('Login response status:', response.status);
                const data = await response.json();
                console.log('Login response data:', data);

                if (response.ok) {
                    authToken = data.token;
                    console.log('Login successful, token received');
                    document.getElementById('login-section').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                    loadBackups();
                    loadSchedules();
                    loadSystemInfo();
                } else {
                    console.error('Login failed:', data.error);
                    document.getElementById('loginError').textContent = data.error;
                }
            } catch (error) {
                console.error('Login error:', error);
                document.getElementById('loginError').textContent = 'Verbindungsfehler: ' + error.message;
            }
        }

        async function handleBackupSubmit(e) {
            e.preventDefault();
            
            const backupData = {
                type: document.getElementById('dbType').value,
                host: document.getElementById('dbHost').value,
                port: document.getElementById('dbPort').value,
                database: document.getElementById('dbName').value,
                username: document.getElementById('dbUsername').value,
                password: document.getElementById('dbPassword').value
            };

            try {
                const response = await fetch('/api/backup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(backupData)
                });

                const data = await response.json();
                const resultDiv = document.getElementById('backupResult');

                if (response.ok) {
                    resultDiv.innerHTML = '<div class="success">' + data.message + '</div>';
                    loadBackups();
                } else {
                    resultDiv.innerHTML = '<div class="error">' + data.error + '</div>';
                }
            } catch (error) {
                document.getElementById('backupResult').innerHTML = '<div class="error">Verbindungsfehler</div>';
            }
        }

        async function handleScheduleSubmit(e) {
            e.preventDefault();
            
            const scheduleData = {
                name: document.getElementById('scheduleName').value,
                cronExpression: document.getElementById('cronExpression').value,
                dbConfig: {
                    type: document.getElementById('scheduleDbType').value,
                    host: document.getElementById('scheduleDbHost').value,
                    port: document.getElementById('scheduleDbPort').value,
                    database: document.getElementById('scheduleDbName').value,
                    username: document.getElementById('scheduleDbUsername').value,
                    password: document.getElementById('scheduleDbPassword').value
                }
            };

            try {
                const response = await fetch('/api/schedule', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(scheduleData)
                });

                const data = await response.json();
                const resultDiv = document.getElementById('scheduleResult');

                if (response.ok) {
                    resultDiv.innerHTML = '<div class="success">' + data.message + '</div>';
                    loadSchedules();
                    document.getElementById('scheduleForm').reset();
                } else {
                    resultDiv.innerHTML = '<div class="error">' + data.error + '</div>';
                }
            } catch (error) {
                document.getElementById('scheduleResult').innerHTML = '<div class="error">Verbindungsfehler</div>';
            }
        }

        function handleDbTypeChange(e) {
            const portField = document.getElementById('dbPort');
            switch(e.target.value) {
                case 'mysql':
                    portField.value = '3306';
                    break;
                case 'postgresql':
                    portField.value = '5432';
                    break;
                case 'mongodb':
                    portField.value = '27017';
                    break;
                default:
                    portField.value = '';
            }
        }

        function handleScheduleDbTypeChange(e) {
            const portField = document.getElementById('scheduleDbPort');
            switch(e.target.value) {
                case 'mysql':
                    portField.value = '3306';
                    break;
                case 'postgresql':
                    portField.value = '5432';
                    break;
                case 'mongodb':
                    portField.value = '27017';
                    break;
                default:
                    portField.value = '';
            }
        }

        async function loadBackups() {
            try {
                const response = await fetch('/api/backups', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });

                const backups = await response.json();
                const backupsList = document.getElementById('backupsList');

                if (response.ok) {
                    backupsList.innerHTML = backups.map(backup => 
                        '<div class="backup-item">' +
                            '<div>' +
                                '<strong>' + backup.filename + '</strong>' +
                                '<span class="schedule-info"> (' + backup.type + ')</span><br>' +
                                '<small>Erstellt: ' + new Date(backup.created).toLocaleString('de-DE') + '</small><br>' +
                                '<small>Größe: ' + (backup.size / 1024 / 1024).toFixed(2) + ' MB</small>' +
                            '</div>' +
                            '<div>' +
                                (backup.type === 'file' ? 
                                    '<button onclick="downloadBackup(\\\'' + backup.filename + '\\\')" >Download</button>' : 
                                    '<span style="color: #666; font-size: 0.9em;">Verzeichnis</span>') +
                                '<button onclick="deleteBackup(\\\'' + backup.filename + '\\\')" style="background: #e74c3c; margin-left: 5px;">Löschen</button>' +
                            '</div>' +
                        '</div>'
                    ).join('');
                } else {
                    backupsList.innerHTML = '<div class="error">' + backups.error + '</div>';
                }
            } catch (error) {
                document.getElementById('backupsList').innerHTML = '<div class="error">Fehler beim Laden der Backups</div>';
            }
        }

        async function loadSchedules() {
            try {
                const response = await fetch('/api/schedules', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });

                const schedules = await response.json();
                const schedulesList = document.getElementById('schedulesList');

                if (response.ok) {
                    if (schedules.length === 0) {
                        schedulesList.innerHTML = '<h3>Aktive Zeitpläne:</h3><p style="color: #666;">Keine Zeitpläne konfiguriert.</p>';
                    } else {
                        schedulesList.innerHTML = '<h3>Aktive Zeitpläne:</h3>' + schedules.map(schedule => 
                            '<div class="backup-item">' +
                                '<div>' +
                                    '<span class="status-indicator status-active"></span>' +
                                    '<strong>' + schedule.name + '</strong><br>' +
                                    '<small>Cron: ' + schedule.cronExpression + '</small><br>' +
                                    '<small>Datenbank: ' + schedule.dbConfig.type + ' - ' + schedule.dbConfig.database + '</small><br>' +
                                    '<small>Host: ' + schedule.dbConfig.host + ':' + schedule.dbConfig.port + '</small><br>' +
                                    '<small>Erstellt: ' + new Date(schedule.created).toLocaleString('de-DE') + '</small>' +
                                '</div>' +
                                '<div>' +
                                    '<button onclick="deleteSchedule(\\\'' + schedule.id + '\\\')" style="background: #e74c3c;">Löschen</button>' +
                                '</div>' +
                            '</div>'
                        ).join('');
                    }
                } else {
                    schedulesList.innerHTML = '<div class="error">' + schedules.error + '</div>';
                }
            } catch (error) {
                document.getElementById('schedulesList').innerHTML = '<div class="error">Fehler beim Laden der Zeitpläne</div>';
            }
        }

        async function loadSystemInfo() {
            try {
                const response = await fetch('/api/system', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });

                const systemInfo = await response.json();
                const systemInfoDiv = document.getElementById('systemInfo');

                if (response.ok) {
                    systemInfoDiv.innerHTML = 
                        '<h3>System-Status</h3>' +
                        '<p><strong>Version:</strong> ' + systemInfo.version + '</p>' +
                        '<p><strong>Name:</strong> ' + systemInfo.name + '</p>' +
                        '<p><strong>Node.js:</strong> ' + systemInfo.nodeVersion + '</p>' +
                        '<p><strong>Uptime:</strong> ' + Math.floor(systemInfo.uptime / 60) + ' Minuten</p>' +
                        '<p><strong>Git Commit:</strong> ' + systemInfo.git.commit + '</p>' +
                        '<p><strong>Git Datum:</strong> ' + systemInfo.git.date + '</p>' +
                        '<p><strong>Auto-Update:</strong> ' + (systemInfo.autoUpdate ? '✅ Aktiviert' : '❌ Deaktiviert') + '</p>' +
                        '<p><strong>Repository:</strong> ' + systemInfo.repository + '</p>' +
                        '<p><strong>Branch:</strong> ' + systemInfo.branch + '</p>';
                } else {
                    systemInfoDiv.innerHTML = '<div class="error">' + systemInfo.error + '</div>';
                }
            } catch (error) {
                document.getElementById('systemInfo').innerHTML = '<div class="error">Fehler beim Laden der System-Informationen</div>';
            }
        }

        async function manualUpdate() {
            try {
                const response = await fetch('/api/update', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });

                const data = await response.json();
                const resultDiv = document.getElementById('updateResult');

                if (response.ok) {
                    resultDiv.innerHTML = '<div class="success">' + data.message + '</div>';
                    loadSystemInfo();
                } else {
                    resultDiv.innerHTML = '<div class="error">' + data.error + '</div>';
                }
            } catch (error) {
                document.getElementById('updateResult').innerHTML = '<div class="error">Verbindungsfehler</div>';
            }
        }

        function downloadBackup(filename) {
            window.open('/api/backup/' + filename + '/download?token=' + authToken, '_blank');
        }

        async function deleteBackup(filename) {
            if (confirm('Backup ' + filename + ' wirklich löschen?')) {
                try {
                    const response = await fetch('/api/backup/' + filename, {
                        method: 'DELETE',
                        headers: { 'Authorization': 'Bearer ' + authToken }
                    });

                    if (response.ok) {
                        loadBackups();
                    } else {
                        const data = await response.json();
                        alert('Fehler: ' + data.error);
                    }
                } catch (error) {
                    alert('Verbindungsfehler');
                }
            }
        }

        async function deleteSchedule(scheduleId) {
            if (confirm('Zeitplan wirklich löschen?')) {
                try {
                    const response = await fetch('/api/schedule/' + scheduleId, {
                        method: 'DELETE',
                        headers: { 'Authorization': 'Bearer ' + authToken }
                    });

                    if (response.ok) {
                        loadSchedules();
                        const resultDiv = document.getElementById('scheduleResult');
                        resultDiv.innerHTML = '<div class="success">Zeitplan erfolgreich gelöscht</div>';
                        setTimeout(() => {
                            resultDiv.innerHTML = '';
                        }, 3000);
                    } else {
                        const data = await response.json();
                        alert('Fehler: ' + data.error);
                    }
                } catch (error) {
                    alert('Verbindungsfehler');
                }
            }
        }

        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById(tabName + '-content').classList.add('active');
            event.target.classList.add('active');
        }

        function logout() {
            authToken = null;
            document.getElementById('login-section').style.display = 'block';
            document.getElementById('main-content').style.display = 'none';
            document.getElementById('loginForm').reset();
            document.getElementById('loginError').textContent = '';
        }

        console.log('JavaScript vollständig geladen');
    </script>
</body>
</html>`;
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