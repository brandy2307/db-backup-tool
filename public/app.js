/**
 * Database Backup Tool - Complete Enhanced Frontend JavaScript mit Session-Persistenz und Security
 * Handles all client-side functionality including Git Backup configuration, persistent sessions and security features
 */

console.log('🛡️ Secure Database Backup Tool - Complete Enhanced Frontend wird geladen...');

// Global Variables (Original + Security)
let authToken = null;
let gitBackupConfig = null;
let sessionInfo = null;
let securityInfo = null;
let captchaRequired = false;
let twoFactorRequired = false;
let currentCaptchaId = null;

// ====== ENHANCED SECURITY TOKEN MANAGEMENT ======
function saveToken(token) {
  authToken = token;
  // Token in localStorage speichern für Persistenz
  if (typeof Storage !== "undefined") {
    localStorage.setItem('db-backup-token', token);
  }
}

function loadToken() {
  // Token aus localStorage laden
  if (typeof Storage !== "undefined") {
    const stored = localStorage.getItem('db-backup-token');
    if (stored) {
      authToken = stored;
      return stored;
    }
  }
  return null;
}

function clearToken() {
  authToken = null;
  if (typeof Storage !== "undefined") {
    localStorage.removeItem('db-backup-token');
  }
}

// ====== ENHANCED SECURITY STATUS CHECK ======
async function checkSecurityStatus() {
  try {
    const response = await fetch('/api/security-info', {
      method: 'GET',
      headers: {
        'Authorization': authToken ? `Bearer ${authToken}` : ''
      },
      credentials: 'include'
    });

    if (response.ok) {
      securityInfo = await response.json();
      updateSecurityIndicators();
      return true;
    }
  } catch (error) {
    console.error('Security Status Fehler:', error);
  }
  return false;
}

// Security Indicators Update
function updateSecurityIndicators() {
  if (!securityInfo) return;

  // Update security badges
  const badges = document.querySelectorAll('.security-badge');
  badges.forEach(badge => {
    if (badge.textContent.includes('HTTPS')) {
      badge.style.display = securityInfo.httpsEnabled ? 'inline-block' : 'none';
    }
    if (badge.textContent.includes('2FA')) {
      badge.style.display = securityInfo.has2FA ? 'inline-block' : 'none';
    }
  });

  // Update security status indicators
  const indicators = document.querySelectorAll('.security-indicator');
  indicators.forEach(indicator => {
    const icon = indicator.querySelector('.icon');
    const text = indicator.querySelector('span');
    
    if (text && text.textContent.includes('Verbindung')) {
      icon.className = securityInfo.httpsEnabled ? 'icon secure' : 'icon warning';
      text.textContent = securityInfo.httpsEnabled ? 'HTTPS Verbindung aktiv' : 'HTTP Verbindung (unsicher)';
    }
  });
}

// ====== ENHANCED SESSION STATUS CHECK ======
async function checkSessionStatus() {
  try {
    const response = await fetch('/api/session-status', {
      method: 'GET',
      headers: {
        'Authorization': authToken ? `Bearer ${authToken}` : ''
      },
      credentials: 'include'
    });

    const data = await response.json();
    
    if (data.authenticated) {
      console.log('✅ Session ist gültig');
      authToken = data.token;
      sessionInfo = data.session;
      saveToken(data.token);
      
      // Update session timeout display
      if (data.timeToExpiry) {
        updateSessionTimeout(data.timeToExpiry);
      }
      
      return true;
    } else {
      console.log('❌ Session ist ungültig:', data.reason);
      clearToken();
      return false;
    }
  } catch (error) {
    console.error('Session-Status Fehler:', error);
    clearToken();
    return false;
  }
}

// Session Timeout Display
function updateSessionTimeout(timeToExpiry) {
  const minutes = Math.floor(timeToExpiry / 60000);
  if (minutes <= 5) {
    showWarning('session-warning', `Session läuft in ${minutes} Minuten ab!`);
  }
}

// ====== CAPTCHA FUNCTIONS ======
async function loadCaptcha() {
  try {
    const response = await fetch('/api/captcha', {
      method: 'GET',
      credentials: 'include'
    });

    const data = await response.json();
    
    if (response.ok) {
      currentCaptchaId = data.id;
      const captchaImage = document.getElementById('captcha-image');
      if (captchaImage) {
        captchaImage.innerHTML = data.svg;
      }
      
      // Show CAPTCHA container
      const captchaContainer = document.getElementById('captcha-container');
      if (captchaContainer) {
        captchaContainer.classList.remove('hidden');
      }
      captchaRequired = true;
      
      console.log('🤖 CAPTCHA geladen:', currentCaptchaId);
    } else {
      console.error('CAPTCHA Fehler:', data.error);
    }
  } catch (error) {
    console.error('CAPTCHA Ladefehler:', error);
  }
}

function refreshCaptcha() {
  loadCaptcha();
}

// ====== PASSWORD STRENGTH VALIDATION ======
function validatePasswordStrength(password) {
  const minLength = 12;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  let strength = 0;
  let feedback = [];
  
  if (password.length >= minLength) strength++;
  else feedback.push(`Mindestens ${minLength} Zeichen`);
  
  if (hasUppercase) strength++;
  else feedback.push('Mindestens einen Großbuchstaben');
  
  if (hasLowercase) strength++;
  else feedback.push('Mindestens einen Kleinbuchstaben');
  
  if (hasNumbers) strength++;
  else feedback.push('Mindestens eine Zahl');
  
  if (hasSpecialChars) strength++;
  else feedback.push('Mindestens ein Sonderzeichen');
  
  return {
    strength: strength,
    valid: strength === 5,
    feedback: feedback,
    level: strength < 3 ? 'weak' : strength < 5 ? 'medium' : 'strong'
  };
}

function updatePasswordStrength(password) {
  const validation = validatePasswordStrength(password);
  const strengthContainer = document.querySelector('.password-strength');
  
  if (strengthContainer) {
    strengthContainer.classList.remove('hidden');
    strengthContainer.className = `password-strength password-strength-${validation.level}`;
    
    // Update tooltip with feedback
    if (validation.feedback.length > 0) {
      strengthContainer.title = 'Fehlende Anforderungen: ' + validation.feedback.join(', ');
    } else {
      strengthContainer.title = 'Passwort erfüllt alle Anforderungen';
    }
  }
}

// Auto-Login beim Laden der Seite
async function initializeApp() {
  console.log('🛡️ Initialisiere Secure App...');
  
  // Versuche Token aus localStorage zu laden
  const storedToken = loadToken();
  
  if (storedToken) {
    console.log('🔑 Gespeicherter Token gefunden, prüfe Gültigkeit...');
    
    const isValid = await checkSessionStatus();
    
    if (isValid) {
      console.log('✅ Token ist gültig, zeige Hauptinhalt');
      await checkSecurityStatus();
      showMainContent();
      loadInitialData();
      return;
    } else {
      console.log('❌ Token ist ungültig, zeige Login');
    }
  }
  
  // Zeige Login-Sektion
  document.getElementById('login-section').style.display = 'block';
  document.getElementById('main-content').style.display = 'none';
}

// Periodische Session-Überprüfung
function startSessionCheck() {
  setInterval(async () => {
    if (authToken) {
      const isValid = await checkSessionStatus();
      if (!isValid) {
        console.log('Session abgelaufen, leite zu Login weiter');
        await logout();
      }
    }
  }, 5 * 60 * 1000); // Alle 5 Minuten prüfen
}

// Enhanced DOMContentLoaded Event
document.addEventListener('DOMContentLoaded', function() {
  console.log('🛡️ DOM geladen, initialisiere Enhanced Session Management...');
  
  // Event Listener initialisieren
  initializeEventListeners();
  
  // App mit Session-Check initialisieren
  initializeApp();
  
  // Periodische Session-Überprüfung starten
  startSessionCheck();
});

/**
 * Initialize all event listeners
 */
function initializeEventListeners() {
  // Login Form
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    console.log('Login Form gefunden, füge Event Listener hinzu...');
    loginForm.addEventListener('submit', handleLogin);
  } else {
    console.error('Login Form nicht gefunden!');
  }

  // Backup Form
  const backupForm = document.getElementById('backupForm');
  if (backupForm) {
    backupForm.addEventListener('submit', handleBackupSubmit);
  }

  // Schedule Form
  const scheduleForm = document.getElementById('scheduleForm');
  if (scheduleForm) {
    scheduleForm.addEventListener('submit', handleScheduleSubmit);
  }

  // Git Backup Form
  const gitBackupForm = document.getElementById('gitBackupForm');
  if (gitBackupForm) {
    gitBackupForm.addEventListener('submit', handleGitBackupSubmit);
  }

  // Database Type Changes
  const dbType = document.getElementById('dbType');
  if (dbType) {
    dbType.addEventListener('change', handleDbTypeChange);
  }

  const scheduleDbType = document.getElementById('scheduleDbType');
  if (scheduleDbType) {
    scheduleDbType.addEventListener('change', handleScheduleDbTypeChange);
  }

  // Git Backup Toggle
  const gitBackupEnabled = document.getElementById('gitBackupEnabled');
  if (gitBackupEnabled) {
    gitBackupEnabled.addEventListener('change', handleGitBackupToggle);
  }

  // Password strength checker
  const passwordField = document.getElementById('password');
  if (passwordField) {
    passwordField.addEventListener('input', function() {
      updatePasswordStrength(this.value);
    });
  }

  // Manual Update Button
  const manualUpdateButton = document.getElementById('manual-update-button');
  if (manualUpdateButton) {
    manualUpdateButton.addEventListener('click', manualUpdate);
  }

  // Security Tab Buttons
  const setup2faBtn = document.getElementById('setup-2fa-btn');
  if (setup2faBtn) {
    setup2faBtn.addEventListener('click', setup2FA);
  }

  const disable2faBtn = document.getElementById('disable-2fa-btn');
  if (disable2faBtn) {
    disable2faBtn.addEventListener('click', disable2FA);
  }

  const changePasswordBtn = document.querySelector('.security-btn.warning');
  if (changePasswordBtn && changePasswordBtn.textContent.includes('Passwort ändern')) {
    changePasswordBtn.addEventListener('click', changePassword);
  }

  const showPasswordReqsBtn = document.querySelector('.security-btn.primary');
  if (showPasswordReqsBtn && showPasswordReqsBtn.textContent.includes('Passwort-Anforderungen')) {
    showPasswordReqsBtn.addEventListener('click', showPasswordRequirements);
  }

  const loadSessionsBtn = document.querySelector('.security-btn.primary');
  if (loadSessionsBtn && loadSessionsBtn.textContent.includes('Sessions laden')) {
    loadSessionsBtn.addEventListener('click', loadActiveSessions);
  }

  const terminateSessionsBtn = document.querySelector('.security-btn.danger');
  if (terminateSessionsBtn && terminateSessionsBtn.textContent.includes('Andere Sessions beenden')) {
    terminateSessionsBtn.addEventListener('click', terminateAllOtherSessions);
  }

  const refreshSecurityBtn = document.querySelector('.security-btn.primary');
  if (refreshSecurityBtn && refreshSecurityBtn.textContent.includes('Einstellungen aktualisieren')) {
    refreshSecurityBtn.addEventListener('click', refreshSecurityInfo);
  }
}

// Alle API-Aufrufe mit credentials erweitern
async function makeAuthenticatedRequest(url, options = {}) {
  const defaultOptions = {
    headers: {
      'Authorization': 'Bearer ' + authToken,
      'Content-Type': 'application/json',
      ...options.headers
    },
    credentials: 'include'
  };

  const response = await fetch(url, { ...defaultOptions, ...options });
  
  // Prüfe auf 401 Unauthorized
  if (response.status === 401) {
    console.log('🔒 Token ungültig, leite zu Login weiter');
    await logout();
    throw new Error('Session abgelaufen');
  }
  
  return response;
}

/**
 * Handle login form submission - Enhanced mit Session-Persistenz und Security
 */
async function handleLogin(e) {
  console.log('🔐 Login Form submitted!');
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const rememberMe = document.getElementById('remember-me') ? document.getElementById('remember-me').checked : false;
  
  console.log('Login attempt for user:', username);

  const loginData = {
    username,
    password,
    rememberMe
  };
  
  // Add CAPTCHA if required
  if (captchaRequired && currentCaptchaId) {
    const captchaText = document.getElementById('captcha-text');
    if (!captchaText || !captchaText.value) {
      showError('loginError', 'Bitte gib den CAPTCHA-Code ein');
      return;
    }
    loginData.captchaId = currentCaptchaId;
    loginData.captchaText = captchaText.value;
  }
  
  // Add 2FA if required
  if (twoFactorRequired) {
    const twoFactorToken = document.getElementById('two-factor-token');
    if (!twoFactorToken || !twoFactorToken.value) {
      showError('loginError', 'Bitte gib den 2FA-Code ein');
      return;
    }
    loginData.twoFactorToken = twoFactorToken.value;
  }

  try {
    // Disable login button during request
    const loginButton = document.getElementById('login-button');
    const loginText = document.getElementById('login-text');
    if (loginButton && loginText) {
      loginButton.disabled = true;
      loginText.innerHTML = '<span class="loading-spinner"></span> Anmeldung...';
    }

    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(loginData),
      credentials: 'include' // Wichtig für Cookies
    });

    console.log('Login response status:', response.status);
    const data = await response.json();
    console.log('Login response data:', data);

    // Re-enable login button
    if (loginButton && loginText) {
      loginButton.disabled = false;
      loginText.textContent = 'Anmelden';
    }

    if (response.ok) {
      console.log('✅ Login successful, token received');
      saveToken(data.token); // Verwende neue saveToken Funktion
      sessionInfo = data.session;
      
      // Hide CAPTCHA and 2FA containers
      const captchaContainer = document.getElementById('captcha-container');
      const twoFactorContainer = document.getElementById('two-factor-container');
      if (captchaContainer) captchaContainer.classList.add('hidden');
      if (twoFactorContainer) twoFactorContainer.classList.add('hidden');
      
      captchaRequired = false;
      twoFactorRequired = false;
      
      // Check for password change requirement
      if (data.requiresPasswordChange) {
        showWarning('loginError', 'Bitte ändere dein Passwort nach dem Login für erhöhte Sicherheit');
      }
      
      showMainContent();
      loadInitialData();
    } else {
      console.error('❌ Login failed:', data.error);
      
      // Handle specific error cases
      if (data.code === 'CAPTCHA_REQUIRED' || data.requiresCaptcha) {
        await loadCaptcha();
      }
      
      if (data.code === '2FA_REQUIRED' || data.requires2FA) {
        const twoFactorContainer = document.getElementById('two-factor-container');
        if (twoFactorContainer) {
          twoFactorContainer.classList.remove('hidden');
        }
        twoFactorRequired = true;
      }
      
      if (data.code === 'ACCOUNT_LOCKED') {
        showError('loginError', `Account gesperrt für ${data.lockedUntil} Minuten`);
        // Reload CAPTCHA for locked accounts
        await loadCaptcha();
      } else {
        showError('loginError', data.error);
      }
    }
  } catch (error) {
    console.error('Login error:', error);
    showError('loginError', 'Verbindungsfehler: ' + error.message);
    
    // Re-enable login button on error
    const loginButton = document.getElementById('login-button');
    const loginText = document.getElementById('login-text');
    if (loginButton && loginText) {
      loginButton.disabled = false;
      loginText.textContent = 'Anmelden';
    }
  }
}

/**
 * Show main content after successful login
 */
function showMainContent() {
  document.getElementById('login-section').style.display = 'none';
  document.getElementById('main-content').style.display = 'block';
}

/**
 * Load initial data after login
 */
function loadInitialData() {
  loadBackups();
  loadSchedules();
  loadSystemInfo();
  loadGitBackupConfig();
  checkSecurityStatus();
}

/**
 * Handle backup form submission
 */
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
    showLoading('backupResult', 'Erstelle Backup...');
    
    const response = await makeAuthenticatedRequest('/api/backup', {
      method: 'POST',
      body: JSON.stringify(backupData)
    });

    const data = await response.json();
    hideLoading('backupResult');

    if (response.ok) {
      let message = data.message;
      if (data.gitPushed) {
        message += ' ✅ Git Push erfolgreich!';
      } else if (gitBackupConfig?.enabled) {
        message += ' ⚠️ Git Push fehlgeschlagen';
      }
      
      showSuccess('backupResult', message);
      if (data.note) {
        showInfo('backupResult', data.note);
      }
      loadBackups();
      // Clear sensitive data
      document.getElementById('dbPassword').value = '';
    } else {
      showError('backupResult', data.error);
    }
  } catch (error) {
    hideLoading('backupResult');
    if (error.message !== 'Session abgelaufen') {
      showError('backupResult', 'Verbindungsfehler: ' + error.message);
    }
  }
}

/**
 * Handle schedule form submission
 */
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
    showLoading('scheduleResult', 'Erstelle Zeitplan...');
    
    const response = await makeAuthenticatedRequest('/api/schedule', {
      method: 'POST',
      body: JSON.stringify(scheduleData)
    });

    const data = await response.json();
    hideLoading('scheduleResult');

    if (response.ok) {
      showSuccess('scheduleResult', data.message);
      loadSchedules();
      document.getElementById('scheduleForm').reset();
    } else {
      showError('scheduleResult', data.error);
    }
  } catch (error) {
    hideLoading('scheduleResult');
    if (error.message !== 'Session abgelaufen') {
      showError('scheduleResult', 'Verbindungsfehler: ' + error.message);
    }
  }
}

/**
 * Handle Git Backup form submission
 */
async function handleGitBackupSubmit(e) {
  e.preventDefault();
  
  const gitData = {
    enabled: document.getElementById('gitBackupEnabled').checked,
    repository: document.getElementById('gitBackupRepository').value,
    username: document.getElementById('gitBackupUsername').value,
    token: document.getElementById('gitBackupToken').value,
    branch: document.getElementById('gitBackupBranch').value || 'main'
  };

  try {
    showLoading('gitBackupResult', 'Speichere Git Backup Konfiguration...');
    
    const response = await makeAuthenticatedRequest('/api/git-backup/config', {
      method: 'POST',
      body: JSON.stringify(gitData)
    });

    const data = await response.json();
    hideLoading('gitBackupResult');

    if (response.ok) {
      showSuccess('gitBackupResult', data.message);
      if (data.needsRestart) {
        showWarning('gitBackupResult', data.needsRestart);
      }
      loadGitBackupConfig();
      loadSystemInfo();
    } else {
      showError('gitBackupResult', data.error);
    }
  } catch (error) {
    hideLoading('gitBackupResult');
    if (error.message !== 'Session abgelaufen') {
      showError('gitBackupResult', 'Verbindungsfehler: ' + error.message);
    }
  }
}

/**
 * Handle Git Backup toggle
 */
function handleGitBackupToggle(e) {
  const enabled = e.target.checked;
  const configFields = document.querySelectorAll('.git-config-field');
  
  configFields.forEach(field => {
    field.style.display = enabled ? 'block' : 'none';
  });
  
  // Test Button anzeigen/verstecken
  const testButton = document.getElementById('testGitBackup');
  if (testButton) {
    testButton.style.display = enabled ? 'inline-block' : 'none';
  }
}

/**
 * Test Git Backup connection
 */
async function testGitBackup() {
  try {
    showLoading('gitBackupResult', 'Teste Git Backup Verbindung...');
    
    const response = await makeAuthenticatedRequest('/api/git-backup/test', {
      method: 'POST'
    });

    const data = await response.json();
    hideLoading('gitBackupResult');

    if (response.ok) {
      showSuccess('gitBackupResult', data.message);
    } else {
      showError('gitBackupResult', data.error);
    }
  } catch (error) {
    hideLoading('gitBackupResult');
    if (error.message !== 'Session abgelaufen') {
      showError('gitBackupResult', 'Verbindungsfehler: ' + error.message);
    }
  }
}

/**
 * Load Git Backup configuration
 */
async function loadGitBackupConfig() {
  try {
    const response = await makeAuthenticatedRequest('/api/git-backup/config');

    if (response.ok) {
      gitBackupConfig = await response.json();
      
      // Formular ausfüllen
      const gitBackupEnabled = document.getElementById('gitBackupEnabled');
      const gitBackupRepository = document.getElementById('gitBackupRepository');
      const gitBackupUsername = document.getElementById('gitBackupUsername');
      const gitBackupBranch = document.getElementById('gitBackupBranch');
      const tokenField = document.getElementById('gitBackupToken');
      
      if (gitBackupEnabled) gitBackupEnabled.checked = gitBackupConfig.enabled;
      if (gitBackupRepository) gitBackupRepository.value = gitBackupConfig.repository;
      if (gitBackupUsername) gitBackupUsername.value = gitBackupConfig.username;
      if (gitBackupBranch) gitBackupBranch.value = gitBackupConfig.branch;
      
      // Token-Feld - zeige nur ob vorhanden
      if (tokenField) {
        if (gitBackupConfig.hasToken) {
          tokenField.placeholder = '••••••••••••••••••••••••••••••••••••••••';
        } else {
          tokenField.placeholder = 'Personal Access Token oder App Password';
        }
      }
      
      // Toggle Event auslösen
      if (gitBackupEnabled) {
        handleGitBackupToggle({ target: { checked: gitBackupConfig.enabled } });
      }
      
    } else {
      console.error('Fehler beim Laden der Git Backup Konfiguration');
    }
  } catch (error) {
    if (error.message !== 'Session abgelaufen') {
      console.error('Git Backup Config Fehler:', error);
    }
  }
}

/**
 * Handle database type change for backup form
 */
function handleDbTypeChange(e) {
  const portField = document.getElementById('dbPort');
  if (portField) {
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
}

/**
 * Handle database type change for schedule form
 */
function handleScheduleDbTypeChange(e) {
  const portField = document.getElementById('scheduleDbPort');
  if (portField) {
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
}

/**
 * Load backups list - Enhanced mit Session-Persistenz
 */
async function loadBackups() {
  try {
    const response = await makeAuthenticatedRequest('/api/backups');
    const backups = await response.json();
    const backupsList = document.getElementById('backupsList');

    if (response.ok && backupsList) {
      if (backups.length === 0) {
        backupsList.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">Keine Backups vorhanden.</p>';
      } else {
        backupsList.innerHTML = backups.map(backup => createBackupItemHTML(backup)).join('');
      }
    } else if (backupsList) {
      showError('backupsList', backups.error || 'Fehler beim Laden');
    }
  } catch (error) {
    if (error.message !== 'Session abgelaufen') {
      showError('backupsList', 'Fehler beim Laden der Backups: ' + error.message);
    }
  }
}

/**
 * Create HTML for backup item
 */
function createBackupItemHTML(backup) {
  const downloadButton = backup.type === 'file' ? 
    `<button onclick="downloadBackup('${backup.filename}')">Download</button>` : 
    '<span style="color: #666; font-size: 0.9em;">Verzeichnis</span>';
    
  const deleteButton = backup.canDelete !== false ? 
    `<button onclick="deleteBackup('${backup.filename}')" style="background: #e74c3c; margin-left: 5px;">Löschen</button>` :
    '<span style="color: #999; font-size: 0.9em;">Nur Admin</span>';

  return `
    <div class="backup-item">
      <div>
        <strong>${backup.filename}</strong>
        <span class="schedule-info">(${backup.type})</span><br>
        <small>Erstellt: ${new Date(backup.created).toLocaleString('de-DE')}</small><br>
        <small>Größe: ${(backup.size / 1024 / 1024).toFixed(2)} MB</small>
        ${backup.createdBy ? `<br><small>Von: ${backup.createdBy}</small>` : ''}
      </div>
      <div>
        ${downloadButton}
        ${deleteButton}
      </div>
    </div>
  `;
}

/**
 * Load schedules list - Enhanced mit Session-Persistenz
 */
async function loadSchedules() {
  try {
    const response = await makeAuthenticatedRequest('/api/schedules');
    const schedules = await response.json();
    const schedulesList = document.getElementById('schedulesList');

    if (response.ok && schedulesList) {
      if (schedules.length === 0) {
        schedulesList.innerHTML = '<h3>Aktive Zeitpläne:</h3><p style="color: #666;">Keine Zeitpläne konfiguriert.</p>';
      } else {
        schedulesList.innerHTML = '<h3>Aktive Zeitpläne:</h3>' + 
          schedules.map(schedule => createScheduleItemHTML(schedule)).join('');
      }
    } else if (schedulesList) {
      showError('schedulesList', schedules.error || 'Fehler beim Laden');
    }
  } catch (error) {
    if (error.message !== 'Session abgelaufen') {
      showError('schedulesList', 'Fehler beim Laden der Zeitpläne: ' + error.message);
    }
  }
}

/**
 * Create HTML for schedule item
 */
function createScheduleItemHTML(schedule) {
  const deleteButton = schedule.canDelete !== false ?
    `<button onclick="deleteSchedule('${schedule.id}')" style="background: #e74c3c;">Löschen</button>` :
    '<span style="color: #999; font-size: 0.9em;">Nur Admin</span>';

  return `
    <div class="backup-item">
      <div>
        ${deleteButton}
      </div>
    </div>
  `;
}

/**
 * Load system information - Enhanced mit Session-Persistenz
 */
async function loadSystemInfo() {
  try {
    const response = await makeAuthenticatedRequest('/api/system');
    const systemInfo = await response.json();
    const systemInfoDiv = document.getElementById('systemInfo');

    if (response.ok && systemInfoDiv) {
      systemInfoDiv.innerHTML = createSystemInfoHTML(systemInfo);
      
      // Update repository info in the fixed section
      const repoUrl = document.getElementById('repo-url');
      const repoBranch = document.getElementById('repo-branch');
      if (repoUrl) repoUrl.textContent = systemInfo.repository;
      if (repoBranch) repoBranch.textContent = systemInfo.branch;
      
      // Update Git Backup status
      const gitBackupStatus = document.getElementById('git-backup-status');
      if (gitBackupStatus) {
        if (systemInfo.gitBackup.enabled) {
          gitBackupStatus.innerHTML = `
            <span style="color: #27ae60;">✅ Aktiviert</span><br>
            <small>Repository: ${systemInfo.gitBackup.repository || 'Nicht konfiguriert'}</small><br>
            <small>Anmeldedaten: ${systemInfo.gitBackup.hasCredentials ? '✅ Vorhanden' : '❌ Fehlen'}</small>
          `;
        } else {
          gitBackupStatus.innerHTML = '<span style="color: #e74c3c;">❌ Deaktiviert</span>';
        }
      }
    } else if (systemInfoDiv) {
      showError('systemInfo', systemInfo.error || 'Fehler beim Laden');
    }
  } catch (error) {
    if (error.message !== 'Session abgelaufen') {
      showError('systemInfo', 'Fehler beim Laden der System-Informationen: ' + error.message);
    }
  }
}

/**
 * Create HTML for system information
 */
function createSystemInfoHTML(systemInfo) {
  let securitySection = '';
  if (systemInfo.security) {
    securitySection = `
      <h4>🛡️ Sicherheits-Status</h4>
      <p><strong>Aktive Sessions:</strong> ${systemInfo.security.activeSessions}</p>
      <p><strong>Überwachte IPs:</strong> ${systemInfo.security.failedAttempts}</p>
      <p><strong>CAPTCHA Sessions:</strong> ${systemInfo.security.captchaSessions}</p>
      <p><strong>HTTPS:</strong> ${systemInfo.security.httpsEnabled ? '✅ Aktiviert' : '❌ Deaktiviert'}</p>
      <p><strong>2FA:</strong> ${systemInfo.security.twoFactorEnabled ? '✅ Aktiviert' : '❌ Deaktiviert'}</p>
      <p><strong>Starke Passwörter:</strong> ${systemInfo.security.strongPasswordsEnabled ? '✅ Aktiviert' : '❌ Deaktiviert'}</p>
    `;
  }

  return `
    <h3>System-Status</h3>
    <p><strong>Version:</strong> ${systemInfo.version}</p>
    <p><strong>Name:</strong> ${systemInfo.name}</p>
    <p><strong>Node.js:</strong> ${systemInfo.nodeVersion}</p>
    <p><strong>Uptime:</strong> ${Math.floor(systemInfo.uptime / 60)} Minuten</p>
    <p><strong>Plattform:</strong> ${systemInfo.platform || 'Unknown'}</p>
    <p><strong>Architektur:</strong> ${systemInfo.arch || 'Unknown'}</p>
    <p><strong>Git Commit:</strong> ${systemInfo.git.commit}</p>
    <p><strong>Git Datum:</strong> ${systemInfo.git.date}</p>
    <p><strong>Auto-Update:</strong> ${systemInfo.autoUpdate ? '✅ Aktiviert' : '❌ Deaktiviert'}</p>
    <p><strong>Repository:</strong> ${systemInfo.repository}</p>
    <p><strong>Branch:</strong> ${systemInfo.branch}</p>
    <p><strong>Git Backup:</strong> ${systemInfo.gitBackup.enabled ? '✅ Aktiviert' : '❌ Deaktiviert'}</p>
    ${systemInfo.gitBackup.enabled ? `
      <p><strong>Git Repository:</strong> ${systemInfo.gitBackup.repository || 'Nicht konfiguriert'}</p>
      <p><strong>Git Anmeldedaten:</strong> ${systemInfo.gitBackup.hasCredentials ? '✅ Vorhanden' : '❌ Fehlen'}</p>
    ` : ''}
    ${securitySection}
  `;
}

/**
 * Manual update function - Enhanced mit Session-Persistenz
 */
async function manualUpdate() {
  try {
    showLoading('updateResult', 'Führe Update durch...');
    
    const response = await makeAuthenticatedRequest('/api/update', {
      method: 'POST'
    });

    const data = await response.json();
    hideLoading('updateResult');

    if (response.ok) {
      showSuccess('updateResult', data.message);
      loadSystemInfo();
    } else {
      showError('updateResult', data.error);
    }
  } catch (error) {
    hideLoading('updateResult');
    if (error.message !== 'Session abgelaufen') {
      showError('updateResult', 'Verbindungsfehler: ' + error.message);
    }
  }
}

/**
 * Download backup file
 */
function downloadBackup(filename) {
  if (authToken) {
    window.open('/api/backup/' + filename + '/download?token=' + authToken, '_blank');
  }
}

/**
 * Delete backup with confirmation - Enhanced mit Session-Persistenz
 */
async function deleteBackup(filename) {
  if (confirm('Backup "' + filename + '" wirklich löschen?')) {
    try {
      const response = await makeAuthenticatedRequest('/api/backup/' + filename, {
        method: 'DELETE'
      });

      if (response.ok) {
        loadBackups();
        showSuccess('backupsList', 'Backup erfolgreich gelöscht');
        setTimeout(() => clearMessages('backupsList'), 3000);
      } else {
        const data = await response.json();
        showError('backupsList', 'Fehler: ' + data.error);
      }
    } catch (error) {
      if (error.message !== 'Session abgelaufen') {
        showError('backupsList', 'Verbindungsfehler: ' + error.message);
      }
    }
  }
}

/**
 * Delete schedule with confirmation - Enhanced mit Session-Persistenz
 */
async function deleteSchedule(scheduleId) {
  if (confirm('Zeitplan wirklich löschen?')) {
    try {
      const response = await makeAuthenticatedRequest('/api/schedule/' + scheduleId, {
        method: 'DELETE'
      });

      if (response.ok) {
        loadSchedules();
        showSuccess('scheduleResult', 'Zeitplan erfolgreich gelöscht');
        setTimeout(() => clearMessages('scheduleResult'), 3000);
      } else {
        const data = await response.json();
        showError('scheduleResult', 'Fehler: ' + data.error);
      }
    } catch (error) {
      if (error.message !== 'Session abgelaufen') {
        showError('scheduleResult', 'Verbindungsfehler: ' + error.message);
      }
    }
  }
}

// ====== 2FA FUNCTIONS ======

/**
 * Setup 2FA
 */
async function setup2FA() {
  try {
    const response = await makeAuthenticatedRequest('/api/2fa/setup', {
      method: 'POST'
    });

    const data = await response.json();
    
    if (response.ok) {
      // Show QR Code
      const qrContainer = document.getElementById('qr-code-container') || createQRContainer();
      qrContainer.innerHTML = `
        <h4>📱 2FA Setup</h4>
        <p>Scanne diesen QR-Code mit deiner Authenticator-App:</p>
        <img src="${data.qrCode}" alt="2FA QR Code" style="max-width: 200px; border: 2px solid #e1e5e9; border-radius: 10px;">
        <p><strong>Manueller Code:</strong> <code>${data.secret}</code></p>
        <div style="margin-top: 20px;">
          <input type="text" id="verify-2fa-token" placeholder="6-stelliger Code" maxlength="6" style="padding: 10px; margin-right: 10px;">
          <button onclick="verify2FA()" style="padding: 10px 20px;">Verifizieren</button>
        </div>
        <div id="2fa-verify-result"></div>
      `;
      qrContainer.style.display = 'block';
    } else {
      showError('2fa-result', data.error);
    }
  } catch (error) {
    showError('2fa-result', 'Fehler beim 2FA Setup: ' + error.message);
  }
}

function createQRContainer() {
  const container = document.createElement('div');
  container.id = 'qr-code-container';
  container.className = 'qr-code-container';
  const systemContent = document.getElementById('system-content');
  if (systemContent) {
    systemContent.appendChild(container);
  }
  return container;
}

/**
 * Verify 2FA Setup
 */
async function verify2FA() {
  const tokenField = document.getElementById('verify-2fa-token');
  if (!tokenField) {
    showError('2fa-verify-result', 'Token-Eingabefeld nicht gefunden');
    return;
  }
  
  const token = tokenField.value;
  
  if (!token || token.length !== 6) {
    showError('2fa-verify-result', 'Bitte gib einen 6-stelligen Code ein');
    return;
  }
  
  try {
    const response = await makeAuthenticatedRequest('/api/2fa/verify', {
      method: 'POST',
      body: JSON.stringify({ token })
    });

    const data = await response.json();
    
    if (response.ok) {
      showSuccess('2fa-verify-result', '2FA erfolgreich aktiviert!');
      const qrContainer = document.getElementById('qr-code-container');
      if (qrContainer) {
        setTimeout(() => {
          qrContainer.style.display = 'none';
        }, 3000);
      }
      await checkSecurityStatus();
      loadSystemInfo();
    } else {
      showError('2fa-verify-result', data.error);
    }
  } catch (error) {
    showError('2fa-verify-result', 'Fehler bei der 2FA Verifikation: ' + error.message);
  }
}

/**
 * Disable 2FA
 */
async function disable2FA() {
  const password = prompt('Bitte gib dein Passwort ein:');
  const token = prompt('Bitte gib deinen aktuellen 2FA-Code ein:');
  
  if (!password || !token) {
    showError('2fa-result', 'Passwort und 2FA-Code sind erforderlich');
    return;
  }
  
  try {
    const response = await makeAuthenticatedRequest('/api/2fa/disable', {
      method: 'POST',
      body: JSON.stringify({ password, token })
    });

    const data = await response.json();
    
    if (response.ok) {
      showSuccess('2fa-result', '2FA erfolgreich deaktiviert');
      await checkSecurityStatus();
      loadSystemInfo();
    } else {
      showError('2fa-result', data.error);
    }
  } catch (error) {
    showError('2fa-result', 'Fehler bei der 2FA Deaktivierung: ' + error.message);
  }
}

// ====== SESSION MANAGEMENT FUNCTIONS ======

/**
 * Load Active Sessions
 */
async function loadActiveSessions() {
  try {
    const response = await makeAuthenticatedRequest('/api/active-sessions');
    const data = await response.json();
    
    if (response.ok) {
      displayActiveSessions(data.sessions);
    } else {
      showError('sessions-result', data.error);
    }
  } catch (error) {
    showError('sessions-result', 'Fehler beim Laden der Sessions: ' + error.message);
  }
}

/**
 * Display Active Sessions
 */
function displayActiveSessions(sessions) {
  const container = document.getElementById('active-sessions-list') || createSessionsList();
  
  if (sessions.length === 0) {
    container.innerHTML = '<p>Keine aktiven Sessions gefunden.</p>';
    return;
  }
  
  container.innerHTML = sessions.map(session => `
    <div class="session-item ${session.current ? 'current-session' : ''}">
      <div class="session-info">
        <strong>${session.current ? '🔵 Aktuelle Session' : '⚪ Andere Session'}</strong><br>
        <small>IP: ${session.ip}</small><br>
        <small>Browser: ${session.userAgent.substring(0, 50)}...</small><br>
        <small>Erstellt: ${new Date(session.createdAt).toLocaleString('de-DE')}</small><br>
        <small>Letzte Aktivität: ${new Date(session.lastActivity).toLocaleString('de-DE')}</small><br>
        <small>Remember Me: ${session.rememberMe ? 'Ja' : 'Nein'}</small>
      </div>
      ${!session.current ? `<button onclick="terminateSession('${session.id}')" class="terminate-btn" style="background: #e74c3c; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer;">Beenden</button>` : ''}
    </div>
  `).join('');
}

function createSessionsList() {
  const container = document.createElement('div');
  container.id = 'active-sessions-list';
  container.className = 'sessions-list';
  const systemContent = document.getElementById('system-content');
  if (systemContent) {
    systemContent.appendChild(container);
  }
  return container;
}

/**
 * Terminate Session
 */
async function terminateSession(sessionId) {
  if (confirm('Session wirklich beenden?')) {
    try {
      const response = await makeAuthenticatedRequest(`/api/session/${sessionId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        showSuccess('sessions-result', 'Session erfolgreich beendet');
        loadActiveSessions();
      } else {
        const data = await response.json();
        showError('sessions-result', data.error);
      }
    } catch (error) {
      showError('sessions-result', 'Fehler beim Beenden der Session: ' + error.message);
    }
  }
}

// ====== PASSWORD CHANGE FUNCTION ======

/**
 * Change Password
 */
async function changePassword() {
  const currentPassword = prompt('Aktuelles Passwort:');
  if (!currentPassword) return;
  
  const newPassword = prompt('Neues Passwort (min. 12 Zeichen, Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen):');
  if (!newPassword) return;
  
  const confirmPassword = prompt('Neues Passwort bestätigen:');
  if (newPassword !== confirmPassword) {
    alert('Passwörter stimmen nicht überein!');
    return;
  }
  
  // Client-side validation
  const validation = validatePasswordStrength(newPassword);
  if (!validation.valid) {
    alert('Passwort erfüllt nicht die Sicherheitsanforderungen:\n' + validation.feedback.join('\n'));
    return;
  }
  
  const changeData = {
    currentPassword,
    newPassword
  };
  
  // Add 2FA if user has it enabled
  if (securityInfo && securityInfo.has2FA) {
    const twoFactorToken = prompt('2FA-Code:');
    if (!twoFactorToken) return;
    changeData.twoFactorToken = twoFactorToken;
  }
  
  try {
    const response = await makeAuthenticatedRequest('/api/change-password', {
      method: 'POST',
      body: JSON.stringify(changeData)
    });

    const data = await response.json();
    
    if (response.ok) {
      alert('Passwort erfolgreich geändert!');
      await checkSecurityStatus();
    } else {
      alert('Fehler: ' + data.error);
    }
  } catch (error) {
    alert('Fehler beim Ändern des Passworts: ' + error.message);
  }
}

/**
 * Show tab content
 */
function showTab(tabName) {
  // Hide all tab contents
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });
  
  // Remove active class from all tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.classList.remove('active');
  });
  
  // Show selected tab content
  const tabContent = document.getElementById(tabName + '-content');
  if (tabContent) {
    tabContent.classList.add('active');
  }
  
  // Add active class to clicked tab
  if (event && event.target) {
    event.target.classList.add('active');
  }
  
  // Load data for specific tabs
  switch(tabName) {
    case 'backups':
      loadBackups();
      break;
    case 'schedule':
      loadSchedules();
      break;
    case 'git-backup':
      loadGitBackupConfig();
      break;
    case 'system':
      loadSystemInfo();
      checkSecurityStatus();
      break;
    case 'security':
      checkSecurityStatus();
      loadActiveSessions();
      break;
  }
}

/**
 * Enhanced Logout function mit Session-Persistenz
 */
async function logout() {
  try {
    await fetch('/api/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + authToken },
      credentials: 'include'
    });
  } catch (error) {
    console.error('Logout error:', error);
  }
  
  // Lokalen State löschen
  clearToken();
  gitBackupConfig = null;
  sessionInfo = null;
  securityInfo = null;
  captchaRequired = false;
  twoFactorRequired = false;
  currentCaptchaId = null;
  
  // Login-Sektion anzeigen
  document.getElementById('login-section').style.display = 'block';
  document.getElementById('main-content').style.display = 'none';
  
  // Containers verstecken
  const captchaContainer = document.getElementById('captcha-container');
  const twoFactorContainer = document.getElementById('two-factor-container');
  if (captchaContainer) captchaContainer.classList.add('hidden');
  if (twoFactorContainer) twoFactorContainer.classList.add('hidden');
  
  // Formulare zurücksetzen
  document.getElementById('loginForm').reset();
  clearMessages('loginError');
  
  console.log('🔓 Logged out successfully');
}

/**
 * Utility Functions
 */

/**
 * Show error message
 */
function showError(elementId, message) {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = `<div class="alert error">${message}</div>`;
  }
}

/**
 * Show success message
 */
function showSuccess(elementId, message) {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = `<div class="alert success">${message}</div>`;
  }
}

/**
 * Show warning message
 */
function showWarning(elementId, message) {
  const element = document.getElementById(elementId);
  if (element) {
    const existing = element.innerHTML;
    element.innerHTML = existing + `<div class="alert warning">${message}</div>`;
  }
}

/**
 * Show info message
 */
function showInfo(elementId, message) {
  const element = document.getElementById(elementId);
  if (element) {
    const existing = element.innerHTML;
    element.innerHTML = existing + `<div class="alert info">${message}</div>`;
  }
}

/**
 * Show loading message
 */
function showLoading(elementId, message = 'Lädt...') {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = `<div style="color: #3498db; text-align: center; padding: 10px;"><span class="loading-spinner"></span> ${message}</div>`;
  }
}

/**
 * Hide loading message
 */
function hideLoading(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = '';
  }
}

/**
 * Clear all messages from element
 */
function clearMessages(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    const messages = element.querySelectorAll('.alert, .error, .success, .warning, .info');
    messages.forEach(msg => msg.remove());
  }
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format date
 */
function formatDate(dateString) {
  return new Date(dateString).toLocaleString('de-DE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

/**
 * Validate cron expression (basic)
 */
function validateCronExpression(cron) {
  const cronRegex = /^(\*|([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])|\*\/([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])) (\*|([0-9]|1[0-9]|2[0-3])|\*\/([0-9]|1[0-9]|2[0-3])) (\*|([1-9]|1[0-9]|2[0-9]|3[0-1])|\*\/([1-9]|1[0-9]|2[0-9]|3[0-1])) (\*|([1-9]|1[0-2])|\*\/([1-9]|1[0-2])) (\*|([0-6])|\*\/([0-6]))$/;
  return cronRegex.test(cron);
}

// ====== ENHANCED SECURITY EVENT HANDLERS ======

// Behandle Seitenaktualisierung
window.addEventListener('beforeunload', function() {
  // Token wird automatisch in localStorage gespeichert
  console.log('🔒 Seite wird neu geladen, Token gespeichert');
});

// Enhanced Error handling for security events
window.addEventListener('error', function(e) {
  console.error('🚨 Uncaught error:', e.error);
  if (e.error.message.includes('auth') || e.error.message.includes('token')) {
    console.error('🔒 Authentifizierungsfehler erkannt');
  }
});

window.addEventListener('unhandledrejection', function(e) {
  console.error('🚨 Unhandled promise rejection:', e.reason);
  if (e.reason && e.reason.toString().includes('auth')) {
    console.error('🔒 Authentifizierungsfehler in Promise erkannt');
  }
});

// Security monitoring
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'visible' && authToken) {
    // Prüfe Session wenn Tab wieder aktiv wird
    checkSessionStatus();
  }
});

// Detect suspicious activity (multiple tabs)
window.addEventListener('storage', function(e) {
  if (e.key === 'db-backup-token' && e.newValue !== authToken) {
    console.log('🔒 Token in anderem Tab geändert, synchronisiere...');
    authToken = e.newValue;
    if (!authToken) {
      logout();
    }
  }
});

// Network status monitoring
window.addEventListener('online', function() {
  console.log('🌐 Netzwerk wieder verfügbar');
  if (authToken) {
    checkSessionStatus();
  }
});

window.addEventListener('offline', function() {
  console.log('📵 Netzwerk nicht verfügbar');
  showWarning('network-status', 'Keine Netzwerkverbindung - Funktionen möglicherweise eingeschränkt');
});

console.log('🛡️ Secure Database Backup Tool - Complete Enhanced Frontend JavaScript vollständig geladen');
// ====== FUNCTIONS MOVED FROM INDEX.HTML ======

// Security Tab Functions
function showPasswordRequirements() {
    const reqDiv = document.getElementById('password-requirements');
    if (reqDiv) {
        if (reqDiv.style.display === 'none') {
            reqDiv.style.display = 'block';
        } else {
            reqDiv.style.display = 'none';
        }
    }
}

async function refreshSecurityInfo() {
    try {
        await checkSecurityStatus();
        
        if (securityInfo) {
            updateSecurityDisplay();
            showSuccess('security-settings-result', 'Sicherheits-Informationen aktualisiert');
        }
    } catch (error) {
        showError('security-settings-result', 'Fehler beim Laden der Sicherheits-Informationen');
    }
}

function updateSecurityDisplay() {
    if (!securityInfo) return;
    
    // Update metrics
    const activeSessionsCount = document.getElementById('active-sessions-count');
    const securityLevel = document.getElementById('security-level');
    
    if (activeSessionsCount) {
        activeSessionsCount.textContent = securityInfo.activeSessions || '0';
    }
    
    if (securityLevel) {
        let level = 'Niedrig';
        let levelClass = 'danger';
        
        if (securityInfo.has2FA && securityInfo.httpsEnabled && securityInfo.strongPasswordsEnabled) {
            level = 'Hoch';
            levelClass = 'secure';
        } else if (securityInfo.httpsEnabled || securityInfo.has2FA) {
            level = 'Mittel';
            levelClass = 'warning';
        }
        
        securityLevel.textContent = level;
        if (securityLevel.parentElement) {
            securityLevel.parentElement.className = `metric-card ${levelClass}`;
        }
    }
    
    // Update 2FA Status
    const twoFAStatus = document.getElementById('2fa-status');
    const setup2FABtn = document.getElementById('setup-2fa-btn');
    const disable2FABtn = document.getElementById('disable-2fa-btn');
    
    if (twoFAStatus) {
        if (securityInfo.has2FA) {
            twoFAStatus.innerHTML = `
                <div class="alert success">
                    <strong>✅ 2FA ist aktiviert</strong><br>
                    Dein Account ist mit Zwei-Faktor-Authentifizierung geschützt.
                </div>
            `;
            if (setup2FABtn) setup2FABtn.style.display = 'none';
            if (disable2FABtn) disable2FABtn.style.display = 'inline-block';
        } else {
            twoFAStatus.innerHTML = `
                <div class="alert warning">
                    <strong>⚠️ 2FA ist nicht aktiviert</strong><br>
                    Aktiviere 2FA für zusätzliche Sicherheit.
                </div>
            `;
            if (setup2FABtn) setup2FABtn.style.display = 'inline-block';
            if (disable2FABtn) disable2FABtn.style.display = 'none';
        }
    }
    
    // Update Security Settings Info
    const securitySettingsInfo = document.getElementById('security-settings-info');
    if (securitySettingsInfo) {
        securitySettingsInfo.innerHTML = `
            <div class="security-status-grid">
                <div class="security-card ${securityInfo.httpsEnabled ? 'secure' : 'warning'}">
                    <h4>🔐 HTTPS</h4>
                    <div class="value">${securityInfo.httpsEnabled ? 'AN' : 'AUS'}</div>
                </div>
                <div class="security-card ${securityInfo.has2FA ? 'secure' : 'warning'}">
                    <h4>🛡️ 2FA</h4>
                    <div class="value">${securityInfo.has2FA ? 'AN' : 'AUS'}</div>
                </div>
                <div class="security-card ${securityInfo.strongPasswordsEnabled ? 'secure' : 'warning'}">
                    <h4>🔑 Starke Passwörter</h4>
                    <div class="value">${securityInfo.strongPasswordsEnabled ? 'AN' : 'AUS'}</div>
                </div>
            </div>
            <p><strong>Session Timeout:</strong> ${securityInfo.sessionTimeout} Minuten</p>
            <p><strong>Max. Login-Versuche:</strong> ${securityInfo.maxFailedAttempts}</p>
            <p><strong>CAPTCHA Schwelle:</strong> ${securityInfo.captchaThreshold} Fehlversuche</p>
            <p><strong>Letzter Login:</strong> ${securityInfo.lastLogin ? new Date(securityInfo.lastLogin).toLocaleString('de-DE') : 'Unbekannt'}</p>
        `;
    }
}

async function terminateAllOtherSessions() {
    if (confirm('Alle anderen Sessions beenden? Du bleibst nur in der aktuellen Session angemeldet.')) {
        try {
            const response = await makeAuthenticatedRequest('/api/active-sessions');
            const data = await response.json();
            
            if (response.ok) {
                const otherSessions = data.sessions.filter(session => !session.current);
                
                for (const session of otherSessions) {
                    await makeAuthenticatedRequest(`/api/session/${session.id}`, {
                        method: 'DELETE'
                    });
                }
                
                showSuccess('sessions-result', `${otherSessions.length} andere Sessions beendet`);
                loadActiveSessions();
            }
        } catch (error) {
            showError('sessions-result', 'Fehler beim Beenden der Sessions: ' + error.message);
        }
    }
}

// Initialize security display when tab is opened
function initSecurityTab() {
    refreshSecurityInfo();
    loadActiveSessions();
}