/**
 * Database Backup Tool - Frontend JavaScript (Enhanced mit Git Backup) - TEIL 1
 * Handles all client-side functionality including Git Backup configuration
 */

console.log('Database Backup Tool - Enhanced Frontend wird geladen...');

// Global Variables
let authToken = null;
let gitBackupConfig = null;

// DOM Content Loaded Event
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM geladen, initialisiere Event Listener...');
    initializeEventListeners();
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
}

/**
 * Handle login form submission
 */
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
            showMainContent();
            loadInitialData();
        } else {
            console.error('Login failed:', data.error);
            showError('loginError', data.error);
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('loginError', 'Verbindungsfehler: ' + error.message);
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
        
        const response = await fetch('/api/backup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken
            },
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
        showError('backupResult', 'Verbindungsfehler: ' + error.message);
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
        
        const response = await fetch('/api/schedule', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken
            },
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
        showError('scheduleResult', 'Verbindungsfehler: ' + error.message);
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
        
        const response = await fetch('/api/git-backup/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken
            },
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
        showError('gitBackupResult', 'Verbindungsfehler: ' + error.message);
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
        
        const response = await fetch('/api/git-backup/test', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + authToken }
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
        showError('gitBackupResult', 'Verbindungsfehler: ' + error.message);
    }
}

/**
 * Load Git Backup configuration
 */
async function loadGitBackupConfig() {
    try {
        const response = await fetch('/api/git-backup/config', {
            headers: { 'Authorization': 'Bearer ' + authToken }
        });

        if (response.ok) {
            gitBackupConfig = await response.json();
            
            // Formular ausfüllen
            document.getElementById('gitBackupEnabled').checked = gitBackupConfig.enabled;
            document.getElementById('gitBackupRepository').value = gitBackupConfig.repository;
            document.getElementById('gitBackupUsername').value = gitBackupConfig.username;
            document.getElementById('gitBackupBranch').value = gitBackupConfig.branch;
            
            // Token-Feld - zeige nur ob vorhanden
            const tokenField = document.getElementById('gitBackupToken');
            if (gitBackupConfig.hasToken) {
                tokenField.placeholder = '••••••••••••••••••••••••••••••••••••••••';
            } else {
                tokenField.placeholder = 'Personal Access Token oder App Password';
            }
            
            // Toggle Event auslösen
            handleGitBackupToggle({ target: { checked: gitBackupConfig.enabled } });
            
        } else {
            console.error('Fehler beim Laden der Git Backup Konfiguration');
        }
    } catch (error) {
        console.error('Git Backup Config Fehler:', error);
    }
}

/**
 * Handle database type change for backup form
 */
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

/**
 * Handle database type change for schedule form
 */
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
/**
 * Database Backup Tool - Frontend JavaScript (Enhanced mit Git Backup) - TEIL 2
 * Data Loading Functions und Utility Functions
 */

/**
 * Load backups list
 */
async function loadBackups() {
    try {
        const response = await fetch('/api/backups', {
            headers: { 'Authorization': 'Bearer ' + authToken }
        });

        const backups = await response.json();
        const backupsList = document.getElementById('backupsList');

        if (response.ok) {
            if (backups.length === 0) {
                backupsList.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">Keine Backups vorhanden.</p>';
            } else {
                backupsList.innerHTML = backups.map(backup => createBackupItemHTML(backup)).join('');
            }
        } else {
            showError('backupsList', backups.error);
        }
    } catch (error) {
        showError('backupsList', 'Fehler beim Laden der Backups: ' + error.message);
    }
}

/**
 * Create HTML for backup item
 */
function createBackupItemHTML(backup) {
    return `
        <div class="backup-item">
            <div>
                <strong>${backup.filename}</strong>
                <span class="schedule-info">(${backup.type})</span><br>
                <small>Erstellt: ${new Date(backup.created).toLocaleString('de-DE')}</small><br>
                <small>Größe: ${(backup.size / 1024 / 1024).toFixed(2)} MB</small>
            </div>
            <div>
                ${backup.type === 'file' ? 
                    `<button onclick="downloadBackup('${backup.filename}')">Download</button>` : 
                    '<span style="color: #666; font-size: 0.9em;">Verzeichnis</span>'
                }
                <button onclick="deleteBackup('${backup.filename}')" style="background: #e74c3c; margin-left: 5px;">Löschen</button>
            </div>
        </div>
    `;
}

/**
 * Load schedules list
 */
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
                schedulesList.innerHTML = '<h3>Aktive Zeitpläne:</h3>' + 
                    schedules.map(schedule => createScheduleItemHTML(schedule)).join('');
            }
        } else {
            showError('schedulesList', schedules.error);
        }
    } catch (error) {
        showError('schedulesList', 'Fehler beim Laden der Zeitpläne: ' + error.message);
    }
}

/**
 * Create HTML for schedule item
 */
function createScheduleItemHTML(schedule) {
    return `
        <div class="backup-item">
            <div>
                <span class="status-indicator status-active"></span>
                <strong>${schedule.name}</strong><br>
                <small>Cron: ${schedule.cronExpression}</small><br>
                <small>Datenbank: ${schedule.dbConfig.type} - ${schedule.dbConfig.database}</small><br>
                <small>Host: ${schedule.dbConfig.host}:${schedule.dbConfig.port}</small><br>
                <small>Erstellt: ${new Date(schedule.created).toLocaleString('de-DE')}</small>
            </div>
            <div>
                <button onclick="deleteSchedule('${schedule.id}')" style="background: #e74c3c;">Löschen</button>
            </div>
        </div>
    `;
}

/**
 * Load system information
 */
async function loadSystemInfo() {
    try {
        const response = await fetch('/api/system', {
            headers: { 'Authorization': 'Bearer ' + authToken }
        });

        const systemInfo = await response.json();
        const systemInfoDiv = document.getElementById('systemInfo');

        if (response.ok) {
            systemInfoDiv.innerHTML = createSystemInfoHTML(systemInfo);
            
            // Update repository info in the fixed section
            document.getElementById('repo-url').textContent = systemInfo.repository;
            document.getElementById('repo-branch').textContent = systemInfo.branch;
            
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
        } else {
            showError('systemInfo', systemInfo.error);
        }
    } catch (error) {
        showError('systemInfo', 'Fehler beim Laden der System-Informationen: ' + error.message);
    }
}

/**
 * Create HTML for system information
 */
function createSystemInfoHTML(systemInfo) {
    return `
        <h3>System-Status</h3>
        <p><strong>Version:</strong> ${systemInfo.version}</p>
        <p><strong>Name:</strong> ${systemInfo.name}</p>
        <p><strong>Node.js:</strong> ${systemInfo.nodeVersion}</p>
        <p><strong>Uptime:</strong> ${Math.floor(systemInfo.uptime / 60)} Minuten</p>
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
    `;
}

/**
 * Manual update function
 */
async function manualUpdate() {
    try {
        showLoading('updateResult', 'Führe Update durch...');
        
        const response = await fetch('/api/update', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + authToken }
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
        showError('updateResult', 'Verbindungsfehler: ' + error.message);
    }
}

/**
 * Download backup file
 */
function downloadBackup(filename) {
    window.open('/api/backup/' + filename + '/download?token=' + authToken, '_blank');
}

/**
 * Delete backup with confirmation
 */
async function deleteBackup(filename) {
    if (confirm('Backup "' + filename + '" wirklich löschen?')) {
        try {
            const response = await fetch('/api/backup/' + filename, {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + authToken }
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
            showError('backupsList', 'Verbindungsfehler: ' + error.message);
        }
    }
}

/**
 * Delete schedule with confirmation
 */
async function deleteSchedule(scheduleId) {
    if (confirm('Zeitplan wirklich löschen?')) {
        try {
            const response = await fetch('/api/schedule/' + scheduleId, {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + authToken }
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
            showError('scheduleResult', 'Verbindungsfehler: ' + error.message);
        }
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
    document.getElementById(tabName + '-content').classList.add('active');
    
    // Add active class to clicked tab
    event.target.classList.add('active');
    
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
            break;
    }
}

/**
 * Logout function
 */
async function logout() {
    try {
        await fetch('/api/logout', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + authToken }
        });
    } catch (error) {
        console.error('Logout error:', error);
    }
    
    // Clear local state
    authToken = null;
    gitBackupConfig = null;
    
    // Show login section
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('main-content').style.display = 'none';
    
    // Reset forms
    document.getElementById('loginForm').reset();
    clearMessages('loginError');
    
    console.log('Logged out successfully');
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
        element.innerHTML = `<div class="error">${message}</div>`;
    }
}

/**
 * Show success message
 */
function showSuccess(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `<div class="success">${message}</div>`;
    }
}

/**
 * Show warning message
 */
function showWarning(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        const existing = element.innerHTML;
        element.innerHTML = existing + `<div class="warning">${message}</div>`;
    }
}

/**
 * Show info message
 */
function showInfo(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        const existing = element.innerHTML;
        element.innerHTML = existing + `<div class="info">${message}</div>`;
    }
}

/**
 * Show loading message
 */
function showLoading(elementId, message = 'Lädt...') {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `<div style="color: #3498db; text-align: center; padding: 10px;">${message}</div>`;
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
        const messages = element.querySelectorAll('.error, .success, .warning, .info');
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

// Error handling for uncaught errors
window.addEventListener('error', function(e) {
    console.error('Uncaught error:', e.error);
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
});

console.log('Database Backup Tool - Enhanced Frontend JavaScript vollständig geladen');