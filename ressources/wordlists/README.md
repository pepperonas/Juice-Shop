# 📚 Wordlists

## common.txt

Diese Wordlist enthält gängige Verzeichnisse und Dateien, die auf Webservern zu finden sind. Sie wird für Directory Scanning mit Tools wie `gobuster` verwendet.

### Verwendung

```bash
gobuster dir -u http://localhost:3000 -w common.txt -x js,json,md,txt,pdf
```

### Inhalt

Die Liste enthält:
- Versteckte Dateien (`.git`, `.env`, etc.)
- Konfigurationsdateien (`.htaccess`, `.config`)
- Backup-Dateien
- Standard-Verzeichnisse
- Well-known URIs

### Sicherheitshinweis

Diese Wordlist darf nur für legale Penetrationstests mit ausdrücklicher Erlaubnis verwendet werden.