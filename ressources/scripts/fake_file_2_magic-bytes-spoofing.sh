#!/bin/bash
# OWASP Juice Shop - PDF Upload Bypass
# Methode: Einfache Dateiumbenennung
#
# Beschreibung:
# Dieses Script zeigt, wie eine normale XML-Datei einfach durch
# Umbenennung der Dateiendung als PDF hochgeladen werden kann.

echo "🔨 Erstelle XML-Datei..."

# 1. Erstelle eine normale XML-Datei
cat > test.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <message>This is a test XML file</message>
    <description>Diese Datei wird als PDF getarnt</description>
</root>
EOF

echo "✅ XML-Datei erstellt"

# 2. Benenne sie zu .pdf um
echo "🔄 Benenne XML zu PDF um..."
mv test.xml test.pdf

echo "✅ Datei 'test.pdf' wurde erstellt!"
echo "📁 Die Datei ist eigentlich XML, hat aber eine .pdf Endung"